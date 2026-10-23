const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { Pool } = require("pg");

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT || 9340);
const HOST = "0.0.0.0";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 5
});

const attempts = new Map();
const MAX_BODY = 16 * 1024;
const SESSION_HOURS = 8;

function send(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  });
  res.end(JSON.stringify(data));
}

function clientKey(req) {
  return req.socket.remoteAddress || "unknown";
}

function rateLimited(req) {
  const key = clientKey(req);
  const now = Date.now();
  let entry = attempts.get(key);

  if (!entry || now - entry.start > 60000) {
    entry = { start: now, count: 0 };
    attempts.set(key, entry);
  }

  entry.count++;
  return entry.count > 30;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (Buffer.byteLength(raw) > MAX_BODY) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(raw || "{}"));
      } catch {
        reject(new Error("INVALID_JSON"));
      }
    });
    req.on("error", reject);
  });
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function getToken(req) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : "";
}

async function getUserFromRequest(req) {
  const token = await getToken(req);
  if (!token) return null;

  const result = await pool.query(
    `SELECT u.id, u.username
       FROM auth_sessions s
       JOIN auth_users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
    [tokenHash(token)]
  );

  return result.rows[0] || null;
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  await pool.query(
    `INSERT INTO auth_sessions (user_id, token_hash, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '${SESSION_HOURS} hours')`,
    [userId, tokenHash(token)]
  );
  return token;
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) NOT NULL,
      username_normalized VARCHAR(24) NOT NULL UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS auth_sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx
      ON auth_sessions (expires_at);
  `);
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && url.pathname === "/api/health") {
    await pool.query("SELECT 1");
    return send(res, 200, { ok: true, service: "PcBrawl ID" });
  }

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/login.html")) {
    const file = path.join(__dirname, "login.html");
    if (!fs.existsSync(file)) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("login.html not found");
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    });
    return res.end(fs.readFileSync(file));
  }

  if (!url.pathname.startsWith("/api/")) {
    return send(res, 404, { error: "Not found" });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { error: "Method not allowed" });
  }

  if (rateLimited(req)) {
    return send(res, 429, { error: "Too many requests. Try again later." });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (error) {
    return send(res, error.message === "BODY_TOO_LARGE" ? 413 : 400, {
      error: error.message === "BODY_TOO_LARGE" ? "Request too large" : "Invalid JSON"
    });
  }

  if (url.pathname === "/api/register") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const normalized = username.toLowerCase();

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return send(res, 400, {
        error: "Username must be 3–24 letters, numbers or underscores."
      });
    }
    if (password.length < 8 || password.length > 128) {
      return send(res, 400, {
        error: "Password must be between 8 and 128 characters."
      });
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = (await scrypt(password, salt, 64)).toString("hex");

    try {
      const created = await pool.query(
        `INSERT INTO auth_users
          (username, username_normalized, password_salt, password_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING id, username`,
        [username, normalized, salt, hash]
      );
      const user = created.rows[0];
      const token = await createSession(user.id);
      return send(res, 201, {
        ok: true, token, user: { id: user.id, username: user.username }
      });
    } catch (error) {
      if (error.code === "23505") {
        return send(res, 409, { error: "That username is already registered." });
      }
      throw error;
    }
  }

  if (url.pathname === "/api/login") {
    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!username || !password || password.length > 128) {
      return send(res, 400, { error: "Enter your username and password." });
    }

    const result = await pool.query(
      `SELECT id, username, password_salt, password_hash
         FROM auth_users WHERE username_normalized = $1`,
      [username]
    );

    if (!result.rows.length) {
      return send(res, 401, { error: "Incorrect username or password." });
    }

    const user = result.rows[0];
    const hash = (await scrypt(password, user.password_salt, 64)).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(user.password_hash, "hex");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return send(res, 401, { error: "Incorrect username or password." });
    }

    const token = await createSession(user.id);
    return send(res, 200, {
      ok: true, token, user: { id: user.id, username: user.username }
    });
  }

  if (url.pathname === "/api/me") {
    const user = await getUserFromRequest(req);
    if (!user) return send(res, 401, { error: "Not signed in." });
    return send(res, 200, { ok: true, user });
  }

  if (url.pathname === "/api/logout") {
    const token = await getToken(req);
    if (token) {
      await pool.query("DELETE FROM auth_sessions WHERE token_hash = $1", [
        tokenHash(token)
      ]);
    }
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: "Unknown API endpoint." });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(error => {
    console.error("Request failed:", error.message);
    if (!res.headersSent) send(res, 500, { error: "Internal server error." });
    else res.destroy();
  });
});

async function start() {
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is missing. Configure PostgreSQL before starting.");
    process.exit(1);
  }
  await initializeDatabase();
  await pool.query("DELETE FROM auth_sessions WHERE expires_at < NOW()");
  server.listen(PORT, HOST, () => {
    console.log(`PcBrawl ID listening on ${HOST}:${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  server.close();
  await pool.end();
  process.exit(0);
});
