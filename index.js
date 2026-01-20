import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ===== ENV =====
const JWT_SECRET = process.env.JWT_SECRET;
const FATSECRET_CONSUMER_KEY = process.env.FATSECRET_CONSUMER_KEY;
const FATSECRET_SHARED_SECRET = process.env.FATSECRET_SHARED_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) throw new Error("Missing JWT_SECRET");
if (!FATSECRET_CONSUMER_KEY) throw new Error("Missing FATSECRET_CONSUMER_KEY");
if (!FATSECRET_SHARED_SECRET) throw new Error("Missing FATSECRET_SHARED_SECRET");
if (!DATABASE_URL) throw new Error("Missing DATABASE_URL");

// ===== DB =====
const { Pool } = pg;
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    create table if not exists users (
      id serial primary key,
      email text unique not null,
      password_hash text not null,
      created_at timestamptz default now()
    );
  `);
}
initDb().catch((e) => console.error("DB init error:", e));

// ===== JWT =====
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ===== FatSecret OAuth1 helpers =====
const BASE_URL = "https://platform.fatsecret.com/rest/server.api";

function oauthEncode(str) {
  return encodeURIComponent(str)
    .replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function normalizeParams(params) {
  const pairs = Object.entries(params).map(([k, v]) => [String(k), String(v)]);
  pairs.sort((a, b) =>
    a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1
  );
  return pairs.map(([k, v]) => `${oauthEncode(k)}=${oauthEncode(v)}`).join("&");
}

function buildBaseString(method, url, params) {
  return [method.toUpperCase(), oauthEncode(url), oauthEncode(normalizeParams(params))].join("&");
}

function signHmacSha1(baseString, consumerSecret) {
  const key = `${oauthEncode(consumerSecret)}&`;
  return crypto.createHmac("sha1", key).update(baseString).digest("base64");
}

function toQueryString(params) {
  return Object.entries(params)
    .map(([k, v]) => `${oauthEncode(k)}=${oauthEncode(String(v))}`)
    .join("&");
}

async function fatsecretGet(extraParams) {
  const oauthParams = {
    oauth_consumer_key: FATSECRET_CONSUMER_KEY,
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_nonce: crypto.randomBytes(16).toString("hex"),
    oauth_version: "1.0",
  };

  const unsigned = { ...extraParams, ...oauthParams };
  const baseString = buildBaseString("GET", BASE_URL, unsigned);
  const signature = signHmacSha1(baseString, FATSECRET_SHARED_SECRET);

  const params = { ...unsigned, oauth_signature: signature };
  const url = `${BASE_URL}?${toQueryString(params)}`;

  const r = await fetch(url);
  const text = await r.text();

  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`FatSecret returned non-JSON: ${text.slice(0, 200)}`);
  }

  if (json?.error) {
    throw new Error(`FatSecret error ${json.error.code}: ${json.error.message}`);
  }

  return json;
}

// ===== ROUTES =====
app.get("/", (req, res) => res.json({ ok: true }));

// AUTH: REGISTER
app.post("/auth/register", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");

  if (!email || password.length < 6) {
    return res.status(400).json({ error: "Invalid email or password (min 6 chars)" });
  }

  const password_hash = await bcrypt.hash(password, 10);

  try {
    const r = await pool.query(
      "insert into users(email,password_hash) values($1,$2) returning id,email",
      [email, password_hash]
    );
    return res.json({ token: signToken(r.rows[0]) });
  } catch (e) {
    if (String(e?.message).toLowerCase().includes("duplicate")) {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: "Server error" });
  }
});

// AUTH: LOGIN
app.post("/auth/login", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");

  if (!email || !password) return res.status(400).json({ error: "Invalid credentials" });

  const r = await pool.query("select id,email,password_hash from users where email=$1", [email]);
  const user = r.rows[0];
  if (!user) return res.status(401).json({ error: "Wrong credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Wrong credentials" });

  return res.json({ token: signToken(user) });
});

// (optional) ME
app.get("/me", authMiddleware, (req, res) => res.json({ user: req.user }));

// FatSecret: SEARCH (PROTETTA)
app.get("/fatsecret/search", authMiddleware, async (req, res) => {
  try {
    const query = String(req.query.query ?? "").trim();
    if (!query) return res.status(400).json({ error: "Missing query" });

    const json = await fatsecretGet({
      method: "foods.search",
      format: "json",
      search_expression: query,
      max_results: "20",
      page_number: "0",
    });

    const foodsNode = json?.foods?.food;
    const list = Array.isArray(foodsNode) ? foodsNode : foodsNode ? [foodsNode] : [];

    return res.json({
      foods: list.map((f) => ({
        food_id: f.food_id,
        food_name: f.food_name,
        brand_name: f.brand_name ?? null,
        food_description: f.food_description ?? null,
      })),
      total_results: json?.foods?.total_results ?? null,
    });
  } catch (e) {
    return res.status(502).json({ error: e.message ?? "Upstream error" });
  }
});

// FatSecret: FOOD GET (PROTETTA) - utile per calorie reali più avanti
app.get("/fatsecret/food/:id", authMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id).trim();
    const json = await fatsecretGet({
      method: "food.get",
      format: "json",
      food_id: id,
    });
    return res.json(json);
  } catch (e) {
    return res.status(502).json({ error: e.message ?? "Upstream error" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on ${PORT}`);
});
