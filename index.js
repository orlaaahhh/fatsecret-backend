import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

dotenv.config();
console.log("BOOT: starting server...");
const app = express();
app.use(cors());
app.use(express.json());

// ✅ Dashboard statica (file in /public) accessibile su /admin
app.use("/admin", express.static("public"));

const PORT = process.env.PORT || 3000;

// ===== ENV =====
const JWT_SECRET = process.env.JWT_SECRET;
const FATSECRET_CONSUMER_KEY = process.env.FATSECRET_CONSUMER_KEY;
const FATSECRET_SHARED_SECRET = process.env.FATSECRET_SHARED_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

// ✅ nuova env per admin dashboard
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!JWT_SECRET) throw new Error("Missing JWT_SECRET");
if (!FATSECRET_CONSUMER_KEY) throw new Error("Missing FATSECRET_CONSUMER_KEY");
if (!FATSECRET_SHARED_SECRET) throw new Error("Missing FATSECRET_SHARED_SECRET");
if (!DATABASE_URL) throw new Error("Missing DATABASE_URL");
if (!ADMIN_API_KEY) throw new Error("Missing ADMIN_API_KEY");

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

  // ✅ nuova tabella meetings per calendario
  await pool.query(`
    create table if not exists meetings (
      id serial primary key,
      user_id integer not null references users(id) on delete cascade,
      title text not null,
      start_time timestamptz not null,
      end_time timestamptz not null,
      zoom_url text not null,
      created_at timestamptz default now(),
      updated_at timestamptz default now(),
      constraint meetings_time_check check (end_time > start_time)
    );
  `);

  await pool.query(`
    create index if not exists meetings_user_start_idx
    on meetings(user_id, start_time);
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

// ✅ Admin middleware (dashboard)
function adminKeyMiddleware(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ===== FatSecret OAuth1 helpers =====
function oauthEncode(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
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

/**
 * Generic OAuth1 GET against ANY FatSecret endpoint URL
 */
async function fatsecretGetAt(baseUrl, extraParams, { debugLabel } = {}) {
  const oauthParams = {
    oauth_consumer_key: FATSECRET_CONSUMER_KEY,
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_nonce: crypto.randomBytes(16).toString("hex"),
    oauth_version: "1.0",
  };

  const unsigned = { ...extraParams, ...oauthParams };
  const baseString = buildBaseString("GET", baseUrl, unsigned);
  const signature = signHmacSha1(baseString, FATSECRET_SHARED_SECRET);

  const params = { ...unsigned, oauth_signature: signature };
  const url = `${baseUrl}?${toQueryString(params)}`;

  console.log(`[FatSecret ${debugLabel ?? "GET"}]`, url);

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

/**
 * Back-compat for server.api (method=...)
 */
const SERVER_API_URL = "https://platform.fatsecret.com/rest/server.api";
async function fatsecretGet(extraParams) {
  return fatsecretGetAt(SERVER_API_URL, extraParams, { debugLabel: "server.api" });
}

// ===== Barcode helpers =====
function digitsOnly(s) {
  return String(s ?? "").replace(/\D/g, "");
}

function toGTIN13(raw) {
  const d = digitsOnly(raw);
  if (d.length === 13) return d;
  if (d.length === 12) return d.padStart(13, "0");
  if (d.length === 8) return d.padStart(13, "0");
  return null;
}

function pickDefaultServing(servingsNode) {
  const servings = servingsNode?.serving;
  const arr = Array.isArray(servings) ? servings : servings ? [servings] : [];
  return arr.find((s) => String(s.is_default) === "1") ?? arr[0] ?? null;
}

function makeDescriptionFromServing(serving) {
  if (!serving) return null;
  const sd = serving.serving_description ?? "serving";
  const calories = serving.calories ?? "0";
  const fat = serving.fat ?? "0";
  const carbs = serving.carbohydrate ?? "0";
  const protein = serving.protein ?? "0";
  return `Per ${sd} - Calories: ${calories}kcal | Fat: ${fat}g | Carbs: ${carbs}g | Protein: ${protein}g`;
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

// ME
app.get("/me", authMiddleware, (req, res) => res.json({ user: req.user }));

// ===========================
// ✅ CALENDARIO - API MEETINGS
// ===========================

// MOBILE: GET meetings in range (from/to ISO) - usa JWT
app.get("/meetings", authMiddleware, async (req, res) => {
  try {
    const from = String(req.query.from ?? "");
    const to = String(req.query.to ?? "");
    if (!from || !to) return res.status(400).json({ error: "Missing from/to" });

    const fromDate = new Date(from);
    const toDate = new Date(to);
    if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
      return res.status(400).json({ error: "Invalid dates" });
    }

    const r = await pool.query(
      `select id, title, start_time, end_time, zoom_url
       from meetings
       where user_id = $1 and start_time >= $2 and start_time < $3
       order by start_time asc`,
      [req.user.uid, fromDate.toISOString(), toDate.toISOString()]
    );

    return res.json({ meetings: r.rows });
  } catch (e) {
    console.error("GET /meetings error:", e);
    return res.status(500).json({ error: "Server error (meetings)" });
  }
});

// DASHBOARD: crea meeting (admin)
app.post("/meetings", adminKeyMiddleware, async (req, res) => {
  const title = String(req.body?.title ?? "").trim();
  const zoomUrl = String(req.body?.zoomUrl ?? "").trim();
  const userId = Number(req.body?.userId);
  const start = new Date(String(req.body?.start ?? ""));
  const end = new Date(String(req.body?.end ?? ""));

  if (!title || !zoomUrl || !userId || isNaN(start) || isNaN(end) || end <= start) {
    return res.status(400).json({ error: "Invalid payload" });
  }

  const r = await pool.query(
    `insert into meetings (user_id, title, start_time, end_time, zoom_url)
     values ($1,$2,$3,$4,$5)
     returning id, title, start_time, end_time, zoom_url`,
    [userId, title, start.toISOString(), end.toISOString(), zoomUrl]
  );

  return res.status(201).json({ meeting: r.rows[0] });
});

// DASHBOARD: trova userId da email (admin)
app.get("/admin/users", adminKeyMiddleware, async (req, res) => {
  const email = String(req.query.email ?? "").trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Missing email" });

  const r = await pool.query(`select id, email from users where email=$1`, [email]);
  return res.json({ user: r.rows[0] ?? null });
});

// ======================
// FatSecret endpoints
// ======================

// FatSecret: SEARCH
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
    return res.status(502).json({ error: e?.message ?? "Upstream error" });
  }
});

// ✅ FatSecret: BARCODE (URL-based v2)
app.get("/fatsecret/barcode", authMiddleware, async (req, res) => {
  try {
    const barcodeRaw = String(req.query.barcode ?? "").trim();
    const gtin13 = toGTIN13(barcodeRaw);
    if (!gtin13) {
      return res.status(400).json({ error: "Invalid barcode. Use EAN-13/UPC-A/EAN-8 digits." });
    }

    const region = String(req.query.region ?? "IT");
    const language = String(req.query.language ?? "en");

    const BARCODE_V2_URL = "https://platform.fatsecret.com/rest/food/barcode/find-by-id/v2";

    const json = await fatsecretGetAt(
      BARCODE_V2_URL,
      {
        format: "json",
        barcode: gtin13,
        region,
        language,
        flag_default_serving: "true",
      },
      { debugLabel: "barcode.v2" }
    );

    const food = json?.food;
    if (!food?.food_id) return res.json({ foods: [] });

    const serving = pickDefaultServing(food?.servings);
    const desc = makeDescriptionFromServing(serving);

    return res.json({
      foods: [
        {
          food_id: String(food.food_id),
          food_name: String(food.food_name),
          brand_name: food.brand_name ?? null,
          food_description: desc,
        },
      ],
    });
  } catch (e) {
    const msg = String(e?.message ?? "");

    if (msg.includes("FatSecret error 10:")) {
      return res.status(403).json({
        error:
          "FatSecret Barcode API not available for this app key (Premier Exclusive) or endpoint not enabled. " +
          "Your FatSecret response was: " +
          msg,
      });
    }

    return res.status(502).json({ error: msg || "Upstream error" });
  }
});

// FatSecret: FOOD GET
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
    return res.status(502).json({ error: e?.message ?? "Upstream error" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on ${PORT}`);
});


