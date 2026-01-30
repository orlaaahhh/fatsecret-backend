import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

dotenv.config();

// ===== LOGGING SYSTEM (Opzionale: per vedere i log nella dashboard logs.html) =====
const MAX_LOGS = 200;
const logBuffer = [];
function captureLog(type, args) {
  const timestamp = new Date().toISOString().split("T")[1].split(".")[0];
  const message = args.map(arg => (typeof arg === 'object' ? JSON.stringify(arg) : String(arg))).join(" ");
  logBuffer.push(`[${timestamp}] [${type.toUpperCase()}] ${message}`);
  if (logBuffer.length > MAX_LOGS) logBuffer.shift();
}
const originalLog = console.log;
const originalError = console.error;
console.log = (...args) => { captureLog("info", args); originalLog.apply(console, args); };
console.error = (...args) => { captureLog("error", args); originalError.apply(console, args); };
// ==============================================================================

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

  // ✅ NUOVO: Tabella Storico (Log ogni X ore)
  await pool.query(`
    create table if not exists user_stats_log (
      id serial primary key,
      user_id integer not null references users(id) on delete cascade,
      calories integer default 0,
      protein numeric(5,1) default 0,
      carbs numeric(5,1) default 0,
      fat numeric(5,1) default 0,
      water_cups numeric(3,1) default 0,
      logged_at timestamptz default now()
    );
  `);

  // ✅ NUOVO: Tabella Giornaliera (1 riga per utente/giorno)
  await pool.query(`
    create table if not exists user_daily_stats (
      id serial primary key,
      user_id integer not null references users(id) on delete cascade,
      date date default current_date not null,
      calories integer default 0,
      protein numeric(5,1) default 0,
      carbs numeric(5,1) default 0,
      fat numeric(5,1) default 0,
      water_cups numeric(3,1) default 0,
      updated_at timestamptz default now(),
      unique(user_id, date)
    );
  `);
  // users goals
  await pool.query(`
    create table if not exists user_goals (
      user_id integer primary key references users(id) on delete cascade,
      calories integer default 2000,
      protein integer default 150,
      carbs integer default 250,
      fat integer default 70,
      water_cups integer default 8,
      updated_at timestamptz default now()
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

const SERVER_API_URL = "https://platform.fatsecret.com/rest/server.api";
async function fatsecretGet(extraParams) {
  return fatsecretGetAt(SERVER_API_URL, extraParams, { debugLabel: "server.api" });
}

// ===== Barcode helpers =====
function digitsOnly(s) { return String(s ?? "").replace(/\D/g, ""); }
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
  return `Per ${sd} - Calories: ${serving.calories ?? 0}kcal | Fat: ${serving.fat ?? 0}g | Carbs: ${serving.carbohydrate ?? 0}g | Protein: ${serving.protein ?? 0}g`;
}

// ===== ROUTES =====
app.get("/", (req, res) => res.json({ ok: true }));

// AUTH: REGISTER
app.post("/auth/register", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");
  if (!email || password.length < 6) return res.status(400).json({ error: "Invalid email or password" });

  const password_hash = await bcrypt.hash(password, 10);
  try {
    const r = await pool.query("insert into users(email,password_hash) values($1,$2) returning id,email", [email, password_hash]);
    return res.json({ token: signToken(r.rows[0]) });
  } catch (e) {
    if (String(e?.message).toLowerCase().includes("duplicate")) return res.status(409).json({ error: "Email exists" });
    return res.status(500).json({ error: "Server error" });
  }
});
// ===========================
// ✅ GESTIONE OBIETTIVI (GOALS)
// ===========================
app.get("/admin/users-list", adminKeyMiddleware, async (req, res) => {
  try {
    const r = await pool.query("select email from users order by email asc");
    return res.json({ users: r.rows });
  } catch (e) {
    return res.status(500).json({ error: "Db error" });
  }
});
// 1. ADMIN: Imposta obiettivi per un utente (tramite email)
app.post("/admin/goals", adminKeyMiddleware, async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const { calories, protein, carbs, fat, water } = req.body;

  if (!email) return res.status(400).json({ error: "Missing email" });

  try {
    // Troviamo l'ID utente dall'email
    const uRes = await pool.query("select id from users where email=$1", [email]);
    if (uRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const uid = uRes.rows[0].id;

    // Salviamo/Aggiorniamo gli obiettivi (UPSERT)
    await pool.query(`
      insert into user_goals (user_id, calories, protein, carbs, fat, water_cups, updated_at)
      values ($1, $2, $3, $4, $5, $6, now())
      on conflict (user_id) do update set
        calories = excluded.calories,
        protein = excluded.protein,
        carbs = excluded.carbs,
        fat = excluded.fat,
        water_cups = excluded.water_cups,
        updated_at = now()
    `, [uid, calories || 2000, protein || 150, carbs || 250, fat || 70, water || 8]);

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "DB Error" });
  }
});

// 2. MOBILE: Scarica i propri obiettivi
app.get("/me/goals", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("select * from user_goals where user_id=$1", [req.user.uid]);
    // Se non ha obiettivi settati, restituiamo i default
    const goals = r.rows[0] || { 
      calories: 2000, protein: 150, carbs: 250, fat: 70, water_cups: 8 
    };
    return res.json({ goals });
  } catch (e) {
    console.error(e);
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

app.get("/me", authMiddleware, (req, res) => res.json({ user: req.user }));
// DASHBOARD: Scarica Excel/CSV
app.get("/admin/export-csv", adminKeyMiddleware, async (req, res) => {
  try {
    // 1. Scarichiamo TUTTI i dati storici
    const r = await pool.query(`
      select u.email, s.date, s.calories, s.protein, s.carbs, s.fat, s.water_cups
      from user_daily_stats s
      join users u on u.id = s.user_id
      order by s.date desc
    `);

    // 2. Creiamo l'intestazione del CSV
    let csv = "Data,Email,Calorie (kcal),Proteine (g),Carboidrati (g),Grassi (g),Acqua (cups)\n";

    // 3. Aggiungiamo le righe
    r.rows.forEach((row) => {
      // Formattiamo la data in YYYY-MM-DD per evitare problemi con Excel
      const dateStr = new Date(row.date).toISOString().split('T')[0];
      
      csv += `${dateStr},${row.email},${row.calories},${row.protein},${row.carbs},${row.fat},${row.water_cups}\n`;
    });

    // 4. Inviamo il file
    res.header("Content-Type", "text/csv");
    res.attachment("report_nutrizione.csv");
    return res.send(csv);

  } catch (e) {
    console.error(e);
    return res.status(500).send("Errore generazione CSV");
  }
});
// ===========================
// ✅ TRACKING / STATS (NUOVO)
// ===========================

// Riceve dati dal Mobile e aggiorna sia lo storico che il giornaliero
app.post("/me/stats-log", authMiddleware, async (req, res) => {
  try {
    const { calories, protein, carbs, fat, water } = req.body;
    const uid = req.user.uid;

    // 1. Inseriamo nello STORICO (Log dettagliato ogni X ore)
    await pool.query(
      `insert into user_stats_log (user_id, calories, protein, carbs, fat, water_cups)
       values ($1, $2, $3, $4, $5, $6)`,
      [uid, calories || 0, protein || 0, carbs || 0, fat || 0, water || 0]
    );

    // 2. Aggiorniamo la tabella GIORNALIERA (Upsert)
    await pool.query(
      `insert into user_daily_stats (user_id, date, calories, protein, carbs, fat, water_cups, updated_at)
       values ($1, current_date, $2, $3, $4, $5, $6, now())
       on conflict (user_id, date) 
       do update set 
         calories = excluded.calories,
         protein = excluded.protein,
         carbs = excluded.carbs,
         fat = excluded.fat,
         water_cups = excluded.water_cups,
         updated_at = now()`,
      [uid, calories || 0, protein || 0, carbs || 0, fat || 0, water || 0]
    );

    console.log(`[STATS] Dati aggiornati per utente ${req.user.email}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error("Stats log error:", e);
    return res.status(500).json({ error: "Errore salvataggio stats" });
  }
});

// ===========================
// ✅ ADMIN ROUTES
// ===========================

// API per Logs (logs.html)
app.get("/admin/server-logs", adminKeyMiddleware, (req, res) => {
  res.json({ logs: logBuffer });
});

// API per Stats Dashboard (stats.html) - NUOVO
app.get("/admin/stats-view", adminKeyMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`
      select u.email, s.date, s.calories, s.protein, s.carbs, s.fat, s.water_cups, s.updated_at
      from user_daily_stats s
      join users u on u.id = s.user_id
      order by s.date desc, s.updated_at desc
      limit 100
    `);
    return res.json({ stats: r.rows });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.get("/admin/users", adminKeyMiddleware, async (req, res) => {
  const email = String(req.query.email ?? "").trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Missing email" });
  const r = await pool.query(`select id, email from users where email=$1`, [email]);
  return res.json({ user: r.rows[0] ?? null });
});

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
     values ($1,$2,$3,$4,$5) returning id, title, start_time, end_time, zoom_url`,
    [userId, title, start.toISOString(), end.toISOString(), zoomUrl]
  );
  return res.status(201).json({ meeting: r.rows[0] });
});

// ===========================
// ✅ USER API: MEETINGS
// ===========================
app.get("/meetings", authMiddleware, async (req, res) => {
  try {
    const from = String(req.query.from ?? "");
    const to = String(req.query.to ?? "");
    const fromDate = new Date(from);
    const toDate = new Date(to);
    if (!from || !to || isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
      return res.status(400).json({ error: "Invalid dates" });
    }
    const r = await pool.query(
      `select id, title, start_time, end_time, zoom_url
       from meetings where user_id = $1 and start_time >= $2 and start_time < $3
       order by start_time asc`,
      [req.user.uid, fromDate.toISOString(), toDate.toISOString()]
    );
    return res.json({ meetings: r.rows });
  } catch (e) {
    console.error("GET /meetings error:", e);
    return res.status(500).json({ error: "Server error (meetings)" });
  }
});

// ======================
// FatSecret endpoints
// ======================
app.get("/fatsecret/search", authMiddleware, async (req, res) => {
  try {
    const query = String(req.query.query ?? "").trim();
    if (!query) return res.status(400).json({ error: "Missing query" });
    const json = await fatsecretGet({ method: "foods.search", format: "json", search_expression: query, max_results: "20", page_number: "0" });
    const foodsNode = json?.foods?.food;
    const list = Array.isArray(foodsNode) ? foodsNode : foodsNode ? [foodsNode] : [];
    return res.json({
      foods: list.map((f) => ({ food_id: f.food_id, food_name: f.food_name, brand_name: f.brand_name ?? null, food_description: f.food_description ?? null })),
      total_results: json?.foods?.total_results ?? null,
    });
  } catch (e) { return res.status(502).json({ error: e?.message ?? "Upstream error" }); }
});

app.get("/fatsecret/barcode", authMiddleware, async (req, res) => {
  try {
    const barcodeRaw = String(req.query.barcode ?? "").trim();
    const gtin13 = toGTIN13(barcodeRaw);
    if (!gtin13) return res.status(400).json({ error: "Invalid barcode" });
    
    const json = await fatsecretGetAt(
      "https://platform.fatsecret.com/rest/food/barcode/find-by-id/v2",
      { format: "json", barcode: gtin13, region: req.query.region ?? "IT", language: req.query.language ?? "en", flag_default_serving: "true" },
      { debugLabel: "barcode.v2" }
    );
    const food = json?.food;
    if (!food?.food_id) return res.json({ foods: [] });
    return res.json({ foods: [{ food_id: String(food.food_id), food_name: String(food.food_name), brand_name: food.brand_name ?? null, food_description: makeDescriptionFromServing(pickDefaultServing(food?.servings)) }] });
  } catch (e) { return res.status(502).json({ error: e?.message ?? "Upstream error" }); }
});

app.get("/fatsecret/food/:id", authMiddleware, async (req, res) => {
  try { return res.json(await fatsecretGet({ method: "food.get", format: "json", food_id: req.params.id })); }
  catch (e) { return res.status(502).json({ error: e?.message ?? "Upstream error" }); }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on ${PORT}`);
});




