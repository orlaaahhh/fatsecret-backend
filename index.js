import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors());

const PORT = process.env.PORT || 3000;

// ====== CONFIG ======
const AUTH_MODE = (process.env.FATSECRET_AUTH_MODE || "oauth1").toLowerCase();

// OAuth1
const FATSECRET_CONSUMER_KEY = process.env.FATSECRET_CONSUMER_KEY;
const FATSECRET_SHARED_SECRET = process.env.FATSECRET_SHARED_SECRET;

// OAuth2 (optional, for later)
const FATSECRET_CLIENT_ID = process.env.FATSECRET_CLIENT_ID;
const FATSECRET_CLIENT_SECRET = process.env.FATSECRET_CLIENT_SECRET;

const BASE_URL = "https://platform.fatsecret.com/rest/server.api";

// ====== HELPERS ======
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

function buildBaseString(httpMethod, url, params) {
  return [
    httpMethod.toUpperCase(),
    oauthEncode(url),
    oauthEncode(normalizeParams(params)),
  ].join("&");
}

function signHmacSha1(baseString, consumerSecret, tokenSecret = "") {
  const key = `${oauthEncode(consumerSecret)}&${oauthEncode(tokenSecret)}`;
  return crypto.createHmac("sha1", key).update(baseString).digest("base64");
}

function toQueryString(params) {
  return Object.entries(params)
    .map(([k, v]) => `${oauthEncode(k)}=${oauthEncode(String(v))}`)
    .join("&");
}

// ====== OAUTH1 REQUEST ======
function buildOAuth1SignedParams(extraParams) {
  if (!FATSECRET_CONSUMER_KEY || !FATSECRET_SHARED_SECRET) {
    throw new Error("Missing FATSECRET_CONSUMER_KEY or FATSECRET_SHARED_SECRET in .env");
  }

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

  return { ...unsigned, oauth_signature: signature };
}

async function fatsecretGetOAuth1(params) {
  const signed = buildOAuth1SignedParams(params);
  const url = `${BASE_URL}?${toQueryString(signed)}`;
  const res = await fetch(url);
  const text = await res.text();

  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`FatSecret returned non-JSON: ${text.slice(0, 300)}`);
  }

  // FatSecret può restituire { error: {...} } anche con HTTP 200
  if (json?.error) {
    throw new Error(`FatSecret error ${json.error.code}: ${json.error.message}`);
  }
  return json;
}

// ====== OAUTH2 REQUEST (OPTIONAL) ======
let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getAccessTokenOAuth2() {
  if (!FATSECRET_CLIENT_ID || !FATSECRET_CLIENT_SECRET) {
    throw new Error("Missing FATSECRET_CLIENT_ID or FATSECRET_CLIENT_SECRET in .env");
  }

  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAt - 30_000) return cachedToken;

  const basic = Buffer.from(`${FATSECRET_CLIENT_ID}:${FATSECRET_CLIENT_SECRET}`).toString("base64");

  const res = await fetch("https://oauth.fatsecret.com/connect/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "basic",
    }),
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`Token error ${res.status}: ${text}`);

  const json = JSON.parse(text);
  cachedToken = json.access_token;
  cachedTokenExpiresAt = now + json.expires_in * 1000;
  return cachedToken;
}

async function fatsecretGetOAuth2(params) {
  const token = await getAccessTokenOAuth2();
  const url = `${BASE_URL}?${new URLSearchParams({ ...params, format: "json" }).toString()}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  const text = await res.text();

  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`FatSecret returned non-JSON: ${text.slice(0, 300)}`);
  }

  if (json?.error) {
    throw new Error(`FatSecret error ${json.error.code}: ${json.error.message}`);
  }
  return json;
}

// ====== SINGLE ENTRYPOINT ======
async function fatsecretGet(params) {
  if (AUTH_MODE === "oauth2") return fatsecretGetOAuth2(params);
  return fatsecretGetOAuth1({ ...params, format: "json" }); // format json anche per oauth1
}

// ====== ROUTES ======
app.get("/", (req, res) => res.json({ ok: true, mode: AUTH_MODE }));

app.get("/fatsecret/search", async (req, res) => {
  try {
    const query = String(req.query.query ?? "").trim();
    if (!query) return res.status(400).json({ error: "Missing query" });

    const json = await fatsecretGet({
      method: "foods.search",
      search_expression: query,
      max_results: "20",
      page_number: "0",
    });

    const foodsNode = json?.foods?.food;
    const list = Array.isArray(foodsNode) ? foodsNode : foodsNode ? [foodsNode] : [];

    res.json({
      foods: list.map((f) => ({
        food_id: f.food_id,
        food_name: f.food_name,
        brand_name: f.brand_name ?? null,
        food_description: f.food_description ?? null,
      })),
      total_results: json?.foods?.total_results ?? null,
    });
  } catch (e) {
    res.status(502).json({ error: e.message ?? "Server error" });
  }
});

app.get("/fatsecret/food/:id", async (req, res) => {
  try {
    const id = String(req.params.id).trim();
    if (!id) return res.status(400).json({ error: "Missing id" });

    const json = await fatsecretGet({
      method: "food.get",
      food_id: id,
    });

    // qui lasciamo raw per ora: poi estraiamo calories/servings in modo pulito
    res.json(json);
  } catch (e) {
    res.status(502).json({ error: e.message ?? "Server error" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend listening on http://0.0.0.0:${PORT} (mode=${AUTH_MODE})`);
});
