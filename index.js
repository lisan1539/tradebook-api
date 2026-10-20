const ALLOWED_ORIGIN = "https://tradebook-stores.pages.dev";
const ITERATIONS = 30000; // iterations used for every NEW hash (stored per user in users.pw_iter)
const MAX_BODY = 262144;
const MAX_SESSIONS = 10;
// Sign-in limits per 15 minutes: same name from same phone / same name from anywhere / anyone from same address
const LOGIN_LIMITS = { ui: 5, u: 20, ip: 40 };
function targetIter(env) {
  const n = parseInt(env && env.PW_ITER, 10);
  return n >= 10000 && n <= 100000 ? n : ITERATIONS;
}
const SESSION_MS = 30 * 24 * 3600 * 1000;
const LOCK_WINDOW = 15 * 60 * 1000;
const enc = new TextEncoder();

// ALLOWED_ORIGIN is the original app address. It stays allowed, and it is used by any business
// that has no addresses of its own set yet. Each business can have its own addresses (M3).
const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Business-Code",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
const fail = (status, message) => json({ error: message }, status);

const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randomHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));
async function sha256(text) {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
async function hashPassword(password, saltHex, iter = ITERATIONS) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(saltHex), iterations: iter },
    key,
    256
  );
  return toHex(bits);
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function cleanUsername(v) {
  const u = String(v || "").trim().toLowerCase();
  return /^[a-z0-9._-]{3,30}$/.test(u) ? u : null;
}
async function readBody(request) {
  try {
    const t = await request.text();
    if (t.length > MAX_BODY) return {};
    return JSON.parse(t);
  } catch { return {}; }
}
const publicUser = (u) => ({
  id: u.id,
  username: u.username,
  displayName: u.display_name,
  isSuperAdmin: !!u.is_super_admin,
  isPlatform: !!u.is_platform,
  businessId: u.owner_id || u.id,
  businessName: u.biz_name || "",
  businessCode: u.biz_code || "",
  mustChangePassword: !!u.must_change_password,
  isDesk: !!u.is_desk,
});

// ---- Businesses (M1) ----
// One business = one owner account (the Super Admin of that business). Keepers belong to the owner
// through users.owner_id. The "platform" account is the app provider: it creates and manages businesses.
const MAX_BUSINESSES = 500;
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS businesses (id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL, note TEXT)",
  "ALTER TABLE users ADD COLUMN is_platform INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE businesses ADD COLUMN trial_started_at INTEGER",
  "ALTER TABLE businesses ADD COLUMN paid_until INTEGER",
  "ALTER TABLE businesses ADD COLUMN store_limit INTEGER NOT NULL DEFAULT 3",
  "ALTER TABLE businesses ADD COLUMN code TEXT",
  "ALTER TABLE businesses ADD COLUMN secret TEXT",
  "ALTER TABLE businesses ADD COLUMN origins TEXT",
  "CREATE UNIQUE INDEX IF NOT EXISTS businesses_code ON businesses(code)",
  "CREATE TABLE IF NOT EXISTS licence_codes (code TEXT PRIMARY KEY, business_id TEXT NOT NULL, months INTEGER NOT NULL, stores INTEGER NOT NULL, amount INTEGER NOT NULL, sig TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT, expires_at INTEGER NOT NULL, voided_at INTEGER, redeemed_at INTEGER, redeemed_by TEXT)",
  "CREATE INDEX IF NOT EXISTS licence_codes_biz ON licence_codes(business_id, created_at)",
  "CREATE TABLE IF NOT EXISTS app_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
  "ALTER TABLE users ADD COLUMN pw_iter INTEGER NOT NULL DEFAULT 30000",
  "CREATE INDEX IF NOT EXISTS tb_entries_store_upd ON entries(store_id, updated_at)",
  "CREATE INDEX IF NOT EXISTS tb_audit_store ON audit_log(store_id, id)",
  "CREATE INDEX IF NOT EXISTS tb_audit_user ON audit_log(user_id)",
  "CREATE INDEX IF NOT EXISTS tb_users_owner ON users(owner_id)",
  "CREATE INDEX IF NOT EXISTS tb_stores_owner ON stores(owner_id)",
  "CREATE INDEX IF NOT EXISTS tb_members_store ON memberships(store_id)",
  "CREATE INDEX IF NOT EXISTS tb_sessions_user ON sessions(user_id, created_at)",
  "CREATE INDEX IF NOT EXISTS tb_sessions_exp ON sessions(expires_at)",
  "CREATE INDEX IF NOT EXISTS tb_login_win ON login_attempts(window_start)",
  "CREATE TABLE IF NOT EXISTS pay_reports (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, user_id TEXT, months INTEGER NOT NULL, stores INTEGER NOT NULL, amount INTEGER NOT NULL, note TEXT, status TEXT NOT NULL DEFAULT 'pending', code TEXT, reply TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, dismissed_at INTEGER)",
  "CREATE INDEX IF NOT EXISTS pay_reports_biz ON pay_reports(business_id, created_at)",
  "CREATE INDEX IF NOT EXISTS pay_reports_status ON pay_reports(status, created_at)",
  // ---- Shop / Cart (C1, C2) ----
  "ALTER TABLE users ADD COLUMN is_desk INTEGER NOT NULL DEFAULT 0",
  "CREATE TABLE IF NOT EXISTS shop_products (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, name TEXT NOT NULL, price INTEGER NOT NULL, category TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS shop_products_biz ON shop_products(business_id, active)",
  "CREATE TABLE IF NOT EXISTS shop_settings (business_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, bank_name TEXT NOT NULL DEFAULT '', acct_name TEXT NOT NULL DEFAULT '', acct_no TEXT NOT NULL DEFAULT '', welcome TEXT NOT NULL DEFAULT '', price_edit INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)",
  "CREATE TABLE IF NOT EXISTS shop_customers (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, username TEXT NOT NULL, display_name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, pw_iter INTEGER NOT NULL DEFAULT 30000, is_active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0)",
  "CREATE UNIQUE INDEX IF NOT EXISTS shop_customers_u ON shop_customers(business_id, username)",
  "CREATE TABLE IF NOT EXISTS shop_sessions (token_hash TEXT PRIMARY KEY, customer_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS shop_sessions_c ON shop_sessions(customer_id)",
  // ---- Orders (C3) ----
  "CREATE TABLE IF NOT EXISTS shop_orders (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, no INTEGER NOT NULL, customer_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'submitted', asked TEXT NOT NULL, items TEXT NOT NULL, total INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '', assigned_to TEXT, idem TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
  "CREATE UNIQUE INDEX IF NOT EXISTS shop_orders_no ON shop_orders(business_id, no)",
  "CREATE UNIQUE INDEX IF NOT EXISTS shop_orders_idem ON shop_orders(customer_id, idem)",
  "CREATE INDEX IF NOT EXISTS shop_orders_biz ON shop_orders(business_id, status, updated_at)",
  "CREATE INDEX IF NOT EXISTS shop_orders_cust ON shop_orders(customer_id, created_at)",
  "CREATE TABLE IF NOT EXISTS shop_order_events (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL, at INTEGER NOT NULL, actor TEXT NOT NULL, who TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')",
  "CREATE INDEX IF NOT EXISTS shop_order_events_o ON shop_order_events(order_id, id)",
  // ---- Invoices and payment (C4, C5) ----
  "ALTER TABLE shop_orders ADD COLUMN adj TEXT NOT NULL DEFAULT '[]'",
  "ALTER TABLE shop_orders ADD COLUMN inv_no INTEGER",
  "ALTER TABLE shop_orders ADD COLUMN staff_note TEXT NOT NULL DEFAULT ''",
  "ALTER TABLE shop_orders ADD COLUMN expires_at INTEGER",
  "ALTER TABLE shop_orders ADD COLUMN pay_note TEXT NOT NULL DEFAULT ''",
  "ALTER TABLE shop_orders ADD COLUMN paid_at INTEGER",
  "CREATE UNIQUE INDEX IF NOT EXISTS shop_orders_inv ON shop_orders(business_id, inv_no)",
  // ---- Automatic stock-out when an order is paid (C7) ----
  "ALTER TABLE shop_settings ADD COLUMN stock_store TEXT NOT NULL DEFAULT ''",
  "ALTER TABLE shop_orders ADD COLUMN stock_entry TEXT NOT NULL DEFAULT ''",
  // ---- Hide prices from customers until the shop invoices the order ----
  "ALTER TABLE shop_settings ADD COLUMN hide_prices INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shop_products ADD COLUMN hide_price INTEGER NOT NULL DEFAULT 0",
];

// ---- Prepaid codes and prices (M5) ----
// Price: 1,500 naira per month per block of 3 stores; 10% off for 6 months, 15% off for 12 months.
const PRICE_BLOCK = 1500;
function priceFor(stores, months) {
  const monthly = PRICE_BLOCK * Math.max(1, Math.ceil(stores / 3));
  return Math.round(months === 12 ? monthly * 12 * 0.85 : months === 6 ? monthly * 6 * 0.9 : monthly);
}
const priceTable = () => [3, 6, 9, 12].map((n) => ({ stores: n, m1: priceFor(n, 1), m6: priceFor(n, 6), m12: priceFor(n, 12) }));
const CODE_LIFE = 365 * 86400000;
const CODE_RE = /^TB-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/;
function newLicenceCode() {
  const c = [...crypto.getRandomValues(new Uint8Array(12))].map((x) => CODE_CHARS[x % 32]).join("");
  return "TB-" + c.slice(0, 4) + "-" + c.slice(4, 8) + "-" + c.slice(8);
}
function normaliseCode(v) {
  const t = String(v || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const m = t.match(/^TB([A-Z0-9]{12})$/);
  return m ? "TB-" + m[1].slice(0, 4) + "-" + m[1].slice(4, 8) + "-" + m[1].slice(8) : "";
}
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
const codeStatus = (r, now) => (r.redeemed_at ? "redeemed" : r.voided_at ? "voided" : now > r.expires_at ? "expired" : "unused");
const codeOut = (r, now) => ({
  code: r.code, months: r.months, stores: r.stores, amount: r.amount,
  createdAt: r.created_at, expiresAt: r.expires_at, redeemedAt: r.redeemed_at || null, status: codeStatus(r, now),
});
const BAD_CODE = "That code isn't valid. Check it and try again.";

// ---- Business identity (M3) ----
// code   = short public business code (printed on the app, safe to share)
// secret = private, one per business, never sent to the app. Used to sign that business's prepaid
//          licence codes (M5), so a code for one business can never work for another.
// origins= the web addresses allowed to use the backend for that business (comma separated)
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const newCode = () => [...crypto.getRandomValues(new Uint8Array(6))].map((x) => CODE_CHARS[x % 32]).join("");
async function newIdentity(env) {
  for (let i = 0; i < 10; i++) {
    const code = newCode();
    const hit = await env.DB.prepare("SELECT 1 AS x FROM businesses WHERE code=?").bind(code).first();
    if (!hit) return { code, secret: randomHex(32) };
  }
  throw new Error("no code");
}
function cleanOrigins(list) {
  if (!Array.isArray(list) || list.length > 5) return null;
  const out = [];
  for (const v of list) {
    let u;
    try { u = new URL(String(v).trim()); } catch { return null; }
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (!(u.protocol === "https:" || (local && u.protocol === "http:"))) return null;
    if (u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) return null;
    if (!out.includes(u.origin)) out.push(u.origin);
  }
  return out;
}
let OC = null;
// Remember the list for 15 seconds only. A web address that is not on the list gets one fresh look at the
// database (at most every 5 seconds) so a newly saved address works at once instead of after a minute.
async function allowedOrigins(env, origin) {
  const now = Date.now();
  if (OC && now - OC.t < 15000) {
    if (!origin || OC.set.has(origin) || now - (OC.miss || 0) < 5000) return OC.set;
    OC.miss = now;
  }
  const r = await env.DB.prepare("SELECT origins FROM businesses WHERE origins IS NOT NULL AND origins<>''").all();
  const set = new Set([ALLOWED_ORIGIN]);
  for (const x of r.results) for (const o of x.origins.split(",")) if (o) set.add(o);
  OC = { t: now, set, miss: now };
  return set;
}
function originOk(u, origin, request) {
  if (u.is_platform) return true;
  const code = request.headers.get("X-Business-Code");
  if (code && (!u.biz_code || code.trim().toUpperCase() !== u.biz_code)) return false;
  if (!origin) return true;
  const list = u.biz_origins ? u.biz_origins.split(",") : [ALLOWED_ORIGIN];
  return list.includes(origin);
}
const WRONG_APP = () =>
  json({ error: "This app is not set up for your business. Please use your business's own app.", code: "wrong_app" }, 403);

// ---- Licence (M2) ----
// Trial starts at the first sign-in of the business. After it ends there is a grace period (everything
// still works, with a warning), then the business becomes view-only. All times are server times.
const DAY = 86400000;
const TRIAL_DAYS = 14;
const GRACE_DAYS = 7;
const DEFAULT_STORE_LIMIT = 3;
function licenceOf(u, now, storesUsed) {
  if (u.is_platform) return { state: "unlimited", storeLimit: null, storesUsed, serverTime: now };
  const ts = Number(u.trial_started_at) || 0;
  const paid = Number(u.paid_until) || 0;
  const trialEnd = ts ? ts + TRIAL_DAYS * DAY : null;
  const end = Math.max(trialEnd || 0, paid);
  let state;
  if ((!ts && !paid) || (trialEnd && now < trialEnd)) state = "trial";
  else if (now < paid) state = "active";
  else if (now < end + GRACE_DAYS * DAY) state = "grace";
  else state = "readonly";
  const target = state === "grace" ? end + GRACE_DAYS * DAY : end;
  return {
    state,
    trialEndsAt: trialEnd,
    paidUntil: paid || null,
    endsAt: end || null,
    graceEndsAt: end ? end + GRACE_DAYS * DAY : null,
    daysLeft: state === "readonly" ? 0 : target ? Math.max(0, Math.ceil((target - now) / DAY)) : TRIAL_DAYS,
    storeLimit: u.store_limit || DEFAULT_STORE_LIMIT,
    storesUsed,
    serverTime: now,
  };
}
async function licenceFor(env, u) {
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM stores WHERE owner_id=? AND is_archived=0")
    .bind(u.owner_id || u.id).first();
  return licenceOf(u, Date.now(), c.n);
}
function addMonthsFrom(base, n) {
  const d = new Date(base);
  d.setUTCMonth(d.getUTCMonth() + n);
  return d.getTime();
}
let READY = null;
function ensureSchema(env) {
  if (READY) return READY;
  READY = (async () => {
    for (const q of SCHEMA) {
      try { await env.DB.prepare(q).run(); }
      catch (e) { if (!/duplicate column|already exists/i.test(String((e && e.message) || e))) throw e; }
    }
    await env.DB.prepare(
      "INSERT OR IGNORE INTO businesses (id,name,status,created_at) SELECT id, display_name || char(39) || 's business', 'active', created_at FROM users WHERE is_super_admin=1 AND owner_id IS NULL"
    ).run();
    const need = await env.DB.prepare("SELECT id FROM businesses WHERE code IS NULL OR secret IS NULL").all();
    for (const x of need.results) {
      const idn = await newIdentity(env);
      await env.DB.prepare("UPDATE businesses SET code=COALESCE(code,?), secret=COALESCE(secret,?) WHERE id=?")
        .bind(idn.code, idn.secret, x.id).run();
    }
    const p = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE is_platform=1").first();
    if (!p.n)
      await env.DB.prepare(
        "UPDATE users SET is_platform=1 WHERE id=(SELECT id FROM users WHERE is_super_admin=1 AND owner_id IS NULL ORDER BY created_at LIMIT 1)"
      ).run();
  })().catch((e) => { READY = null; throw e; });
  return READY;
}
const BIZ_JOIN = " LEFT JOIN businesses b ON b.id=COALESCE(u.owner_id,u.id)";
const cleanBizName = (v) => String(v || "").trim().replace(/\s+/g, " ").slice(0, 80);

async function getUser(request, env) {
  const h = request.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  const th = await sha256(h.slice(7));
  const row = await env.DB.prepare(
    "SELECT u.id,u.username,u.display_name,u.owner_id,u.is_super_admin,u.is_platform,u.is_desk,u.must_change_password,b.name AS biz_name,b.code AS biz_code,b.origins AS biz_origins,b.trial_started_at,b.paid_until,b.store_limit,COALESCE(b.status,'active') AS biz_status FROM sessions s JOIN users u ON u.id=s.user_id" + BIZ_JOIN + " WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1"
  ).bind(th, Date.now()).first();
  return row ? { ...row, th } : null;
}
async function newSession(env, userId) {
  const token = randomHex(32);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)"
  ).bind(await sha256(token), userId, now + SESSION_MS, now).run();
  // keep only the newest MAX_SESSIONS sign-ins of this person
  await env.DB.prepare(
    "DELETE FROM sessions WHERE user_id=?1 AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2)"
  ).bind(userId, MAX_SESSIONS).run();
  return token;
}
// Housekeeping: now and then remove expired sessions and old sign-in counters (keeps the database small)
async function purgeOld(env, now) {
  if (Math.random() > 0.05) return;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at<?").bind(now),
    env.DB.prepare("DELETE FROM login_attempts WHERE window_start<?").bind(now - LOCK_WINDOW),
  ]);
}
const BUMP_SQL = "INSERT INTO login_attempts (username,fail_count,window_start) VALUES (?1,1,?2) ON CONFLICT(username) DO UPDATE SET fail_count = CASE WHEN ?2 - window_start >= ?3 THEN 1 ELSE fail_count + 1 END, window_start = CASE WHEN ?2 - window_start >= ?3 THEN ?2 ELSE window_start END";
async function storesFor(user, env) {
  if (user.is_super_admin) {
    const r = await env.DB.prepare(
      "SELECT id,name,address FROM stores WHERE owner_id=? AND is_archived=0 ORDER BY created_at"
    ).bind(user.id).all();
    return r.results.map((s) => ({ ...s, role: "owner" }));
  }
  const r = await env.DB.prepare(
    "SELECT s.id,s.name,s.address,m.role FROM memberships m JOIN stores s ON s.id=m.store_id WHERE m.user_id=? AND s.is_archived=0 ORDER BY s.created_at"
  ).bind(user.id).all();
  return r.results;
}


const ROLES = ["manager", "keeper", "viewer"];
const MAX_KEEPERS = 50;

async function ownedStoreIds(env, ownerId) {
  const r = await env.DB.prepare(
    "SELECT id FROM stores WHERE owner_id=? AND is_archived=0"
  ).bind(ownerId).all();
  return new Set(r.results.map((x) => x.id));
}
function cleanAssignments(list, owned) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const out = [];
  for (const a of list) {
    if (!a || !owned.has(a.storeId) || !ROLES.includes(a.role) || seen.has(a.storeId)) continue;
    seen.add(a.storeId);
    out.push({ storeId: a.storeId, role: a.role });
  }
  return out;
}
async function keepersFor(user, env) {
  const u = await env.DB.prepare(
    "SELECT id,username,display_name,is_active,is_desk,must_change_password FROM users WHERE owner_id=? ORDER BY created_at"
  ).bind(user.id).all();
  const m = await env.DB.prepare(
    "SELECT m.user_id,m.store_id,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.owner_id=?"
  ).bind(user.id).all();
  const by = {};
  for (const r of m.results) (by[r.user_id] = by[r.user_id] || []).push({ storeId: r.store_id, role: r.role });
  return u.results.map((k) => ({
    id: k.id,
    username: k.username,
    displayName: k.display_name,
    isActive: !!k.is_active,
    isDesk: !!k.is_desk,
    mustChangePassword: !!k.must_change_password,
    assignments: by[k.id] || [],
  }));
}
const audit = (env, storeId, userId, action, detail) =>
  env.DB.prepare(
    "INSERT INTO audit_log (store_id,user_id,action,detail,created_at) VALUES (?,?,?,?,?)"
  ).bind(storeId, userId, action, detail, Date.now());


async function roleIn(env, user, storeId) {
  if (user.is_super_admin) {
    const s = await env.DB.prepare(
      "SELECT id FROM stores WHERE id=? AND owner_id=? AND is_archived=0"
    ).bind(storeId, user.id).first();
    return s ? "owner" : null;
  }
  const m = await env.DB.prepare(
    "SELECT m.role FROM memberships m JOIN stores s ON s.id=m.store_id WHERE m.user_id=? AND m.store_id=? AND s.is_archived=0"
  ).bind(user.id, storeId).first();
  return m ? m.role : null;
}
const canModifyEntry = (role, user, e) =>
  role === "owner" || role === "manager" || (role === "keeper" && e.created_by === user.id);

function validDate(s) {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + "T00:00:00Z");
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
}
function cleanEntry(b) {
  const type = b.type === "in" || b.type === "out" ? b.type : null;
  if (!type) return { error: "Entry type must be in or out" };
  const ref = String(b.ref || "").trim().slice(0, 120);
  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 200)
    return { error: "An entry needs between 1 and 200 items" };
  const items = [];
  for (const it of b.items) {
    const name = String((it && it.name) || "").trim().slice(0, 80);
    const qty = Number(it && it.qty);
    if (!name || !Number.isFinite(qty) || qty <= 0 || qty > 1e9)
      return { error: "Each item needs a name and a quantity above 0" };
    items.push({ name, qty });
  }
  return { type, ref, items };
}
const ENTRY_SELECT =
  "SELECT e.id,e.type,e.entry_date,e.ref,e.items,e.created_by,e.created_at,e.updated_at,e.edited,e.deleted_at,u.display_name AS created_by_name FROM entries e LEFT JOIN users u ON u.id=e.created_by";
const entryOut = (r) => ({
  id: r.id,
  type: r.type,
  date: r.entry_date,
  ref: r.ref || "",
  items: JSON.parse(r.items),
  createdAt: r.created_at,
  rev: r.updated_at,
  edited: !!r.edited,
  createdBy: r.created_by,
  createdByName: r.created_by_name || "",
  deleted: !!r.deleted_at,
});

const ENTRY_ID = /^[A-Za-z0-9_-]{8,40}$/;
const ENTRY_ACTIONS = "('entry_added','entry_edited','entry_deleted')";
const activityOut = (r) => {
  const out = {
    id: r.id,
    action: r.action,
    at: r.created_at,
    who: r.user_name || "",
    storeId: r.store_id || null,
    storeName: r.store_name || "",
    detail: r.detail || "",
  };
  if (r.e_items) {
    try { out.entry = { type: r.e_type, ref: r.e_ref || "", items: JSON.parse(r.e_items) }; } catch (e) {}
  }
  return out;
};
const ACTIVITY_SELECT =
  "SELECT a.id,a.action,a.detail,a.created_at,a.store_id,u.display_name AS user_name,s.name AS store_name,e.type AS e_type,e.ref AS e_ref,e.items AS e_items FROM audit_log a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN stores s ON s.id=a.store_id LEFT JOIN entries e ON a.action IN " +
  ENTRY_ACTIONS + " AND e.id=substr(a.detail, instr(a.detail, ':') + 1)";

// ---- Payment reports ("I have paid") ----
const PAY_STATUS = ["pending", "sent", "declined", "closed"];
const PAY_SELECT = "SELECT p.*,b.name AS biz_name,u.username AS owner_username FROM pay_reports p JOIN businesses b ON b.id=p.business_id LEFT JOIN users u ON u.id=p.business_id";
const payOut = (r, platform) => {
  const o = {
    id: r.id, status: r.status, months: r.months, stores: r.stores, amount: r.amount, note: r.note || "",
    createdAt: r.created_at, updatedAt: r.updated_at, reply: r.reply || "",
    code: r.status === "sent" || r.status === "closed" ? r.code || "" : "",
  };
  if (platform) { o.businessId = r.business_id; o.businessName = r.biz_name || ""; o.ownerUsername = r.owner_username || ""; }
  return o;
};

// ---- Shop / Cart (C1, C2): catalogue, shop settings, customer accounts ----
// Customers are NOT staff accounts. They live in their own tables and sessions, so a customer token is never
// accepted by any staff endpoint (and the reverse). Prices are whole naira.
const SHOP = { maxProducts: 500, maxCustomers: 2000, maxPrice: 100000000, importLines: 200, sessions: 5, signupPerWindow: 6 };
const SHOP_PHONE = /^\+?[0-9]{7,15}$/;
const cleanText = (v, n) => String(v == null ? "" : v).replace(/[<>\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const cleanPhone = (v) => String(v || "").replace(/[\s()-]/g, "");
const parsePrice = (v) => {
  const t = String(v == null ? "" : v).replace(/[₦,\s]|naira|ngn/gi, "").replace(/^n(?=\d)/i, "");
  if (!/^\d{1,9}$/.test(t)) return null;
  const n = parseInt(t, 10);
  return n >= 1 && n <= SHOP.maxPrice ? n : null;
};
const settingsOut = (r) => ({
  enabled: !!(r && r.enabled), bankName: (r && r.bank_name) || "", acctName: (r && r.acct_name) || "", acctNo: (r && r.acct_no) || "",
  welcome: (r && r.welcome) || "", priceEdit: !!(r && r.price_edit), stockStore: (r && r.stock_store) || "", hidePrices: !!(r && r.hide_prices),
});
const productOut = (r) => ({ id: r.id, name: r.name, price: r.price, category: r.category || "", active: !!r.active, hidePrice: !!r.hide_price });
// Which business is this shop page for? The app's business code (config.js) first, otherwise its web address.
async function shopBiz(env, request, origin) {
  const code = (request.headers.get("X-Business-Code") || "").trim().toUpperCase();
  const COLS = "SELECT id,name,status,origins,code,trial_started_at,paid_until,store_limit FROM businesses";
  let b = null;
  if (code) b = await env.DB.prepare(COLS + " WHERE code=?").bind(code).first();
  else if (origin) {
    const r = await env.DB.prepare(COLS + " WHERE origins LIKE ?").bind("%" + origin + "%").all();
    const hit = r.results.filter((x) => String(x.origins || "").split(",").includes(origin));
    if (hit.length === 1) b = hit[0];
  }
  if (!b) return { error: fail(404, "This shop is not set up. Please use the shop link from the business.") };
  if (origin) {
    const list = b.origins ? b.origins.split(",") : [ALLOWED_ORIGIN];
    if (!list.includes(origin)) return { error: WRONG_APP() };
  }
  if (b.status !== "active") return { error: fail(403, "This shop is not available right now.") };
  const st = await env.DB.prepare("SELECT * FROM shop_settings WHERE business_id=?").bind(b.id).first();
  const lic = licenceOf(b, Date.now(), 0);
  return { b, st, open: !!(st && st.enabled) && lic.state !== "readonly" };
}
const custOut = (c) => ({ id: c.id, username: c.username, displayName: c.display_name, phone: c.phone });
async function newCustSession(env, cid) {
  const token = randomHex(32), now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO shop_sessions (token_hash,customer_id,expires_at,created_at) VALUES (?,?,?,?)").bind(await sha256(token), cid, now + SESSION_MS, now),
    env.DB.prepare("DELETE FROM shop_sessions WHERE customer_id=?1 AND token_hash NOT IN (SELECT token_hash FROM shop_sessions WHERE customer_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2)").bind(cid, SHOP.sessions),
  ]);
  return token;
}
async function getCustomer(request, env, bid) {
  const h = request.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  const th = await sha256(h.slice(7));
  const row = await env.DB.prepare(
    "SELECT c.* FROM shop_sessions s JOIN shop_customers c ON c.id=s.customer_id WHERE s.token_hash=? AND s.expires_at>? AND c.business_id=? AND c.is_active=1"
  ).bind(th, Date.now(), bid).first();
  return row ? { ...row, th } : null;
}
async function shopLimited(env, keys, limits, now) {
  const att = await env.DB.prepare("SELECT username,fail_count,window_start FROM login_attempts WHERE username IN (" + keys.map(() => "?").join(",") + ")").bind(...keys).all();
  for (const a of att.results) {
    const i = keys.indexOf(a.username);
    if (i >= 0 && now - a.window_start < LOCK_WINDOW && a.fail_count >= limits[i]) return true;
  }
  return false;
}
// ---- Orders (C3) ----
const ORDER_OPEN = ["submitted", "reviewing", "approved", "accepted", "paid_reported"];
const ORDER_LIMITS = { lines: 50, qty: 999, open: 5, perHour: 10, note: 200 };
const firstName = (n) => String(n || "").trim().split(/\s+/)[0] || "";
const evStmt = (env, orderId, actor, who, action, detail) =>
  env.DB.prepare("INSERT INTO shop_order_events (order_id,at,actor,who,action,detail) VALUES (?,?,?,?,?,?)").bind(orderId, Date.now(), actor, who || "", action, detail || "");
const evOut = (e) => ({ at: e.at, actor: e.actor, who: e.who, action: e.action, detail: e.detail });
const orderLinesOut = (txt) => { try { return JSON.parse(txt).map((l) => ({ id: l.id, name: l.name, price: l.price, qty: l.qty, hid: l.hid ? 1 : 0 })); } catch (e) { return []; } };
const ORDER_HOURS = 24;
// A paid order takes its items out of the chosen store. The entry id comes from the order id, so it can never be recorded twice.
async function stockOutOrder(env, bid, o, userId, userName_, now) {
  if (o.stock_entry) return { done: true };
  const st = await env.DB.prepare("SELECT stock_store FROM shop_settings WHERE business_id=?").bind(bid).first();
  const sid = st && st.stock_store;
  if (!sid) return { done: false, reason: "off" };
  const store = await env.DB.prepare("SELECT id,name FROM stores WHERE id=? AND owner_id=? AND is_archived=0").bind(sid, bid).first();
  if (!store) return { done: false, reason: "store" };
  const items = orderLinesOut(o.items).map((l) => ({ name: l.name, qty: l.qty }));
  if (!items.length || items.length > 200) return { done: false, reason: "items" };
  const eid = "o" + o.id.replace(/-/g, "");
  const ref = ("Order #" + o.no + (o.inv_no ? " " + invLabel(o.inv_no) : "")).slice(0, 120);
  const date = new Date(now + 3600000).toISOString().slice(0, 10);
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO entries (id,store_id,type,entry_date,ref,items,created_by,created_at,updated_at,deleted_at) VALUES (?,?,'out',?,?,?,?,?,?,NULL)").bind(eid, store.id, date, ref, JSON.stringify(items), userId, now, now),
    env.DB.prepare("UPDATE shop_orders SET stock_entry=? WHERE id=? AND stock_entry=''").bind(eid, o.id),
    audit(env, store.id, userId, "entry_added", "out:" + eid),
    evStmt(env, o.id, "staff", userName_, "stock_out", store.name),
  ]);
  return { done: true, store: store.name };
}
const invLabel = (n) => (n ? "INV-" + String(n).padStart(4, "0") : "");
const adjOut = (txt) => { try { return JSON.parse(txt || "[]").map((a) => ({ label: a.label, amount: a.amount })); } catch (e) { return []; } };
const ngnTxt = (n) => "\u20A6" + Math.round(n).toLocaleString("en-US");
// A waiting invoice or payment that nobody answered in 24 hours expires. Checked whenever orders are read.
async function expireOrders(env, bid, now) {
  const r = (await env.DB.prepare("SELECT id FROM shop_orders WHERE business_id=? AND status IN ('approved','accepted') AND expires_at IS NOT NULL AND expires_at<? LIMIT 50").bind(bid, now).all()).results;
  for (const x of r) {
    const u = await env.DB.prepare("UPDATE shop_orders SET status='expired',updated_at=? WHERE id=? AND status IN ('approved','accepted') AND expires_at<?").bind(now, x.id, now).run();
    if (u.meta && u.meta.changes) await evStmt(env, x.id, "system", "", "expired", "").run();
  }
}
function editSummary(before, after, adjB, adjA) {
  const out = [], bm = new Map(before.map((l) => [l.id, l])), am = new Map(after.map((l) => [l.id, l]));
  for (const l of after) {
    const o = bm.get(l.id);
    if (!o) out.push(l.name + " added \u00D7" + l.qty);
    else { if (o.qty !== l.qty) out.push(l.name + " " + o.qty + "\u2192" + l.qty); if (o.price !== l.price) out.push(l.name + " price " + ngnTxt(o.price) + "\u2192" + ngnTxt(l.price)); }
  }
  for (const l of before) if (!am.has(l.id)) out.push(l.name + " removed");
  const key = (a) => a.label + "|" + a.amount;
  const ab = new Set(adjB.map(key)), aa = new Set(adjA.map(key));
  for (const a of adjA) if (!ab.has(key(a))) out.push(a.label + " " + (a.amount > 0 ? "+" : "-") + ngnTxt(Math.abs(a.amount)));
  for (const a of adjB) if (!aa.has(key(a))) out.push(a.label + " removed");
  return out.join("; ").slice(0, 300) || "No changes";
}
const orderEvents = async (env, id) => (await env.DB.prepare("SELECT at,actor,who,action,detail FROM shop_order_events WHERE order_id=? ORDER BY id").bind(id).all()).results.map(evOut);
const userName = async (env, id) => (id ? ((await env.DB.prepare("SELECT display_name FROM users WHERE id=?").bind(id).first()) || {}).display_name || "" : "");

async function shopCustomerApi(request, env, origin, path, method) {
  const r = await shopBiz(env, request, origin);
  if (r.error) return r.error;
  const { b, st, open } = r;
  const now = Date.now();
  const ip = (request.headers.get("CF-Connecting-IP") || "unknown").slice(0, 60);
  const bump = (...ks) => env.DB.batch(ks.map((k) => env.DB.prepare(BUMP_SQL).bind(k, now, LOCK_WINDOW)));
  const info = { name: b.name, open, welcome: (st && st.welcome) || "" };

  if (path === "/api/c/info" && method === "GET") return json(info);

  if (path === "/api/c/signup" && method === "POST") {
    if (!open) return fail(403, "This shop is not taking new customers right now.");
    const body = await readBody(request);
    const username = cleanUsername(body.username);
    const name = cleanText(body.displayName, 60);
    const phone = cleanPhone(body.phone);
    const pw = String(body.password || "").slice(0, 200);
    if (!username) return fail(400, "Username must be 3-30 letters, numbers, dots, dashes or underscores");
    if (name.length < 2) return fail(400, "Please enter your name");
    if (!SHOP_PHONE.test(phone)) return fail(400, "Enter a phone number we can reach you on");
    if (pw.length < 8) return fail(400, "Password must be at least 8 characters");
    const kIP = "su:" + ip;
    if (await shopLimited(env, [kIP], [SHOP.signupPerWindow], now)) return fail(429, "Too many sign-ups from this phone. Try again later.");
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_customers WHERE business_id=?").bind(b.id).first();
    if (n.n >= SHOP.maxCustomers) return fail(503, "This shop cannot take more customers right now.");
    const taken = await env.DB.prepare("SELECT 1 AS x FROM shop_customers WHERE business_id=? AND username=?").bind(b.id, username).first();
    if (taken) return fail(409, "That username is taken. Please choose another.");
    const id = crypto.randomUUID(), salt = randomHex(16), iter = targetIter(env);
    try {
      await env.DB.prepare("INSERT INTO shop_customers (id,business_id,username,display_name,phone,password_hash,password_salt,pw_iter,is_active,created_at,last_seen) VALUES (?,?,?,?,?,?,?,?,1,?,?)")
        .bind(id, b.id, username, name, phone, await hashPassword(pw, salt, iter), salt, iter, now, now).run();
    } catch (e) {
      if (/unique/i.test(String((e && e.message) || e))) return fail(409, "That username is taken. Please choose another.");
      throw e;
    }
    await bump(kIP);
    return json({ token: await newCustSession(env, id), customer: custOut({ id, username, display_name: name, phone }), shop: info }, 201);
  }

  if (path === "/api/c/login" && method === "POST") {
    const body = await readBody(request);
    const username = cleanUsername(body.username);
    const pw = String(body.password || "").slice(0, 200);
    const bad = () => fail(401, "Wrong username or password");
    if (!username || !pw) return bad();
    const kUI = "cui:" + b.id + ":" + username + ":" + ip, kU = "cu:" + b.id + ":" + username, kIP = "cip:" + ip;
    if (await shopLimited(env, [kUI, kU, kIP], [LOGIN_LIMITS.ui, LOGIN_LIMITS.u, LOGIN_LIMITS.ip], now))
      return fail(429, "Too many wrong attempts. Try again in 15 minutes.");
    const c = await env.DB.prepare("SELECT * FROM shop_customers WHERE business_id=? AND username=?").bind(b.id, username).first();
    if (!c) { await hashPassword(pw, "0000000000000000"); await bump(kUI, kIP); return bad(); }
    const iter = c.pw_iter || ITERATIONS;
    if (!same(await hashPassword(pw, c.password_salt, iter), c.password_hash)) { await bump(kUI, kU, kIP); return bad(); }
    if (!c.is_active) return fail(403, "This account is turned off. Please contact the shop.");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM login_attempts WHERE username IN (?,?)").bind(kUI, kU),
      env.DB.prepare("UPDATE shop_customers SET last_seen=? WHERE id=?").bind(now, c.id),
    ]);
    return json({ token: await newCustSession(env, c.id), customer: custOut(c), shop: info });
  }

  const me = await getCustomer(request, env, b.id);
  if (!me) return fail(401, "Please sign in");

  if (path === "/api/c/logout" && method === "POST") {
    await env.DB.prepare("DELETE FROM shop_sessions WHERE token_hash=?").bind(me.th).run();
    return json({ ok: true });
  }
  if (path === "/api/c/me" && method === "GET") {
    if (now - (me.last_seen || 0) > 3600000) await env.DB.prepare("UPDATE shop_customers SET last_seen=? WHERE id=?").bind(now, me.id).run();
    return json({ customer: custOut(me), shop: info });
  }
  if (path === "/api/c/delete" && method === "POST") {
    const body = await readBody(request);
    const k = "cd:" + me.id;
    if (await shopLimited(env, [k], [LOGIN_LIMITS.ui], now)) return fail(429, "Too many wrong attempts. Try again in 15 minutes.");
    if (!same(await hashPassword(String(body.password || "").slice(0, 200), me.password_salt, me.pw_iter || ITERATIONS), me.password_hash)) { await bump(k); return fail(400, "Your password is not right"); }
    const pend = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_orders WHERE customer_id=? AND status='paid_reported'").bind(me.id).first();
    if (pend.n) return fail(409, "The shop is still confirming a payment you reported. Please wait for it, then try again.");
    const open = (await env.DB.prepare("SELECT id FROM shop_orders WHERE customer_id=? AND status IN ('submitted','reviewing','approved','accepted')").bind(me.id).all()).results;
    const st2 = [];
    for (const x of open) {
      st2.push(env.DB.prepare("UPDATE shop_orders SET status='cancelled',expires_at=NULL,updated_at=? WHERE id=?").bind(now, x.id));
      st2.push(evStmt(env, x.id, "customer", "", "cancelled", "Account deleted"));
    }
    st2.push(env.DB.prepare("UPDATE shop_orders SET note='' WHERE customer_id=?").bind(me.id));
    st2.push(env.DB.prepare("UPDATE shop_customers SET username=?,display_name='Deleted customer',phone='',password_hash='',password_salt='',is_active=0 WHERE id=?").bind("deleted-" + me.id.slice(0, 8), me.id));
    st2.push(env.DB.prepare("DELETE FROM shop_sessions WHERE customer_id=?").bind(me.id));
    await env.DB.batch(st2);
    return json({ ok: true });
  }
  if (path === "/api/c/password" && method === "POST") {
    const body = await readBody(request);
    const cur = String(body.current || "").slice(0, 200), nx = String(body.next || "").slice(0, 200);
    if (nx.length < 8) return fail(400, "New password must be at least 8 characters");
    const k = "cp:" + me.id;
    if (await shopLimited(env, [k], [LOGIN_LIMITS.ui], now)) return fail(429, "Too many wrong attempts. Try again in 15 minutes.");
    if (!same(await hashPassword(cur, me.password_salt, me.pw_iter || ITERATIONS), me.password_hash)) { await bump(k); return fail(400, "Your current password is not right"); }
    const salt = randomHex(16), iter = targetIter(env);
    await env.DB.batch([
      env.DB.prepare("UPDATE shop_customers SET password_hash=?,password_salt=?,pw_iter=? WHERE id=?").bind(await hashPassword(nx, salt, iter), salt, iter, me.id),
      env.DB.prepare("DELETE FROM shop_sessions WHERE customer_id=? AND token_hash<>?").bind(me.id, me.th),
    ]);
    return json({ ok: true });
  }
  if (path === "/api/c/products" && method === "GET") {
    if (!open) return json({ open: false, products: [] });
    const rows = (await env.DB.prepare("SELECT id,name,price,category,hide_price FROM shop_products WHERE business_id=? AND active=1 ORDER BY (category=''), category COLLATE NOCASE, name COLLATE NOCASE LIMIT ?").bind(b.id, SHOP.maxProducts).all()).results;
    const gh = !!(st && st.hide_prices);
    return json({ open: true, products: rows.map((x) => { const hid = gh || !!x.hide_price; return { id: x.id, name: x.name, price: hid ? null : x.price, hidden: hid, category: x.category || "" }; }) });
  }

  // ---- customer orders ----
  await expireOrders(env, b.id, now);
  // While the shop is still checking an order, prices it chose to hide stay hidden from the customer.
  const maskOf = (o) => ["submitted", "reviewing"].includes(o.status) && orderLinesOut(o.asked).some((l) => l.hid);
  const maskLines = (lines, on) => lines.map((l) => ({ ...l, price: on && l.hid ? null : l.price }));
  const custOrder = async (o) => ({
    priceHidden: maskOf(o),
    id: o.id, no: o.no, invoice: invLabel(o.inv_no), status: o.status, total: maskOf(o) && orderLinesOut(o.items).some((l) => l.hid) ? null : o.total, note: o.note, staffNote: o.staff_note || "",
    createdAt: o.created_at, updatedAt: o.updated_at, expiresAt: ["approved", "accepted"].includes(o.status) ? o.expires_at : null, payNote: o.pay_note || "", paidAt: o.paid_at || null,
    items: maskLines(orderLinesOut(o.items), maskOf(o)), asked: maskLines(orderLinesOut(o.asked), maskOf(o)), adj: maskOf(o) ? [] : adjOut(o.adj), handler: firstName(await userName(env, o.assigned_to)),
    pay: ["accepted", "paid_reported", "paid"].includes(o.status) && st ? { bankName: st.bank_name, acctName: st.acct_name, acctNo: st.acct_no, amount: o.total, reference: invLabel(o.inv_no) } : null,
    business: b.name,
    events: (await orderEvents(env, o.id)).filter((e) => e.action !== "stock_out").map((e) => ({ ...e, who: firstName(e.who), detail: e.action === "assigned" ? firstName(e.detail) : (e.action === "edited" && maskOf(o) ? "" : e.detail) })),
  });
  if (path === "/api/c/orders" && method === "POST") {
    if (!open) return fail(403, "The shop is closed right now. Your cart is saved on your phone.");
    const body = await readBody(request);
    const idem = typeof body.key === "string" && /^[A-Za-z0-9_-]{8,60}$/.test(body.key) ? body.key : null;
    if (idem) {
      const ex = await env.DB.prepare("SELECT * FROM shop_orders WHERE customer_id=? AND idem=?").bind(me.id, idem).first();
      if (ex) return json({ order: await custOrder(ex), existing: true });
    }
    const want = new Map();
    if (!Array.isArray(body.items) || !body.items.length) return fail(400, "Your cart is empty");
    for (const it of body.items) {
      const id = String((it && it.id) || ""), q = Number(it && it.qty);
      if (!/^[0-9a-f-]{36}$/.test(id) || !Number.isInteger(q) || q < 1 || q > ORDER_LIMITS.qty) return fail(400, "Check the quantities in your cart (1 to " + ORDER_LIMITS.qty + " each)");
      want.set(id, (want.get(id) || 0) + q);
    }
    if (want.size > ORDER_LIMITS.lines) return fail(400, "A cart can hold up to " + ORDER_LIMITS.lines + " different items");
    for (const q of want.values()) if (q > ORDER_LIMITS.qty) return fail(400, "Check the quantities in your cart (1 to " + ORDER_LIMITS.qty + " each)");
    const ids = [...want.keys()];
    const rows = (await env.DB.prepare("SELECT id,name,price,hide_price FROM shop_products WHERE business_id=? AND active=1 AND id IN (" + ids.map(() => "?").join(",") + ")").bind(b.id, ...ids).all()).results;
    if (rows.length !== ids.length) return json({ error: "Some items in your cart are no longer available. Please check your cart.", code: "stale" }, 409);
    const gh = !!(st && st.hide_prices);
    const lines = rows.map((r) => ({ id: r.id, name: r.name, price: r.price, qty: want.get(r.id), ...(gh || r.hide_price ? { hid: 1 } : {}) })).sort((a, c) => a.name.toLowerCase() < c.name.toLowerCase() ? -1 : 1);
    const total = lines.reduce((t, l) => t + l.price * l.qty, 0);
    if (total > SHOP.maxPrice) return fail(400, "This order is too large. Please split it.");
    const openN = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_orders WHERE customer_id=? AND status IN (" + ORDER_OPEN.map(() => "?").join(",") + ")").bind(me.id, ...ORDER_OPEN).first();
    if (openN.n >= ORDER_LIMITS.open) return fail(409, "You already have " + ORDER_LIMITS.open + " orders in progress. Please wait for the shop to finish them first.");
    const hr = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_orders WHERE customer_id=? AND created_at>?").bind(me.id, now - 3600000).first();
    if (hr.n >= ORDER_LIMITS.perHour) return fail(429, "Too many orders in a short time. Please try again later.");
    const note = cleanText(body.note, ORDER_LIMITS.note);
    const id = crypto.randomUUID(), json_ = JSON.stringify(lines);
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        await env.DB.prepare("INSERT INTO shop_orders (id,business_id,no,customer_id,status,asked,items,total,note,assigned_to,idem,created_at,updated_at) SELECT ?,?,COALESCE(MAX(no),0)+1,?,'submitted',?,?,?,?,NULL,?,?,? FROM shop_orders WHERE business_id=?")
          .bind(id, b.id, me.id, json_, json_, total, note, idem, now, now, b.id).run();
        break;
      } catch (e) {
        const m = String((e && e.message) || e);
        if (/unique/i.test(m) && idem) {
          const ex = await env.DB.prepare("SELECT * FROM shop_orders WHERE customer_id=? AND idem=?").bind(me.id, idem).first();
          if (ex) return json({ order: await custOrder(ex), existing: true });
        }
        if (!/unique/i.test(m) || attempt === 3) throw e;
      }
    }
    await evStmt(env, id, "customer", firstName(me.display_name), "submitted", "").run();
    const o = await env.DB.prepare("SELECT * FROM shop_orders WHERE id=?").bind(id).first();
    return json({ order: await custOrder(o) }, 201);
  }
  if (path === "/api/c/orders" && method === "GET") {
    const rows = (await env.DB.prepare("SELECT id,no,inv_no,status,total,items,asked,created_at,updated_at FROM shop_orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 50").bind(me.id).all()).results;
    return json({ orders: rows.map((o) => ({ id: o.id, no: o.no, invoice: invLabel(o.inv_no), status: o.status, total: maskOf(o) && orderLinesOut(o.items).some((l) => l.hid) ? null : o.total, count: orderLinesOut(o.items).reduce((t, l) => t + l.qty, 0), createdAt: o.created_at, updatedAt: o.updated_at })) });
  }
  const com = path.match(/^\/api\/c\/orders\/([0-9a-f-]{36})(?:\/(cancel|accept|decline|change|paid))?$/);
  if (com) {
    const o = await env.DB.prepare("SELECT * FROM shop_orders WHERE id=? AND customer_id=?").bind(com[1], me.id).first();
    if (!o) return fail(404, "Order not found");
    const act = com[2], who = firstName(me.display_name);
    if (!act && method === "GET") return json({ order: await custOrder(o) });
    if (method !== "POST" || !act) return fail(405, "Not allowed");
    const body = await readBody(request);
    const done = async () => json({ order: await custOrder(await env.DB.prepare("SELECT * FROM shop_orders WHERE id=?").bind(o.id).first()) });
    const stale = () => fail(409, o.status === "expired" ? "This invoice has expired. Please ask the shop to reopen it." : "This order has changed. Please refresh and check it again.");
    const upd = async (sql, ...args) => { const r = await env.DB.prepare(sql).bind(...args).run(); return !!(r.meta && r.meta.changes); };
    if (act === "cancel") {
      if (!(await upd("UPDATE shop_orders SET status='cancelled',updated_at=? WHERE id=? AND customer_id=? AND status IN ('submitted','reviewing','approved','accepted')", now, o.id, me.id))) return fail(409, "This order can no longer be cancelled here. Please contact the shop.");
      await evStmt(env, o.id, "customer", who, "cancelled", "").run();
      return await done();
    }
    if (act === "accept") {
      if (!(await upd("UPDATE shop_orders SET status='accepted',expires_at=?,updated_at=? WHERE id=? AND customer_id=? AND status='approved' AND expires_at>?", now + ORDER_HOURS * 3600000, now, o.id, me.id, now))) return stale();
      await evStmt(env, o.id, "customer", who, "accepted", "").run();
      return await done();
    }
    if (act === "decline") {
      if (!(await upd("UPDATE shop_orders SET status='rejected',updated_at=? WHERE id=? AND customer_id=? AND status='approved' AND expires_at>?", now, o.id, me.id, now))) return stale();
      await evStmt(env, o.id, "customer", who, "rejected", cleanText(body.reason, 200)).run();
      return await done();
    }
    if (act === "change") {
      const note = cleanText(body.note, 200);
      if (note.length < 3) return fail(400, "Tell the shop what you would like changed");
      if (!(await upd("UPDATE shop_orders SET status='reviewing',expires_at=NULL,updated_at=? WHERE id=? AND customer_id=? AND status='approved' AND expires_at>?", now, o.id, me.id, now))) return stale();
      await evStmt(env, o.id, "customer", who, "change_asked", note).run();
      return await done();
    }
    if (act === "paid") {
      const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_order_events WHERE order_id=? AND action='paid_reported'").bind(o.id).first();
      if (n.n >= 3) return fail(429, "You have already reported payment several times. Please contact the shop.");
      if (!(await upd("UPDATE shop_orders SET status='paid_reported',pay_note=?,updated_at=? WHERE id=? AND customer_id=? AND status='accepted' AND expires_at>?", cleanText(body.name, 60), now, o.id, me.id, now))) return stale();
      await evStmt(env, o.id, "customer", who, "paid_reported", cleanText(body.name, 60)).run();
      return await done();
    }
  }
  return fail(404, "Not found");
}

async function handle(request, env, origin) {
    const path = new URL(request.url).pathname;
    const method = request.method;
    try {
      await ensureSchema(env);
      if (path === "/api/status" && method === "GET") {
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
        return json({ ok: true, hasAdmin: c.n > 0 });
      }

      if (path === "/api/setup" && method === "POST") {
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
        if (c.n > 0) return fail(403, "Setup is already done");
        const b = await readBody(request);
        const username = cleanUsername(b.username);
        const name = String(b.displayName || "").trim().slice(0, 60);
        const pw = String(b.password || "");
        if (!username) return fail(400, "Username must be 3-30 letters, numbers, dots, dashes or underscores");
        if (!name) return fail(400, "Your name is required");
        if (pw.length < 8) return fail(400, "Password must be at least 8 characters");
        const id = crypto.randomUUID();
        const salt = randomHex(16);
        const now0 = Date.now();
        const bizName = cleanBizName(b.businessName) || name + "'s business";
        const idn = await newIdentity(env);
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO users (id,username,display_name,password_hash,password_salt,owner_id,is_super_admin,is_platform,must_change_password,is_active,created_at) VALUES (?,?,?,?,?,NULL,1,1,0,1,?)"
          ).bind(id, username, name, await hashPassword(pw, salt), salt, now0),
          env.DB.prepare("INSERT INTO businesses (id,name,status,created_at,code,secret) VALUES (?,?,'active',?,?,?)").bind(id, bizName, now0, idn.code, idn.secret),
        ]);
        const user = { id, username, display_name: name, is_super_admin: 1, is_platform: 1, must_change_password: 0, biz_name: bizName, biz_code: idn.code };
        return json({ token: await newSession(env, id), user: publicUser(user), stores: [], licence: licenceOf(user, Date.now(), 0) });
      }

      if (path === "/api/login" && method === "POST") {
        const b = await readBody(request);
        const username = cleanUsername(b.username);
        const pw = String(b.password || "").slice(0, 200);
        const bad = () => fail(401, "Wrong username or password");
        if (!username || !pw) return bad();
        const now = Date.now();
        const ip = (request.headers.get("CF-Connecting-IP") || "unknown").slice(0, 60);
        const kUI = "ui:" + username + ":" + ip, kU = "u:" + username, kIP = "ip:" + ip;
        const att = await env.DB.prepare(
          "SELECT username,fail_count,window_start FROM login_attempts WHERE username IN (?,?,?)"
        ).bind(kUI, kU, kIP).all();
        for (const a of att.results) {
          const lim = a.username === kUI ? LOGIN_LIMITS.ui : a.username === kU ? LOGIN_LIMITS.u : LOGIN_LIMITS.ip;
          if (now - a.window_start < LOCK_WINDOW && a.fail_count >= lim)
            return fail(429, "Too many wrong attempts. Try again in 15 minutes.");
        }
        const row = await env.DB.prepare(
          "SELECT u.*,b.name AS biz_name,b.code AS biz_code,b.origins AS biz_origins,b.trial_started_at,b.paid_until,b.store_limit,COALESCE(b.status,'active') AS biz_status FROM users u" + BIZ_JOIN + " WHERE u.username=?"
        ).bind(username).first();
        if (!row) {
          await hashPassword(pw, "0000000000000000");
          await env.DB.batch([env.DB.prepare(BUMP_SQL).bind(kUI, now, LOCK_WINDOW), env.DB.prepare(BUMP_SQL).bind(kIP, now, LOCK_WINDOW)]);
          await purgeOld(env, now);
          return bad();
        }
        const iter = row.pw_iter || ITERATIONS;
        const ok = same(await hashPassword(pw, row.password_salt, iter), row.password_hash);
        if (!ok) {
          await env.DB.batch([
            env.DB.prepare(BUMP_SQL).bind(kUI, now, LOCK_WINDOW),
            env.DB.prepare(BUMP_SQL).bind(kU, now, LOCK_WINDOW),
            env.DB.prepare(BUMP_SQL).bind(kIP, now, LOCK_WINDOW),
          ]);
          await purgeOld(env, now);
          return bad();
        }
        if (!row.is_active) return fail(403, "This account is turned off. Contact your admin.");
        if (row.biz_status !== "active" && !row.is_platform)
          return json({ error: "This business account is suspended. Please contact the app provider.", code: "suspended" }, 403);
        if (!originOk(row, origin, request)) return WRONG_APP();
        await env.DB.batch([
          env.DB.prepare("DELETE FROM login_attempts WHERE username IN (?,?)").bind(kUI, kU),
        ]);
        await purgeOld(env, now);
        // upgrade an older password hash the first time this person signs in (no reset needed)
        const want = targetIter(env);
        if (iter < want) {
          const salt2 = randomHex(16);
          await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,pw_iter=? WHERE id=? AND password_hash=?")
            .bind(await hashPassword(pw, salt2, want), salt2, want, row.id, row.password_hash).run();
        }
        if (!row.is_platform && !row.trial_started_at) {
          row.trial_started_at = Date.now();
          await env.DB.prepare("UPDATE businesses SET trial_started_at=? WHERE id=? AND trial_started_at IS NULL")
            .bind(row.trial_started_at, row.owner_id || row.id).run();
        }
        return json({
          token: await newSession(env, row.id),
          user: publicUser(row),
          stores: await storesFor(row, env),
          licence: await licenceFor(env, row),
        });
      }

      if (path.startsWith("/api/c/")) return await shopCustomerApi(request, env, origin, path, method);

      const user = await getUser(request, env);
      if (!user) return fail(401, "Please sign in");

      if (path === "/api/logout" && method === "POST") {
        await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(user.th).run();
        return json({ ok: true });
      }

      if (user.biz_status !== "active" && !user.is_platform)
        return json({ error: "This business account is suspended. Please contact the app provider.", code: "suspended" }, 403);

      if (!originOk(user, origin, request)) return WRONG_APP();

      if (!user.is_platform && method !== "GET" && path !== "/api/password" && !path.startsWith("/api/subscription/") &&
          licenceOf(user, Date.now(), 0).state === "readonly")
        return json({ error: "Your subscription has ended. The app is view-only until it is renewed.", code: "readonly" }, 403);

      if (path.startsWith("/api/platform/")) {
        if (!user.is_platform) return fail(403, "Not allowed");
        const BIZ_LIST =
          "SELECT b.id,b.name,b.status,b.created_at,b.note,u.username AS owner_username,u.display_name AS owner_name,u.is_active AS owner_active,u.must_change_password AS owner_must_change,u.is_platform AS is_platform,b.trial_started_at,b.paid_until,b.store_limit,b.code,b.origins,b.secret,(SELECT COUNT(*) FROM stores s WHERE s.owner_id=b.id AND s.is_archived=0) AS stores,(SELECT COUNT(*) FROM users k WHERE k.owner_id=b.id) AS keepers FROM businesses b JOIN users u ON u.id=b.id";
        const bizOut = (r) => ({
          id: r.id,
          name: r.name,
          status: r.status,
          note: r.note || "",
          createdAt: r.created_at,
          ownerUsername: r.owner_username,
          ownerName: r.owner_name,
          ownerActive: !!r.owner_active,
          ownerMustChange: !!r.owner_must_change,
          isPlatform: !!r.is_platform,
          stores: r.stores,
          keepers: r.keepers,
          licence: licenceOf(r, Date.now(), r.stores),
          code: r.code || "",
          origins: r.origins ? r.origins.split(",") : [],
          secretFingerprint: r.fp || "",
        });
        const withFp = async (rows) => { for (const r of rows) r.fp = r.secret ? (await sha256(r.secret)).slice(0, 8) : ""; return rows; };

        if (path === "/api/platform/businesses" && method === "GET") {
          const r = await env.DB.prepare(BIZ_LIST + " ORDER BY b.created_at LIMIT 500").all();
          return json({ businesses: (await withFp(r.results)).map(bizOut) });
        }

        if (path === "/api/platform/businesses" && method === "POST") {
          const b = await readBody(request);
          const name = cleanBizName(b.businessName);
          const username = cleanUsername(b.ownerUsername);
          const ownerName = String(b.ownerName || "").trim().slice(0, 60);
          const pw = String(b.password || "");
          if (!name) return fail(400, "Business name is required");
          if (!username) return fail(400, "Username must be 3-30 letters, numbers, dots, dashes or underscores");
          if (!ownerName) return fail(400, "The owner's name is required");
          if (pw.length < 8) return fail(400, "Password must be at least 8 characters");
          const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM businesses").first();
          if (n.n >= MAX_BUSINESSES) return fail(400, "You have reached the limit of " + MAX_BUSINESSES + " businesses");
          const taken = await env.DB.prepare("SELECT id FROM users WHERE username=?").bind(username).first();
          if (taken) return fail(409, "That username is already taken");
          let origins = [];
          if (b.origins !== undefined) {
            origins = cleanOrigins(b.origins);
            if (!origins) return fail(400, "Addresses must be https web addresses like https://myshop.pages.dev (up to 5)");
          }
          const idn = await newIdentity(env);
          const id = crypto.randomUUID();
          const salt = randomHex(16);
          const now = Date.now();
          await env.DB.batch([
            env.DB.prepare(
              "INSERT INTO users (id,username,display_name,password_hash,password_salt,owner_id,is_super_admin,is_platform,must_change_password,is_active,created_at) VALUES (?,?,?,?,?,NULL,1,0,1,1,?)"
            ).bind(id, username, ownerName, await hashPassword(pw, salt), salt, now),
            env.DB.prepare("INSERT INTO businesses (id,name,status,created_at,note,code,secret,origins) VALUES (?,?,'active',?,?,?,?,?)")
              .bind(id, name, now, String(b.note || "").trim().slice(0, 300), idn.code, idn.secret, origins.join(",") || null),
            audit(env, null, user.id, "business_created", name + " (" + username + ")"),
          ]);
          const row = (await withFp([await env.DB.prepare(BIZ_LIST + " WHERE b.id=?").bind(id).first()]))[0];
          return json({ business: bizOut(row) }, 201);
        }

        if (path === "/api/platform/usage" && method === "GET") {
          const q = async (sql) => (await env.DB.prepare(sql).first()) || {};
          const [biz, us, st, en, au, se] = await Promise.all([
            q("SELECT COUNT(*) AS n FROM businesses"), q("SELECT COUNT(*) AS n FROM users"), q("SELECT COUNT(*) AS n FROM stores"),
            q("SELECT COUNT(*) AS n, COALESCE(SUM(length(items)+length(COALESCE(ref,''))+120),0) AS bytes FROM entries"),
            q("SELECT COUNT(*) AS n, COALESCE(SUM(length(COALESCE(detail,''))+80),0) AS bytes FROM audit_log"),
            q("SELECT COUNT(*) AS n FROM sessions"),
          ]);
          const [sp, sc, so] = await Promise.all([q("SELECT COUNT(*) AS n FROM shop_products"), q("SELECT COUNT(*) AS n FROM shop_customers"), q("SELECT COUNT(*) AS n, COALESCE(SUM(length(items)+length(asked)+length(note)+200),0) AS bytes FROM shop_orders")]);
          const since = Date.now() - 86400000;
          const day = await q("SELECT (SELECT COUNT(*) FROM entries WHERE created_at>=" + since + ") AS entries, (SELECT COUNT(*) FROM audit_log WHERE created_at>=" + since + ") AS audit");
          return json({
            businesses: biz.n, users: us.n, stores: st.n, entries: en.n, auditRows: au.n, sessions: se.n,
            approxBytes: (en.bytes || 0) + (au.bytes || 0) + us.n * 300 + st.n * 150 + (so.bytes || 0) + sc.n * 250 + sp.n * 150,
            shop: { products: sp.n, customers: sc.n, orders: so.n },
            last24h: { entries: day.entries || 0, auditRows: day.audit || 0 },
            limits: { dbBytes: 500 * 1024 * 1024, requestsPerDay: 100000, rowsWrittenPerDay: 100000, rowsReadPerDay: 5000000 },
          });
        }

        if (path === "/api/platform/backup" && method === "GET") {
          // Safe copy of the data: never includes password hashes, business secrets or prepaid-code signatures.
          const COLS = {
            businesses: "id,name,status,created_at,note,trial_started_at,paid_until,store_limit,code,origins",
            users: "id,username,display_name,owner_id,is_super_admin,is_platform,must_change_password,is_active,created_at",
            stores: "id,owner_id,name,address,is_archived,created_at",
            memberships: "user_id,store_id,role",
            entries: "id,store_id,type,entry_date,ref,items,created_by,created_at,updated_at,deleted_at,edited",
            audit_log: "id,store_id,user_id,action,entry_id,detail,created_at",
            licence_codes: "code,business_id,months,stores,amount,created_at,expires_at,voided_at,redeemed_at,redeemed_by",
            pay_reports: "id,business_id,user_id,months,stores,amount,note,status,reply,created_at,updated_at,dismissed_at",
            shop_products: "id,business_id,name,price,category,active,hide_price,created_at,updated_at",
            shop_settings: "business_id,enabled,bank_name,acct_name,acct_no,welcome,price_edit,stock_store,hide_prices,updated_at",
            shop_customers: "id,business_id,username,display_name,phone,is_active,created_at,last_seen",
            shop_orders: "id,business_id,no,customer_id,status,asked,items,adj,total,note,staff_note,inv_no,assigned_to,expires_at,pay_note,paid_at,stock_entry,created_at,updated_at",
            shop_order_events: "id,order_id,at,actor,who,action,detail",
          };
          const url = new URL(request.url);
          const t = url.searchParams.get("table") || "";
          if (!COLS[t]) return fail(400, "Unknown table");
          const off = Math.max(0, parseInt(url.searchParams.get("offset"), 10) || 0);
          const r = await env.DB.prepare("SELECT " + COLS[t] + " FROM " + t + " ORDER BY rowid LIMIT 1000 OFFSET ?").bind(off).all();
          if (t === "businesses" && off === 0) await audit(env, null, user.id, "backup_downloaded", "").run();
          return json({ table: t, offset: off, rows: r.results, next: r.results.length === 1000 ? off + 1000 : null, tables: Object.keys(COLS) });
        }

        if (path === "/api/platform/settings") {
          if (method === "GET") {
            const row = await env.DB.prepare("SELECT v FROM app_settings WHERE k='pay_info'").first();
            return json({ payInfo: row ? row.v : "" });
          }
          if (method === "PUT") {
            const b = await readBody(request);
            const v = String(b.payInfo || "").trim().slice(0, 600);
            await env.DB.batch([
              env.DB.prepare("INSERT INTO app_settings (k,v) VALUES ('pay_info',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(v),
              audit(env, null, user.id, "pay_info_changed", ""),
            ]);
            return json({ payInfo: v });
          }
        }

        if (path === "/api/platform/payments" && method === "GET") {
          const st = new URL(request.url).searchParams.get("status");
          const where = PAY_STATUS.includes(st) ? " WHERE p.status=?" : "";
          const q = env.DB.prepare(PAY_SELECT + where + " ORDER BY (p.status='pending') DESC, p.created_at DESC LIMIT 100");
          const r = await (where ? q.bind(st) : q).all();
          return json({ requests: r.results.map((x) => payOut(x, true)) });
        }
        const prm = path.match(/^\/api\/platform\/payments\/([0-9a-f-]{36})\/reply$/);
        if (prm && method === "POST") {
          const b = await readBody(request);
          const cur = await env.DB.prepare(PAY_SELECT + " WHERE p.id=?").bind(prm[1]).first();
          if (!cur) return fail(404, "Payment report not found");
          if (cur.status !== "pending") return fail(400, "This report has already been answered");
          const now = Date.now();
          const msg = String(b.message || "").replace(/[<>]/g, "").trim().slice(0, 300);
          if (b.action === "send") {
            const code = normaliseCode(b.code);
            const lc = code ? await env.DB.prepare("SELECT code,business_id,voided_at,redeemed_at,expires_at FROM licence_codes WHERE code=?").bind(code).first() : null;
            if (!lc || lc.business_id !== cur.business_id || lc.voided_at || lc.redeemed_at || now > lc.expires_at)
              return fail(400, "That code is not valid for this business");
            await env.DB.batch([
              env.DB.prepare("UPDATE pay_reports SET status='sent',code=?,reply=?,updated_at=? WHERE id=? AND status='pending'").bind(code, msg || "Payment confirmed. Thank you.", now, cur.id),
              audit(env, null, user.id, "payment_code_sent", cur.biz_name + ": " + cur.months + " months, " + cur.stores + " stores"),
            ]);
          } else if (b.action === "decline") {
            await env.DB.batch([
              env.DB.prepare("UPDATE pay_reports SET status='declined',reply=?,updated_at=? WHERE id=? AND status='pending'").bind(msg || "We could not find your payment yet. Please check and report again.", now, cur.id),
              audit(env, null, user.id, "payment_declined", cur.biz_name),
            ]);
          } else return fail(400, "Unknown action");
          const row = await env.DB.prepare(PAY_SELECT + " WHERE p.id=?").bind(cur.id).first();
          return json({ request: payOut(row, true) });
        }

        const cm = path.match(/^\/api\/platform\/businesses\/([0-9a-f-]{36})\/codes(?:\/(TB-[A-Z0-9-]{14}))?(\/void)?$/);
        if (cm) {
          const bid = cm[1];
          const biz = await env.DB.prepare("SELECT id,name,secret FROM businesses WHERE id=?").bind(bid).first();
          if (!biz) return fail(404, "Business not found");
          const now = Date.now();
          if (!cm[2] && method === "GET") {
            const r = await env.DB.prepare("SELECT * FROM licence_codes WHERE business_id=? ORDER BY created_at DESC LIMIT 30").bind(bid).all();
            return json({ codes: r.results.map((x) => codeOut(x, now)) });
          }
          if (!cm[2] && method === "POST") {
            const b = await readBody(request);
            const months = Number(b.months);
            const stores = Number(b.stores);
            if (![1, 6, 12].includes(months)) return fail(400, "Months must be 1, 6 or 12");
            if (!Number.isInteger(stores) || stores < 1 || stores > 1000) return fail(400, "Stores must be a whole number from 1 to 1000");
            const code = newLicenceCode();
            const sig = await hmacHex(biz.secret, [code, bid, months, stores].join("|"));
            const amount = priceFor(stores, months);
            await env.DB.batch([
              env.DB.prepare("INSERT INTO licence_codes (code,business_id,months,stores,amount,sig,created_at,created_by,expires_at) VALUES (?,?,?,?,?,?,?,?,?)")
                .bind(code, bid, months, stores, amount, sig, now, user.id, now + CODE_LIFE),
              audit(env, null, user.id, "licence_code_created", biz.name + ": " + months + " months, " + stores + " stores"),
            ]);
            const row = await env.DB.prepare("SELECT * FROM licence_codes WHERE code=?").bind(code).first();
            return json({ code: codeOut(row, now) }, 201);
          }
          if (cm[2] && cm[3] && method === "POST") {
            const r = await env.DB.prepare("UPDATE licence_codes SET voided_at=? WHERE code=? AND business_id=? AND redeemed_at IS NULL AND voided_at IS NULL")
              .bind(now, cm[2], bid).run();
            if (!r.meta || r.meta.changes !== 1) return fail(400, "That code can't be cancelled (already used or cancelled)");
            await audit(env, null, user.id, "licence_code_voided", biz.name).run();
            return json({ ok: true });
          }
          return fail(405, "Not allowed");
        }

        const sm = path.match(/^\/api\/platform\/businesses\/([0-9a-f-]{36})\/secret$/);
        if (sm && (method === "GET" || method === "POST")) {
          const cur = await env.DB.prepare("SELECT id,name,code,secret FROM businesses WHERE id=?").bind(sm[1]).first();
          if (!cur) return fail(404, "Business not found");
          if (method === "GET") {
            await audit(env, null, user.id, "business_secret_viewed", cur.name).run();
            return json({ code: cur.code, secret: cur.secret });
          }
          const fresh = randomHex(32);
          await env.DB.batch([
            env.DB.prepare("UPDATE businesses SET secret=? WHERE id=?").bind(fresh, sm[1]),
            audit(env, null, user.id, "business_secret_rotated", cur.name),
          ]);
          return json({ code: cur.code, secret: fresh });
        }

        const pm = path.match(/^\/api\/platform\/businesses\/([0-9a-f-]{36})$/);
        if (pm && method === "PUT") {
          const bid = pm[1];
          const cur = await env.DB.prepare(BIZ_LIST + " WHERE b.id=?").bind(bid).first();
          if (!cur) return fail(404, "Business not found");
          const b = await readBody(request);
          const stmts = [];
          let kill = false;
          if (typeof b.name === "string") {
            const nm = cleanBizName(b.name);
            if (!nm) return fail(400, "Business name is required");
            stmts.push(env.DB.prepare("UPDATE businesses SET name=? WHERE id=?").bind(nm, bid));
            stmts.push(audit(env, null, user.id, "business_renamed", cur.name + " -> " + nm));
          }
          if (typeof b.note === "string")
            stmts.push(env.DB.prepare("UPDATE businesses SET note=? WHERE id=?").bind(b.note.trim().slice(0, 300), bid));
          if (b.status === "active" || b.status === "suspended") {
            if (b.status === "suspended" && cur.is_platform) return fail(400, "You cannot suspend your own business");
            if (b.status !== cur.status) {
              stmts.push(env.DB.prepare("UPDATE businesses SET status=? WHERE id=?").bind(b.status, bid));
              stmts.push(audit(env, null, user.id, b.status === "suspended" ? "business_suspended" : "business_reactivated", cur.name));
              if (b.status === "suspended") kill = true;
            }
          } else if (b.status !== undefined) return fail(400, "Status must be active or suspended");
          if (b.origins !== undefined) {
            const og = cleanOrigins(b.origins);
            if (!og) return fail(400, "Addresses must be https web addresses like https://myshop.pages.dev (up to 5)");
            stmts.push(env.DB.prepare("UPDATE businesses SET origins=? WHERE id=?").bind(og.join(",") || null, bid));
            stmts.push(audit(env, null, user.id, "business_origins_changed", cur.name + ": " + (og.join(", ") || "default")));
            OC = null;
          }
          if (b.storeLimit !== undefined) {
            const sl = Number(b.storeLimit);
            if (!Number.isInteger(sl) || sl < 1 || sl > 1000) return fail(400, "Store limit must be a whole number from 1 to 1000");
            stmts.push(env.DB.prepare("UPDATE businesses SET store_limit=? WHERE id=?").bind(sl, bid));
            stmts.push(audit(env, null, user.id, "business_store_limit", cur.name + ": " + sl));
          }
          if (b.grantMonths !== undefined) {
            const gm = Number(b.grantMonths);
            if (!Number.isInteger(gm) || gm < 1 || gm > 36) return fail(400, "Months must be a whole number from 1 to 36");
            const li = licenceOf(cur, Date.now(), 0);
            const base = Math.max(Date.now(), Number(cur.paid_until) || 0, li.trialEndsAt || 0);
            const until = addMonthsFrom(base, gm);
            stmts.push(env.DB.prepare("UPDATE businesses SET paid_until=? WHERE id=?").bind(until, bid));
            stmts.push(audit(env, null, user.id, "business_licence_granted", cur.name + ": +" + gm + " months"));
          }
          if (typeof b.ownerPassword === "string" && b.ownerPassword) {
            if (b.ownerPassword.length < 8) return fail(400, "Password must be at least 8 characters");
            const salt = randomHex(16);
            stmts.push(
              env.DB.prepare("UPDATE users SET password_hash=?,pw_iter=30000,password_salt=?,must_change_password=1 WHERE id=?")
                .bind(await hashPassword(b.ownerPassword, salt), salt, bid)
            );
            stmts.push(env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(bid));
            stmts.push(audit(env, null, user.id, "business_owner_password_reset", cur.name));
          }
          if (kill)
            stmts.push(env.DB.prepare("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE id=?1 OR owner_id=?1)").bind(bid));
          if (stmts.length) await env.DB.batch(stmts);
          const row = (await withFp([await env.DB.prepare(BIZ_LIST + " WHERE b.id=?").bind(bid).first()]))[0];
          return json({ business: bizOut(row) });
        }
        return fail(404, "Not found");
      }

      if (path === "/api/subscription" && method === "GET") {
        const row = await env.DB.prepare("SELECT v FROM app_settings WHERE k='pay_info'").first();
        const lic = await licenceFor(env, user);
        return json({
          licence: lic,
          prices: lic.storeLimit ? { m1: priceFor(lic.storeLimit, 1), m6: priceFor(lic.storeLimit, 6), m12: priceFor(lic.storeLimit, 12) } : null,
          table: priceTable(),
          payInfo: row ? row.v : "",
        });
      }

      if (path === "/api/subscription/redeem" && method === "POST") {
        if (user.is_platform) return fail(400, "Your own business has no subscription");
        if (!user.is_super_admin) return fail(403, "Only the owner can enter a subscription code");
        const bid = user.owner_id || user.id;
        const key = "code:" + bid;
        const now = Date.now();
        const att = await env.DB.prepare("SELECT fail_count, window_start FROM login_attempts WHERE username=?").bind(key).first();
        if (att && now - att.window_start < LOCK_WINDOW && att.fail_count >= 5)
          return fail(429, "Too many wrong codes. Try again in 15 minutes.");
        const b = await readBody(request);
        const code = normaliseCode(b.code);
        const bad = async () => {
          await env.DB.prepare(
            "INSERT INTO login_attempts (username,fail_count,window_start) VALUES (?1,1,?2) ON CONFLICT(username) DO UPDATE SET fail_count = CASE WHEN ?2 - window_start >= ?3 THEN 1 ELSE fail_count + 1 END, window_start = CASE WHEN ?2 - window_start >= ?3 THEN ?2 ELSE window_start END"
          ).bind(key, now, LOCK_WINDOW).run();
          return fail(400, BAD_CODE);
        };
        if (!code) return bad();
        const row = await env.DB.prepare("SELECT * FROM licence_codes WHERE code=?").bind(code).first();
        const biz = await env.DB.prepare("SELECT secret FROM businesses WHERE id=?").bind(bid).first();
        if (!row || row.business_id !== bid || !biz || !biz.secret) return bad();
        const want = await hmacHex(biz.secret, [row.code, row.business_id, row.months, row.stores].join("|"));
        if (!same(want, row.sig) || row.voided_at) return bad();
        if (row.redeemed_at) return fail(400, "This code has already been used.");
        if (now > row.expires_at) return fail(400, "This code has expired. Please ask for a new one.");
        const li = licenceOf(user, now, 0);
        const limit = user.store_limit || DEFAULT_STORE_LIMIT;
        if (row.stores < limit && (li.state === "trial" || li.state === "active"))
          return json({ error: "This code is for " + row.stores + " stores but your plan covers " + limit + ". Ask for a code for " + limit + " stores.", code: "store_mismatch" }, 400);
        const claim = await env.DB.prepare(
          "UPDATE licence_codes SET redeemed_at=?, redeemed_by=? WHERE code=? AND redeemed_at IS NULL AND voided_at IS NULL"
        ).bind(now, user.id, code).run();
        if (!claim.meta || claim.meta.changes !== 1) return fail(400, "This code has already been used.");
        const base = Math.max(now, Number(user.paid_until) || 0, li.trialEndsAt || 0);
        const until = addMonthsFrom(base, row.months);
        await env.DB.batch([
          env.DB.prepare("UPDATE businesses SET paid_until=?, store_limit=? WHERE id=?").bind(until, row.stores, bid),
          audit(env, null, user.id, "subscription_redeemed", row.months + " months, " + row.stores + " stores"),
          env.DB.prepare("DELETE FROM login_attempts WHERE username=?").bind(key),
        ]);
        const fresh = { ...user, paid_until: until, store_limit: row.stores };
        return json({ licence: await licenceFor(env, fresh), added: { months: row.months, stores: row.stores } });
      }

      if (path === "/api/subscription/payment" && method === "GET") {
        if (user.is_platform || !user.is_super_admin) return json({ request: null });
        const r = await env.DB.prepare(PAY_SELECT + " WHERE p.business_id=? AND p.dismissed_at IS NULL ORDER BY p.created_at DESC LIMIT 1").bind(user.owner_id || user.id).first();
        return json({ request: r ? payOut(r) : null });
      }

      if (path === "/api/subscription/paid" && method === "POST") {
        if (user.is_platform) return fail(400, "Your own business has no subscription");
        if (!user.is_super_admin) return fail(403, "Only the owner can report a payment");
        const bid = user.owner_id || user.id;
        const b = await readBody(request);
        const months = Number(b.months), stores = Number(b.stores);
        if (![1, 6, 12].includes(months)) return fail(400, "Choose 1, 6 or 12 months");
        if (!Number.isInteger(stores) || stores < 3 || stores > 60 || stores % 3 !== 0) return fail(400, "Choose the number of stores");
        const now = Date.now();
        const li = licenceOf(user, now, 0), limit = user.store_limit || DEFAULT_STORE_LIMIT;
        if (stores < limit && (li.state === "trial" || li.state === "active"))
          return fail(400, "Your plan already covers " + limit + " stores. Choose " + limit + " or more.");
        const open = await env.DB.prepare(PAY_SELECT + " WHERE p.business_id=? AND p.dismissed_at IS NULL AND p.status IN ('pending','sent') ORDER BY p.created_at DESC LIMIT 1").bind(bid).first();
        if (open && open.status === "pending") return json({ request: payOut(open) });
        if (open) return fail(409, "Your code is ready. Tap Add to my subscription first.");
        const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM pay_reports WHERE business_id=? AND created_at>?").bind(bid, now - DAY).first();
        if (cnt.n >= 5) return fail(429, "Too many reports today. Please contact the app provider.");
        const id = crypto.randomUUID();
        const note = String(b.note || "").replace(/[<>\u0000-\u001f]/g, "").trim().slice(0, 120);
        await env.DB.batch([
          env.DB.prepare("INSERT INTO pay_reports (id,business_id,user_id,months,stores,amount,note,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'pending',?,?)")
            .bind(id, bid, user.id, months, stores, priceFor(stores, months), note, now, now),
          audit(env, null, user.id, "payment_reported", months + " months, " + stores + " stores"),
        ]);
        const row = await env.DB.prepare(PAY_SELECT + " WHERE p.id=?").bind(id).first();
        return json({ request: payOut(row) }, 201);
      }

      const dm = path.match(/^\/api\/subscription\/payment\/([0-9a-f-]{36})\/dismiss$/);
      if (dm && method === "POST") {
        if (user.is_platform || !user.is_super_admin) return fail(403, "Not allowed");
        const r = await env.DB.prepare("UPDATE pay_reports SET dismissed_at=?, status=CASE WHEN status='sent' THEN 'closed' ELSE status END WHERE id=? AND business_id=? AND status<>'pending' AND dismissed_at IS NULL")
          .bind(Date.now(), dm[1], user.owner_id || user.id).run();
        return json({ ok: !!(r.meta && r.meta.changes) });
      }

      if (path === "/api/me" && method === "GET") {
        return json({ user: publicUser(user), stores: await storesFor(user, env), licence: await licenceFor(env, user) });
      }

      if (path === "/api/stores" && method === "GET") {
        return json({ stores: await storesFor(user, env) });
      }

      if (path === "/api/stores" && method === "POST") {
        if (!user.is_super_admin) return fail(403, "Only the Super Admin can create stores");
        const b = await readBody(request);
        const name = String(b.name || "").trim().slice(0, 60);
        const address = String(b.address || "").trim().slice(0, 120);
        if (!name) return fail(400, "Store name is required");
        if (!user.is_platform) {
          const lic = await licenceFor(env, user);
          if (lic.storesUsed >= lic.storeLimit)
            return json({ error: "Your plan allows " + lic.storeLimit + " stores. Ask the app provider to add more stores.", code: "store_limit" }, 403);
        }
        const id = crypto.randomUUID();
        const now = Date.now();
        await env.DB.prepare(
          "INSERT INTO stores (id,owner_id,name,address,is_archived,created_at) VALUES (?,?,?,?,0,?)"
        ).bind(id, user.id, name, address, now).run();
        await env.DB.prepare(
          "INSERT INTO audit_log (store_id,user_id,action,detail,created_at) VALUES (?,?,?,?,?)"
        ).bind(id, user.id, "store_created", name, now).run();
        return json({ store: { id, name, address, role: "owner" } }, 201);
      }


      if (path === "/api/password" && method === "POST") {
        const b = await readBody(request);
        const cur = String(b.currentPassword || "");
        const nw = String(b.newPassword || "");
        if (nw.length < 8) return fail(400, "New password must be at least 8 characters");
        if (nw === cur) return fail(400, "Choose a password different from the current one");
        const row = await env.DB.prepare(
          "SELECT password_hash,password_salt,pw_iter FROM users WHERE id=?"
        ).bind(user.id).first();
        if (!same(await hashPassword(cur, row.password_salt, row.pw_iter || ITERATIONS), row.password_hash))
          return fail(400, "Your current password is wrong");
        const salt = randomHex(16);
        const hash = await hashPassword(nw, salt);
        await env.DB.batch([
          env.DB.prepare(
            "UPDATE users SET password_hash=?,pw_iter=30000,password_salt=?,must_change_password=0 WHERE id=?"
          ).bind(hash, salt, user.id),
          env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(user.id, user.th),
          audit(env, null, user.id, "password_changed", user.username),
        ]);
        return json({ ok: true });
      }

      if (path.startsWith("/api/orders")) {
        if (!user.is_super_admin && !user.is_desk) return fail(403, "Only the owner and the order desk can see orders");
        const bid = user.owner_id || user.id;
        const now = Date.now();
        const owner = !!user.is_super_admin;
        await expireOrders(env, bid, now);
        const doneS = ["cancelled", "declined", "rejected", "expired", "paid"];
        const SEL = "SELECT o.*,c.display_name AS cname,c.phone AS cphone,c.username AS cuser,u.display_name AS hname FROM shop_orders o JOIN shop_customers c ON c.id=o.customer_id LEFT JOIN users u ON u.id=o.assigned_to";
        const shopSt = async () => await env.DB.prepare("SELECT * FROM shop_settings WHERE business_id=?").bind(bid).first();
        const row = (o) => ({ id: o.id, no: o.no, invoice: invLabel(o.inv_no), status: o.status, total: o.total, count: orderLinesOut(o.items).reduce((t, l) => t + l.qty, 0), customer: o.cname, phone: o.cphone, handlerId: o.assigned_to || null, handler: o.hname || "", mine: o.assigned_to === user.id, expiresAt: ["approved", "accepted"].includes(o.status) ? o.expires_at : null, createdAt: o.created_at, updatedAt: o.updated_at });

        if (path === "/api/orders/count" && method === "GET") {
          const r = await env.DB.prepare("SELECT SUM(status='submitted') AS n, SUM(status='reviewing' AND assigned_to=?) AS m, SUM(status='paid_reported') AS p FROM shop_orders WHERE business_id=?").bind(user.id, bid).first();
          return json({ fresh: r.n || 0, mine: r.m || 0, pay: r.p || 0 });
        }
        if (path === "/api/orders/desk" && method === "GET") {
          if (!owner) return fail(403, "Only the owner can assign orders");
          const r = (await env.DB.prepare("SELECT id,display_name FROM users WHERE owner_id=? AND is_desk=1 AND is_active=1 ORDER BY display_name").bind(bid).all()).results;
          return json({ desk: [{ id: user.id, name: user.display_name + " (you)" }, ...r.map((x) => ({ id: x.id, name: x.display_name }))] });
        }
        if (path === "/api/orders/catalogue" && method === "GET") {
          const r = (await env.DB.prepare("SELECT id,name,price,category FROM shop_products WHERE business_id=? AND active=1 ORDER BY (category=''), category COLLATE NOCASE, name COLLATE NOCASE LIMIT ?").bind(bid, SHOP.maxProducts).all()).results;
          return json({ products: r.map(productOut).map((p) => ({ id: p.id, name: p.name, price: p.price, category: p.category })) });
        }
        if (path === "/api/orders" && method === "GET") {
          const f = new URL(request.url).searchParams.get("f") || "new";
          const off = Math.max(0, parseInt(new URL(request.url).searchParams.get("offset"), 10) || 0);
          const ph = (a) => a.map(() => "?").join(",");
          let where, args = [bid];
          if (f === "new") { where = "o.status='submitted'"; }
          else if (f === "mine") { where = "o.assigned_to=? AND o.status IN (" + ph(ORDER_OPEN) + ")"; args.push(user.id, ...ORDER_OPEN); }
          else if (f === "pay") { where = "o.status='paid_reported'"; }
          else if (f === "done") { where = "o.status IN (" + ph(doneS) + ")"; args.push(...doneS); }
          else { where = "o.status IN (" + ph(ORDER_OPEN) + ")"; args.push(...ORDER_OPEN); }
          const rows = (await env.DB.prepare(SEL + " WHERE o.business_id=? AND " + where + " ORDER BY " + (f === "done" ? "o.updated_at DESC" : "o.created_at ASC") + " LIMIT 31 OFFSET ?").bind(...args, off).all()).results;
          return json({ orders: rows.slice(0, 30).map(row), more: rows.length > 30 });
        }
        const om = path.match(/^\/api\/orders\/([0-9a-f-]{36})(?:\/(take|release|assign|items|approve|decline|confirm-paid|not-received|reopen|stock-out))?$/);
        if (om) {
          const o = await env.DB.prepare(SEL + " WHERE o.id=? AND o.business_id=?").bind(om[1], bid).first();
          if (!o) return fail(404, "Order not found");
          const act = om[2];
          const full = async (x) => {
            const st = await shopSt();
            const mine = x.assigned_to === user.id;
            return { ...row(x), note: x.note, staffNote: x.staff_note || "", payNote: x.pay_note || "", paidAt: x.paid_at || null, items: orderLinesOut(x.items), asked: orderLinesOut(x.asked), adj: adjOut(x.adj), username: x.cuser,
              canEdit: x.status === "reviewing" && (owner || mine), canPrice: owner || !!(st && st.price_edit), events: await orderEvents(env, x.id),
              stock: { on: !!(st && st.stock_store), done: !!x.stock_entry },
              bank: st ? { bankName: st.bank_name, acctName: st.acct_name, acctNo: st.acct_no } : null };
          };
          if (!act && method === "GET") return json({ order: await full(o) });
          const again = async () => json({ order: await full(await env.DB.prepare(SEL + " WHERE o.id=?").bind(o.id).first()) });
          const me = user.display_name;
          const upd = async (sql, ...args) => { const r = await env.DB.prepare(sql).bind(...args).run(); return !!(r.meta && r.meta.changes); };
          const handler = () => owner || o.assigned_to === user.id;
          if (act === "items") {
            if (method !== "PUT") return fail(405, "Not allowed");
            if (o.status !== "reviewing") return fail(409, "This order can no longer be edited.");
            if (!handler()) return fail(403, "Take this order first");
            const st = await shopSt();
            const priceOk = owner || !!(st && st.price_edit);
            const b = await readBody(request);
            if (!Array.isArray(b.items) || !b.items.length || b.items.length > ORDER_LIMITS.lines) return fail(400, "An order needs between 1 and " + ORDER_LIMITS.lines + " items");
            const before = orderLinesOut(o.items), bm = new Map(before.map((l) => [l.id, l]));
            const seen = new Set(), after = [];
            const newIds = [];
            for (const it of b.items) {
              const id = String((it && it.id) || ""), q = Number(it && it.qty);
              if (!/^[0-9a-f-]{36}$/.test(id) || seen.has(id)) return fail(400, "Check the items in this order");
              if (!Number.isInteger(q) || q < 1 || q > ORDER_LIMITS.qty) return fail(400, "Quantities must be 1 to " + ORDER_LIMITS.qty);
              seen.add(id); if (!bm.has(id)) newIds.push(id);
            }
            const cat = new Map();
            if (newIds.length) for (const r of (await env.DB.prepare("SELECT id,name,price,hide_price FROM shop_products WHERE business_id=? AND active=1 AND id IN (" + newIds.map(() => "?").join(",") + ")").bind(bid, ...newIds).all()).results) cat.set(r.id, r);
            for (const it of b.items) {
              const old = bm.get(it.id), q = Number(it.qty);
              let name, price;
              if (old) { name = old.name; price = old.price; } else { const c = cat.get(it.id); if (!c) return fail(409, "An item you added is no longer in the shop"); name = c.name; price = c.price; }
              if (it.price !== undefined && Number(it.price) !== price) {
                if (!priceOk) return fail(403, "The owner has not allowed price changes");
                const np = parsePrice(it.price); if (np === null) return fail(400, "Enter a price in naira (whole number, more than 0)");
                price = np;
              }
              after.push({ id: it.id, name, price, qty: q, ...((old ? old.hid : (st && st.hide_prices) || (cat.get(it.id) && cat.get(it.id).hide_price)) ? { hid: 1 } : {}) });
            }
            const adjB = adjOut(o.adj);
            let adjA = adjB;
            if (b.adj !== undefined) {
              if (!Array.isArray(b.adj) || b.adj.length > 5) return fail(400, "At most 5 extra lines");
              adjA = [];
              for (const a of b.adj) {
                const label = cleanText(a && a.label, 40), amt = Number(a && a.amount);
                if (!label || !Number.isInteger(amt) || amt === 0 || Math.abs(amt) > SHOP.maxPrice) return fail(400, "Each extra line needs a name and an amount");
                adjA.push({ label, amount: amt });
              }
              if (JSON.stringify(adjA) !== JSON.stringify(adjB) && !priceOk) return fail(403, "The owner has not allowed discounts or delivery fees");
            }
            const total = after.reduce((t, l) => t + l.price * l.qty, 0) + adjA.reduce((t, a) => t + a.amount, 0);
            if (total < 1) return fail(400, "The total must be more than zero");
            if (total > SHOP.maxPrice) return fail(400, "This order is too large");
            const sum = editSummary(before, after, adjB, adjA);
            if (sum === "No changes") return await again();
            if (!(await upd("UPDATE shop_orders SET items=?,adj=?,total=?,updated_at=? WHERE id=? AND business_id=? AND status='reviewing' AND (assigned_to=? OR ?=1)", JSON.stringify(after), JSON.stringify(adjA), total, now, o.id, bid, user.id, owner ? 1 : 0))) return fail(409, "This order has changed. Please reopen it.");
            await evStmt(env, o.id, "staff", me, "edited", sum).run();
            return await again();
          }
          if (method !== "POST") return fail(405, "Not allowed");
          if (act === "take") {
            if (!(await upd("UPDATE shop_orders SET status='reviewing',assigned_to=?,updated_at=? WHERE id=? AND business_id=? AND status='submitted' AND assigned_to IS NULL", user.id, now, o.id, bid))) return fail(409, o.hname ? o.hname + " already took this order." : "This order is no longer waiting.");
            await evStmt(env, o.id, "staff", me, "taken", "").run();
            return await again();
          }
          if (act === "release") {
            if (!owner && o.assigned_to !== user.id) return fail(403, "Only the person handling this order can put it back");
            if (!(await upd("UPDATE shop_orders SET status='submitted',assigned_to=NULL,updated_at=? WHERE id=? AND business_id=? AND status='reviewing'", now, o.id, bid))) return fail(409, "This order cannot be put back now.");
            await evStmt(env, o.id, "staff", me, "released", "").run();
            return await again();
          }
          if (act === "assign") {
            if (!owner) return fail(403, "Only the owner can assign orders");
            const b = await readBody(request);
            const tid = String(b.userId || "");
            const t = tid === user.id ? { id: user.id, display_name: user.display_name } : await env.DB.prepare("SELECT id,display_name FROM users WHERE id=? AND owner_id=? AND is_desk=1 AND is_active=1").bind(tid, bid).first();
            if (!t) return fail(400, "Choose someone from the order desk");
            if (!(await upd("UPDATE shop_orders SET status='reviewing',assigned_to=?,updated_at=? WHERE id=? AND business_id=? AND status IN ('submitted','reviewing')", t.id, now, o.id, bid))) return fail(409, "This order can no longer be assigned.");
            await evStmt(env, o.id, "staff", me, "assigned", t.display_name).run();
            return await again();
          }
          const b = await readBody(request);
          if (act === "approve") {
            if (!handler()) return fail(403, "Only the person handling this order can approve it");
            if (o.total < 1) return fail(400, "The total must be more than zero");
            const note = cleanText(b.note, 200);
            let ok = false;
            for (let attempt = 0; attempt < 4 && !ok; attempt++) {
              try {
                ok = await upd("UPDATE shop_orders SET status='approved',staff_note=?,expires_at=?,inv_no=COALESCE(inv_no,(SELECT COALESCE(MAX(inv_no),0)+1 FROM shop_orders WHERE business_id=?)),updated_at=? WHERE id=? AND business_id=? AND status='reviewing' AND (assigned_to=? OR ?=1)", note, now + ORDER_HOURS * 3600000, bid, now, o.id, bid, user.id, owner ? 1 : 0);
                if (!ok) return fail(409, "This order can no longer be approved.");
              } catch (e) { if (!/unique/i.test(String((e && e.message) || e)) || attempt === 3) throw e; }
            }
            await evStmt(env, o.id, "staff", me, "approved", "").run();
            return await again();
          }
          if (act === "decline") {
            if (!handler()) return fail(403, "Only the person handling this order can decline it");
            const reason = cleanText(b.reason, 200);
            if (reason.length < 3) return fail(400, "Tell the customer why");
            if (!(await upd("UPDATE shop_orders SET status='declined',expires_at=NULL,updated_at=? WHERE id=? AND business_id=? AND status='reviewing' AND (assigned_to=? OR ?=1)", now, o.id, bid, user.id, owner ? 1 : 0))) return fail(409, "This order can no longer be declined.");
            await evStmt(env, o.id, "staff", me, "declined", reason).run();
            return await again();
          }
          if (act === "confirm-paid") {
            if (!(await upd("UPDATE shop_orders SET status='paid',paid_at=?,expires_at=NULL,updated_at=? WHERE id=? AND business_id=? AND status IN ('paid_reported','accepted','expired')", now, now, o.id, bid))) return fail(409, "This order cannot be marked as paid now.");
            await evStmt(env, o.id, "staff", me, "paid", "").run();
            let stockNote = "";
            try { const fresh = await env.DB.prepare("SELECT * FROM shop_orders WHERE id=?").bind(o.id).first(); const r2 = await stockOutOrder(env, bid, fresh, user.id, me, now); if (!r2.done && r2.reason !== "off") stockNote = "Payment saved, but stock could not be taken out. Use the Take out of stock button."; } catch (e) { stockNote = "Payment saved, but stock could not be taken out. Use the Take out of stock button."; }
            const out = await full(await env.DB.prepare(SEL + " WHERE o.id=?").bind(o.id).first());
            return json({ order: out, warning: stockNote });
          }
          if (act === "not-received") {
            const reason = cleanText(b.reason, 200);
            if (reason.length < 3) return fail(400, "Tell the customer what you found");
            if (!(await upd("UPDATE shop_orders SET status='accepted',expires_at=?,updated_at=? WHERE id=? AND business_id=? AND status='paid_reported'", now + ORDER_HOURS * 3600000, now, o.id, bid))) return fail(409, "This payment was already handled.");
            await evStmt(env, o.id, "staff", me, "not_received", reason).run();
            return await again();
          }
          if (act === "stock-out") {
            if (o.status !== "paid") return fail(409, "Only a paid order can be taken out of stock.");
            if (o.stock_entry) return fail(409, "Stock was already taken out for this order.");
            const r2 = await stockOutOrder(env, bid, o, user.id, me, now);
            if (!r2.done) return fail(409, r2.reason === "off" ? "Choose a store for orders in Shop settings first." : "The store chosen in Shop settings is not available. Choose another one.");
            return await again();
          }
          if (act === "reopen") {
            if (!handler()) return fail(403, "Only the person handling this order can reopen it");
            if (!(await upd("UPDATE shop_orders SET status='approved',expires_at=?,updated_at=? WHERE id=? AND business_id=? AND status='expired'", now + ORDER_HOURS * 3600000, now, o.id, bid))) return fail(409, "Only an expired order can be reopened.");
            await evStmt(env, o.id, "staff", me, "reopened", "").run();
            return await again();
          }
        }
        return fail(404, "Not found");
      }

      if (path.startsWith("/api/shop")) {
        if (!user.is_super_admin) return fail(403, "Only the owner can manage the shop");
        const bid = user.owner_id || user.id;
        const now = Date.now();
        const prods = async () => (await env.DB.prepare("SELECT * FROM shop_products WHERE business_id=? ORDER BY (category=''), category COLLATE NOCASE, name COLLATE NOCASE").bind(bid).all()).results.map(productOut);

        if (path === "/api/shop" && method === "GET") {
          const st = await env.DB.prepare("SELECT * FROM shop_settings WHERE business_id=?").bind(bid).first();
          const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_customers WHERE business_id=?").bind(bid).first();
          return json({ settings: settingsOut(st), products: await prods(), customers: c.n, limits: { products: SHOP.maxProducts } });
        }

        if (path === "/api/shop/settings" && method === "PUT") {
          const b = await readBody(request);
          const cur = settingsOut(await env.DB.prepare("SELECT * FROM shop_settings WHERE business_id=?").bind(bid).first());
          const n = { ...cur };
          if (typeof b.bankName === "string") n.bankName = cleanText(b.bankName, 60);
          if (typeof b.acctName === "string") n.acctName = cleanText(b.acctName, 80);
          if (typeof b.acctNo === "string") n.acctNo = b.acctNo.replace(/\s/g, "");
          if (typeof b.welcome === "string") n.welcome = cleanText(b.welcome, 200);
          if (typeof b.priceEdit === "boolean") n.priceEdit = b.priceEdit;
          if (typeof b.hidePrices === "boolean") n.hidePrices = b.hidePrices;
          if (typeof b.enabled === "boolean") n.enabled = b.enabled;
          if (typeof b.stockStore === "string") {
            if (b.stockStore === "") n.stockStore = "";
            else {
              const sx = await env.DB.prepare("SELECT id FROM stores WHERE id=? AND owner_id=? AND is_archived=0").bind(b.stockStore, bid).first();
              if (!sx) return fail(400, "Choose one of your stores");
              n.stockStore = sx.id;
            }
          }
          if (n.acctNo && !/^[0-9]{10}$/.test(n.acctNo)) return fail(400, "The account number must be 10 digits");
          if (n.enabled && (!n.bankName || !n.acctName || !n.acctNo)) return fail(400, "Add your bank details first, so customers know where to pay");
          await env.DB.batch([
            env.DB.prepare("INSERT INTO shop_settings (business_id,enabled,bank_name,acct_name,acct_no,welcome,price_edit,stock_store,hide_prices,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(business_id) DO UPDATE SET enabled=excluded.enabled,bank_name=excluded.bank_name,acct_name=excluded.acct_name,acct_no=excluded.acct_no,welcome=excluded.welcome,price_edit=excluded.price_edit,stock_store=excluded.stock_store,hide_prices=excluded.hide_prices,updated_at=excluded.updated_at")
              .bind(bid, n.enabled ? 1 : 0, n.bankName, n.acctName, n.acctNo, n.welcome, n.priceEdit ? 1 : 0, n.stockStore || "", n.hidePrices ? 1 : 0, now),
            audit(env, null, user.id, n.enabled !== cur.enabled ? (n.enabled ? "shop_opened" : "shop_closed") : "shop_settings", ""),
          ]);
          return json({ settings: n });
        }

        if (path === "/api/shop/products" && method === "POST") {
          const b = await readBody(request);
          const name = cleanText(b.name, 80), cat = cleanText(b.category, 30), price = parsePrice(b.price);
          if (!name) return fail(400, "Enter the item name");
          if (price === null) return fail(400, "Enter a price in naira (whole number, more than 0)");
          const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM shop_products WHERE business_id=?").bind(bid).first();
          if (c.n >= SHOP.maxProducts) return fail(400, "You have reached the limit of " + SHOP.maxProducts + " items");
          const dup = await env.DB.prepare("SELECT 1 AS x FROM shop_products WHERE business_id=? AND lower(name)=lower(?)").bind(bid, name).first();
          if (dup) return fail(409, "You already have an item with that name");
          const id = crypto.randomUUID();
          await env.DB.prepare("INSERT INTO shop_products (id,business_id,name,price,category,active,hide_price,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?,?)").bind(id, bid, name, price, cat, b.hidePrice === true ? 1 : 0, now, now).run();
          return json({ product: { id, name, price, category: cat, active: true, hidePrice: b.hidePrice === true } }, 201);
        }

        if (path === "/api/shop/products/import" && method === "POST") {
          const b = await readBody(request);
          const lines = String(b.text || "").split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
          if (!lines.length) return fail(400, "Paste at least one line, like: Soap, 1500");
          if (lines.length > SHOP.importLines) return fail(400, "At most " + SHOP.importLines + " lines at a time");
          const have = new Map((await env.DB.prepare("SELECT id,lower(name) AS k FROM shop_products WHERE business_id=?").bind(bid).all()).results.map((x) => [x.k, x.id]));
          const stmts = [], skipped = [];
          let added = 0, updated = 0, count = have.size;
          const seen = new Set();
          for (const line of lines) {
            let parts = line.split(/[\t|,]/).map((x) => x.trim());
            let name, price, cat = "";
            if (parts.length >= 2) { name = cleanText(parts[0], 80); price = parsePrice(parts[1]); cat = cleanText(parts[2] || "", 30); }
            else { const m = line.match(/^(.*?)[\s:\-–]+(?:₦|n)?\s*([\d,]+)$/i); if (m) { name = cleanText(m[1], 80); price = parsePrice(m[2]); } }
            if (!name || price === null || price === undefined) { skipped.push({ line: line.slice(0, 60), reason: "Could not read name and price" }); continue; }
            const k = name.toLowerCase();
            if (seen.has(k)) { skipped.push({ line: line.slice(0, 60), reason: "Repeated in your list" }); continue; }
            seen.add(k);
            if (have.has(k)) {
              stmts.push(env.DB.prepare("UPDATE shop_products SET price=?,category=CASE WHEN ?<>'' THEN ? ELSE category END,updated_at=? WHERE id=?").bind(price, cat, cat, now, have.get(k)));
              updated++;
            } else {
              if (count >= SHOP.maxProducts) { skipped.push({ line: line.slice(0, 60), reason: "Item limit reached" }); continue; }
              stmts.push(env.DB.prepare("INSERT INTO shop_products (id,business_id,name,price,category,active,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?)").bind(crypto.randomUUID(), bid, name, price, cat, now, now));
              count++; added++;
            }
          }
          if (stmts.length) await env.DB.batch(stmts);
          return json({ added, updated, skipped, products: await prods() });
        }

        const pm = path.match(/^\/api\/shop\/products\/([0-9a-f-]{36})$/);
        if (pm) {
          const cur = await env.DB.prepare("SELECT * FROM shop_products WHERE id=? AND business_id=?").bind(pm[1], bid).first();
          if (!cur) return fail(404, "Item not found");
          if (method === "DELETE") {
            await env.DB.prepare("DELETE FROM shop_products WHERE id=?").bind(cur.id).run();
            return json({ ok: true });
          }
          if (method === "PUT") {
            const b = await readBody(request);
            let name = cur.name, price = cur.price, cat = cur.category, active = cur.active;
            if (typeof b.name === "string") { name = cleanText(b.name, 80); if (!name) return fail(400, "Enter the item name"); }
            if (b.price !== undefined) { price = parsePrice(b.price); if (price === null) return fail(400, "Enter a price in naira (whole number, more than 0)"); }
            if (typeof b.category === "string") cat = cleanText(b.category, 30);
            if (typeof b.active === "boolean") active = b.active ? 1 : 0;
            let hp = cur.hide_price ? 1 : 0;
            if (typeof b.hidePrice === "boolean") hp = b.hidePrice ? 1 : 0;
            if (name.toLowerCase() !== cur.name.toLowerCase()) {
              const dup = await env.DB.prepare("SELECT 1 AS x FROM shop_products WHERE business_id=? AND lower(name)=lower(?) AND id<>?").bind(bid, name, cur.id).first();
              if (dup) return fail(409, "You already have an item with that name");
            }
            await env.DB.prepare("UPDATE shop_products SET name=?,price=?,category=?,active=?,hide_price=?,updated_at=? WHERE id=?").bind(name, price, cat, active, hp, now, cur.id).run();
            return json({ product: { id: cur.id, name, price, category: cat, active: !!active, hidePrice: !!hp } });
          }
        }

        if (path === "/api/shop/customers" && method === "GET") {
          const rows = (await env.DB.prepare("SELECT id,username,display_name,phone,is_active,created_at,last_seen FROM shop_customers WHERE business_id=? ORDER BY created_at DESC LIMIT 500").bind(bid).all()).results;
          return json({ customers: rows.map((c) => ({ id: c.id, username: c.username, displayName: c.display_name, phone: c.phone, isActive: !!c.is_active, createdAt: c.created_at, lastSeen: c.last_seen })) });
        }
        const cm = path.match(/^\/api\/shop\/customers\/([0-9a-f-]{36})$/);
        if (cm && method === "PUT") {
          const c = await env.DB.prepare("SELECT id,username FROM shop_customers WHERE id=? AND business_id=?").bind(cm[1], bid).first();
          if (!c) return fail(404, "Customer not found");
          const b = await readBody(request);
          const stmts = [];
          if (typeof b.isActive === "boolean") {
            stmts.push(env.DB.prepare("UPDATE shop_customers SET is_active=? WHERE id=?").bind(b.isActive ? 1 : 0, c.id));
            stmts.push(audit(env, null, user.id, b.isActive ? "customer_turned_on" : "customer_turned_off", c.username));
            if (!b.isActive) stmts.push(env.DB.prepare("DELETE FROM shop_sessions WHERE customer_id=?").bind(c.id));
          }
          if (typeof b.password === "string" && b.password) {
            if (b.password.length < 8) return fail(400, "Password must be at least 8 characters");
            const salt = randomHex(16), iter = targetIter(env);
            stmts.push(env.DB.prepare("UPDATE shop_customers SET password_hash=?,password_salt=?,pw_iter=? WHERE id=?").bind(await hashPassword(b.password, salt, iter), salt, iter, c.id));
            stmts.push(env.DB.prepare("DELETE FROM shop_sessions WHERE customer_id=?").bind(c.id));
            stmts.push(audit(env, null, user.id, "customer_password_reset", c.username));
          }
          if (stmts.length) await env.DB.batch(stmts);
          return json({ ok: true });
        }
        return fail(404, "Not found");
      }

      if (path === "/api/keepers" && method === "GET") {
        if (!user.is_super_admin) return fail(403, "Only the Super Admin can manage keepers");
        return json({ keepers: await keepersFor(user, env) });
      }

      if (path === "/api/keepers" && method === "POST") {
        if (!user.is_super_admin) return fail(403, "Only the Super Admin can manage keepers");
        const b = await readBody(request);
        const username = cleanUsername(b.username);
        const name = String(b.displayName || "").trim().slice(0, 60);
        const pw = String(b.password || "");
        if (!username) return fail(400, "Username must be 3-30 letters, numbers, dots, dashes or underscores");
        if (!name) return fail(400, "The keeper's name is required");
        if (pw.length < 8) return fail(400, "Password must be at least 8 characters");
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE owner_id=?").bind(user.id).first();
        if (c.n >= MAX_KEEPERS) return fail(400, "You have reached the limit of " + MAX_KEEPERS + " keepers");
        const taken = await env.DB.prepare("SELECT id FROM users WHERE username=?").bind(username).first();
        if (taken) return fail(409, "That username is already taken");
        const assigns = cleanAssignments(b.assignments, await ownedStoreIds(env, user.id));
        const id = crypto.randomUUID();
        const salt = randomHex(16);
        const hash = await hashPassword(pw, salt);
        const stmts = [
          env.DB.prepare(
            "INSERT INTO users (id,username,display_name,password_hash,password_salt,owner_id,is_super_admin,must_change_password,is_active,created_at) VALUES (?,?,?,?,?,?,0,1,1,?)"
          ).bind(id, username, name, hash, salt, user.id, Date.now()),
        ];
        for (const a of assigns)
          stmts.push(
            env.DB.prepare("INSERT INTO memberships (user_id,store_id,role) VALUES (?,?,?)").bind(id, a.storeId, a.role)
          );
        if (b.isDesk === true) stmts.push(env.DB.prepare("UPDATE users SET is_desk=1 WHERE id=?").bind(id));
        stmts.push(audit(env, null, user.id, "keeper_created", username));
        await env.DB.batch(stmts);
        const keeper = (await keepersFor(user, env)).find((k) => k.id === id);
        return json({ keeper }, 201);
      }

      const km = path.match(/^\/api\/keepers\/([0-9a-f-]{36})$/);
      if (km && method === "PUT") {
        if (!user.is_super_admin) return fail(403, "Only the Super Admin can manage keepers");
        const kid = km[1];
        const k = await env.DB.prepare("SELECT id,username FROM users WHERE id=? AND owner_id=?")
          .bind(kid, user.id).first();
        if (!k) return fail(404, "Keeper not found");
        const b = await readBody(request);
        const stmts = [];
        let killSessions = false;
        if (typeof b.displayName === "string") {
          const name = b.displayName.trim().slice(0, 60);
          if (!name) return fail(400, "The keeper's name is required");
          stmts.push(env.DB.prepare("UPDATE users SET display_name=? WHERE id=?").bind(name, kid));
        }
        if (typeof b.isDesk === "boolean") {
          stmts.push(env.DB.prepare("UPDATE users SET is_desk=? WHERE id=?").bind(b.isDesk ? 1 : 0, kid));
          stmts.push(audit(env, null, user.id, b.isDesk ? "keeper_desk_on" : "keeper_desk_off", k.username));
        }
        if (typeof b.isActive === "boolean") {
          stmts.push(env.DB.prepare("UPDATE users SET is_active=? WHERE id=?").bind(b.isActive ? 1 : 0, kid));
          stmts.push(audit(env, null, user.id, b.isActive ? "keeper_turned_on" : "keeper_turned_off", k.username));
          if (!b.isActive) killSessions = true;
        }
        if (typeof b.password === "string" && b.password) {
          if (b.password.length < 8) return fail(400, "Password must be at least 8 characters");
          const salt = randomHex(16);
          const hash = await hashPassword(b.password, salt);
          stmts.push(
            env.DB.prepare(
              "UPDATE users SET password_hash=?,pw_iter=30000,password_salt=?,must_change_password=1 WHERE id=?"
            ).bind(hash, salt, kid)
          );
          stmts.push(audit(env, null, user.id, "keeper_password_reset", k.username));
          killSessions = true;
        }
        if (Array.isArray(b.assignments)) {
          const assigns = cleanAssignments(b.assignments, await ownedStoreIds(env, user.id));
          stmts.push(env.DB.prepare("DELETE FROM memberships WHERE user_id=?").bind(kid));
          for (const a of assigns)
            stmts.push(
              env.DB.prepare("INSERT INTO memberships (user_id,store_id,role) VALUES (?,?,?)").bind(kid, a.storeId, a.role)
            );
          stmts.push(audit(env, null, user.id, "keeper_access_changed", k.username));
        }
        if (killSessions) stmts.push(env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(kid));
        if (stmts.length) await env.DB.batch(stmts);
        const keeper = (await keepersFor(user, env)).find((x) => x.id === kid);
        return json({ keeper });
      }



      const am = path.match(/^\/api\/stores\/([0-9a-f-]{36})\/activity$/);
      if (am && method === "GET") {
        const role = await roleIn(env, user, am[1]);
        if (!role) return fail(404, "Store not found");
        if (role !== "owner" && role !== "manager") return fail(403, "Only the owner or a manager can see activity");
        const before = Math.max(0, parseInt(new URL(request.url).searchParams.get("before") || "0", 10) || 0);
        const r = await env.DB.prepare(
          ACTIVITY_SELECT + " WHERE a.store_id=? AND (?=0 OR a.id<?) ORDER BY a.id DESC LIMIT 51"
        ).bind(am[1], before, before).all();
        const rows = r.results;
        const hasMore = rows.length > 50;
        if (hasMore) rows.length = 50;
        return json({ activity: rows.map(activityOut), hasMore });
      }

      if (path === "/api/activity" && method === "GET") {
        if (!user.is_super_admin) return fail(403, "Only the Super Admin can see all activity");
        const before = Math.max(0, parseInt(new URL(request.url).searchParams.get("before") || "0", 10) || 0);
        const r = await env.DB.prepare(
          ACTIVITY_SELECT +
            " WHERE (a.store_id IN (SELECT id FROM stores WHERE owner_id=?1) OR a.user_id=?1 OR a.user_id IN (SELECT id FROM users WHERE owner_id=?1)) AND (?2=0 OR a.id<?2) ORDER BY a.id DESC LIMIT 51"
        ).bind(user.id, before).all();
        const rows = r.results;
        const hasMore = rows.length > 50;
        if (hasMore) rows.length = 50;
        return json({ activity: rows.map(activityOut), hasMore });
      }

      const im = path.match(/^\/api\/stores\/([0-9a-f-]{36})\/import$/);
      if (im && method === "POST") {
        const sid = im[1];
        const role = await roleIn(env, user, sid);
        if (!role) return fail(404, "Store not found");
        if (role !== "owner" && role !== "manager") return fail(403, "Only the owner or a manager can import stock");
        const b = await readBody(request);
        const list = Array.isArray(b.entries) ? b.entries : null;
        if (!list || list.length < 1 || list.length > 80) return fail(400, "Send between 1 and 80 entries at a time");
        const now = Date.now();
        const valid = [];
        let invalid = 0;
        for (const raw of list) {
          const c = cleanEntry(raw || {});
          if (c.error || !validDate(raw.date)) { invalid++; continue; }
          let created = Number(raw.createdAt);
          if (!Number.isFinite(created) || created < 946684800000 || created > now + 300000) created = now;
          const origin = ENTRY_ID.test(String(raw.id || "")) ? String(raw.id) : crypto.randomUUID();
          valid.push({
            id: (await sha256(sid + ":" + origin)).slice(0, 32),
            type: c.type, ref: c.ref, items: c.items, date: raw.date, created,
          });
        }
        const found = new Set();
        if (valid.length) {
          const ids = valid.map((v) => v.id);
          const ex = await env.DB.prepare(
            "SELECT id FROM entries WHERE id IN (" + ids.map(() => "?").join(",") + ")"
          ).bind(...ids).all();
          ex.results.forEach((r) => found.add(r.id));
        }
        const stmts = [];
        let imported = 0;
        let skipped = 0;
        for (const v of valid) {
          if (found.has(v.id)) { skipped++; continue; }
          found.add(v.id);
          stmts.push(
            env.DB.prepare(
              "INSERT INTO entries (id,store_id,type,entry_date,ref,items,created_by,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)"
            ).bind(v.id, sid, v.type, v.date, v.ref, JSON.stringify(v.items), user.id, v.created, now)
          );
          imported++;
        }
        if (imported) {
          stmts.push(audit(env, sid, user.id, "entries_imported", imported + " entries"));
          await env.DB.batch(stmts);
        }
        return json({ imported, skipped, invalid });
      }

      const em = path.match(/^\/api\/stores\/([0-9a-f-]{36})\/entries(?:\/([A-Za-z0-9_-]{8,40}))?$/);
      if (em) {
        const sid = em[1];
        const eid = em[2];
        const role = await roleIn(env, user, sid);
        if (!role) return fail(404, "Store not found");

        if (!eid && method === "GET") {
          const since = Math.max(0, parseInt(new URL(request.url).searchParams.get("since") || "0", 10) || 0);
          const LIMIT = 1000;
          const r = await env.DB.prepare(
            ENTRY_SELECT +
              " WHERE e.store_id=? AND e.updated_at>=?" +
              (since === 0 ? " AND e.deleted_at IS NULL" : "") +
              " ORDER BY e.updated_at, e.id LIMIT ?"
          ).bind(sid, since, LIMIT + 1).all();
          const rows = r.results;
          const hasMore = rows.length > LIMIT;
          if (hasMore) rows.length = LIMIT;
          return json({ entries: rows.map(entryOut), hasMore });
        }

        if (eid && method === "PUT") {
          const b = await readBody(request);
          const c = cleanEntry(b);
          if (c.error) return fail(400, c.error);
          const existing = await env.DB.prepare(
            "SELECT id,store_id,created_by,deleted_at,type,ref,items,edited FROM entries WHERE id=?"
          ).bind(eid).first();
          const now = Date.now();
          if (existing) {
            if (existing.store_id !== sid) return fail(404, "Entry not found");
            if (existing.deleted_at) return fail(409, "This entry was deleted");
            if (!canModifyEntry(role, user, existing)) return fail(403, "You can't change this entry");
            // A phone that re-sends a message the server already received must not change anything.
            const unchanged =
              existing.type === c.type && (existing.ref || "") === c.ref && existing.items === JSON.stringify(c.items);
            const staleCreate = b.create === true && existing.edited;
            if (!unchanged && !staleCreate) {
              await env.DB.batch([
                env.DB.prepare("UPDATE entries SET type=?,ref=?,items=?,updated_at=?,edited=1 WHERE id=?")
                  .bind(c.type, c.ref, JSON.stringify(c.items), now, eid),
                audit(env, sid, user.id, "entry_edited", c.type + ":" + eid),
              ]);
            }
          } else {
            if (role !== "owner" && role !== "manager" && role !== "keeper")
              return fail(403, "You can't add entries in this store");
            const date = validDate(b.date) ? b.date : new Date(now).toISOString().slice(0, 10);
            // Entries recorded without signal keep the time they were really recorded (up to 14 days back).
            let created = Number(b.createdAt);
            if (!Number.isFinite(created) || created < now - 14 * 86400000 || created > now + 300000) created = now;
            await env.DB.batch([
              env.DB.prepare(
                "INSERT INTO entries (id,store_id,type,entry_date,ref,items,created_by,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)"
              ).bind(eid, sid, c.type, date, c.ref, JSON.stringify(c.items), user.id, created, now),
              audit(env, sid, user.id, "entry_added", c.type + ":" + eid),
            ]);
          }
          const row = await env.DB.prepare(ENTRY_SELECT + " WHERE e.id=?").bind(eid).first();
          return json({ entry: entryOut(row) }, existing ? 200 : 201);
        }

        if (eid && method === "DELETE") {
          const existing = await env.DB.prepare(
            "SELECT id,store_id,created_by,deleted_at FROM entries WHERE id=?"
          ).bind(eid).first();
          if (!existing || existing.store_id !== sid) return fail(404, "Entry not found");
          if (existing.deleted_at) return json({ ok: true });
          if (!canModifyEntry(role, user, existing)) return fail(403, "You can't delete this entry");
          const now = Date.now();
          await env.DB.batch([
            env.DB.prepare("UPDATE entries SET deleted_at=?,updated_at=? WHERE id=?").bind(now, now, eid),
            audit(env, sid, user.id, "entry_deleted", eid),
          ]);
          return json({ ok: true });
        }

        return fail(405, "Not allowed");
      }

      return fail(404, "Not found");
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (/limit|quota|exceed/i.test(msg))
        return json({ error: "The free daily limit was reached. It resets at midnight UTC.", code: "limit" }, 503);
      console.error("tradebook error:", String((e && e.stack) || e));
      // Add a variable DEBUG = 1 to this worker to see the real reason on screen while fixing a problem.
      return fail(500, env.DEBUG === "1" ? "Server error: " + msg.slice(0, 200) : "Server error");
    }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    let ok = true;
    if (origin) {
      try { await ensureSchema(env); ok = (await allowedOrigins(env, origin)).has(origin); }
      catch (e) { ok = origin === ALLOWED_ORIGIN; }
    }
    let res;
    if (request.method === "OPTIONS") res = new Response(null, { status: 204 }); // preflight carries no data; the real request is checked next
    else if (!ok) res = json({ error: "This web address (" + origin + ") is not registered for your business yet. Ask the app provider to add it under Allowed web addresses.", code: "origin_blocked", origin }, 403);
    else if (request.method !== "GET" && Number(request.headers.get("Content-Length") || 0) > MAX_BODY) res = fail(413, "That request is too large");
    else res = await handle(request, env, origin);
    const h = new Headers(res.headers);
    h.set("X-Content-Type-Options", "nosniff");
    h.set("Referrer-Policy", "no-referrer");
    // Also answer blocked addresses with CORS headers, so the browser lets the app read the reason
    // instead of showing a bare "can't connect" (the data itself is still refused).
    if (origin) {
      h.set("Access-Control-Allow-Origin", origin);
      for (const k in CORS_HEADERS) h.set(k, CORS_HEADERS[k]);
    }
    return new Response(res.body, { status: res.status, headers: h });
  },
};
