'use strict';
require('dotenv').config();
const pg = require('pg');
const { Pool } = pg;
const { v4: uuidv4 } = require('uuid');

// Parse bigint (int8, OID 20) and numeric (OID 1700) as numbers to match SQLite behavior
pg.types.setTypeParser(20, val => parseInt(val, 10));
pg.types.setTypeParser(1700, val => parseFloat(val));

const poolConfig = {
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5000', 10),
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'admin',
  database: process.env.PGDATABASE || 'penchecker',
};

const pool = new Pool(poolConfig);

// Helper to translate SQLite queries to PostgreSQL
function translateSql(sql) {
  if (typeof sql !== 'string') return sql;

  let translated = sql;

  // 1. Translate SQLite datetime('now') to CURRENT_TIMESTAMP
  translated = translated.replace(/datetime\('now'\)/gi, 'CURRENT_TIMESTAMP');

  // 2. Translate SQLite INSERT OR IGNORE INTO scan_blacklist to ON CONFLICT
  translated = translated.replace(
    /INSERT OR IGNORE INTO scan_blacklist\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i,
    'INSERT INTO scan_blacklist ($1) VALUES ($2) ON CONFLICT (domain) DO NOTHING'
  );

  // 3. Translate ? parameter placeholders to $1, $2, $3, etc.
  let paramIndex = 1;
  translated = translated.replace(/\?/g, () => `$${paramIndex++}`);

  // 4. Translate ROUND with N decimals to CAST as numeric for PostgreSQL compatibility
  translated = translated.replace(/ROUND\((AVG\([^)]+\)|[a-zA-Z_0-9.]+),\s*(\d+)\)/gi, 'ROUND(CAST($1 AS numeric), $2)');

  return translated;
}

// Helper to sanitize parameter values (e.g. converting undefined to null)
function sanitizeParams(params) {
  if (!Array.isArray(params)) return params;
  return params.map(val => val === undefined ? null : val);
}

const DB = {
  async run(sql, params = []) {
    const translated = translateSql(sql);
    const sanitized = sanitizeParams(params);
    try {
      const res = await pool.query(translated, sanitized);
      return { lastID: null, changes: res.rowCount };
    } catch (err) {
      console.error('[DB] run error:', err, 'Query:', sql, 'Translated:', translated);
      throw err;
    }
  },
  async get(sql, params = []) {
    const translated = translateSql(sql);
    const sanitized = sanitizeParams(params);
    try {
      const res = await pool.query(translated, sanitized);
      return res.rows[0];
    } catch (err) {
      console.error('[DB] get error:', err, 'Query:', sql, 'Translated:', translated);
      throw err;
    }
  },
  async all(sql, params = []) {
    const translated = translateSql(sql);
    const sanitized = sanitizeParams(params);
    try {
      const res = await pool.query(translated, sanitized);
      return res.rows || [];
    } catch (err) {
      console.error('[DB] all error:', err, 'Query:', sql, 'Translated:', translated);
      throw err;
    }
  },
  async exec(sql) {
    const translated = translateSql(sql);
    try {
      await pool.query(translated);
    } catch (err) {
      console.error('[DB] exec error:', err, 'Query:', sql, 'Translated:', translated);
      throw err;
    }
  },
};

// PostgreSQL Schema Definitions
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT DEFAULT '',
  avatar_url TEXT,
  phone TEXT,
  role TEXT DEFAULT 'user',
  plan TEXT DEFAULT 'free',
  is_active INTEGER DEFAULT 1,
  is_suspended INTEGER DEFAULT 0,
  two_factor_enabled INTEGER DEFAULT 0,
  two_factor_secret TEXT,
  email_verified INTEGER DEFAULT 0,
  email_verify_token TEXT,
  reset_token TEXT,
  reset_token_expires TEXT,
  email_notifications INTEGER DEFAULT 1,
  whatsapp_notifications INTEGER DEFAULT 0,
  slack_webhook_url TEXT,
  discord_webhook_url TEXT,
  onboarding_completed INTEGER DEFAULT 0,
  referral_code TEXT UNIQUE,
  referred_by TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  is_verified INTEGER DEFAULT 0,
  verification_method TEXT,
  verification_token TEXT,
  verified_at TIMESTAMPTZ,
  monitoring_enabled INTEGER DEFAULT 0,
  monitoring_frequency TEXT DEFAULT 'weekly',
  last_monitored_at TIMESTAMPTZ,
  next_monitor_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, domain)
);

CREATE TABLE IF NOT EXISTS scan_blacklist (
  id TEXT PRIMARY KEY,
  domain TEXT UNIQUE NOT NULL,
  reason TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  target_domain TEXT NOT NULL,
  scan_type TEXT DEFAULT 'quick',
  scan_mode TEXT DEFAULT 'passive',
  industry_profile TEXT DEFAULT 'general',
  status TEXT DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  current_step TEXT,
  security_score DOUBLE PRECISION,
  total_vulnerabilities INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0,
  pages_crawled INTEGER DEFAULT 0,
  technologies_detected TEXT DEFAULT '[]',
  headers_checked INTEGER DEFAULT 0,
  final_url TEXT,
  server_software TEXT,
  error_message TEXT,
  scan_log TEXT DEFAULT '[]',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_seconds INTEGER,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  vulnerability_type TEXT NOT NULL,
  category TEXT DEFAULT 'other',
  severity TEXT DEFAULT 'info',
  cvss_score DOUBLE PRECISION DEFAULT 0,
  confidence_score DOUBLE PRECISION DEFAULT 80,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  evidence TEXT DEFAULT '',
  affected_url TEXT DEFAULT '',
  fix_difficulty TEXT DEFAULT 'moderate',
  fix_description TEXT DEFAULT '',
  fix_code_snippet TEXT DEFAULT '',
  owasp_reference TEXT DEFAULT '',
  is_false_positive INTEGER DEFAULT 0,
  is_remediated INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id),
  format TEXT DEFAULT 'json',
  file_path TEXT,
  share_token TEXT UNIQUE,
  share_expires_at TIMESTAMPTZ,
  view_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_badges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  domain TEXT NOT NULL,
  scan_id TEXT,
  security_score DOUBLE PRECISION NOT NULL,
  badge_level TEXT,
  embed_token TEXT UNIQUE,
  earned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ,
  is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ai_chat_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scan_id TEXT,
  session_title TEXT,
  messages TEXT DEFAULT '[]',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  type TEXT,
  data TEXT DEFAULT '{}',
  is_read INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS consent_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  target_url TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  consent_text TEXT,
  consented_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON scan_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON scan_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
CREATE INDEX IF NOT EXISTS idx_notifs_user_id ON notifications(user_id);
`;

const BLACKLIST = [
  'google.com','facebook.com','youtube.com','twitter.com','x.com',
  'instagram.com','amazon.com','microsoft.com','apple.com','netflix.com',
  'paypal.com','linkedin.com','tiktok.com','whatsapp.com','github.com',
  'cia.gov','fbi.gov','nsa.gov',
];

// Initialize DB schema
async function init() {
  await DB.exec(SCHEMA);
  // Seed blacklist
  for (const domain of BLACKLIST) {
    await DB.run(
      `INSERT OR IGNORE INTO scan_blacklist (id, domain, reason) VALUES (?, ?, ?)`,
      [uuidv4(), domain, 'Protected domain — not permitted']
    );
  }
  console.log(`[DB] PostgreSQL database ready: penchecker`);
}

// Start init (called when module loads)
init().catch(err => { console.error('[DB] Init error:', err); process.exit(1); });

module.exports = { DB, db: pool };
