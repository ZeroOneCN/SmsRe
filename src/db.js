/**
 * 数据层：基于 Node 内置 node:sqlite（无需原生编译），单文件库 + WAL。
 * 仅暴露建表、设置项读写与少量通用查询，业务查询保留在 server.js 中以便阅读。
 */
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

mkdirSync(config.dataDir, { recursive: true });

export const db = new DatabaseSync(path.join(config.dataDir, 'smsfor.db'));

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  -- 转发设备（每台手机一个 Token，可独立停用/轮换）
  CREATE TABLE IF NOT EXISTS devices (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    token             TEXT NOT NULL UNIQUE,
    last_heartbeat_at INTEGER,
    last_message_at   INTEGER,
    last_alert_at     INTEGER,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL
  );

  -- 短信解析结果：原件仅后台可见，过期后 code 置空只留哈希
  CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    code        TEXT,
    code_hash   TEXT,
    candidates  TEXT,
    sender_tag  TEXT,
    sender      TEXT,
    raw_text    TEXT,
    received_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    dedupe_key  TEXT UNIQUE,
    status      TEXT NOT NULL DEFAULT 'active'
  );
  CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(received_at DESC);

  -- 访问审计
  CREATE TABLE IF NOT EXISTS views (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER,
    ip         TEXT NOT NULL,
    ua         TEXT,
    session_id TEXT,
    result     TEXT NOT NULL,
    viewed_at  INTEGER NOT NULL,
    dwell_ms   INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_views_time ON views(viewed_at DESC);
  CREATE INDEX IF NOT EXISTS idx_views_ip ON views(ip);

  -- IP 规则：action = block | allow，cidr 支持 IPv4/IPv6 与网段
  CREATE TABLE IF NOT EXISTS ip_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr       TEXT NOT NULL,
    action     TEXT NOT NULL,
    note       TEXT,
    hits       INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    ip           TEXT,
    ua           TEXT,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS auth_attempts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ip      TEXT NOT NULL,
    kind    TEXT NOT NULL,
    success INTEGER NOT NULL,
    at      INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_attempts ON auth_attempts(ip, kind, at);

  CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    actor  TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS blocked_seen (
    ip   TEXT PRIMARY KEY,
    at   INTEGER NOT NULL
  );
`);

/**
 * 兼容旧库：检查列是否存在，缺失时补上（SQLite 不支持 ADD COLUMN IF NOT EXISTS）。
 * @param {string} table 表名
 * @param {string} column 列名
 * @param {string} definition 列定义
 * @returns {void}
 */
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

// 旧版本只存解析结果，这里补上短信原文与发件人（仅后台可见）
ensureColumn('messages', 'sender', 'TEXT');
ensureColumn('messages', 'raw_text', 'TEXT');

/**
 * 读取设置项。
 * @param {string} key 键
 * @param {string} fallback 缺省值
 * @returns {string}
 */
export function getSetting(key, fallback = '') {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}

/**
 * 写入设置项（存在则覆盖）。
 * @param {string} key 键
 * @param {string|number} value 值
 * @returns {void}
 */
export function setSetting(key, value) {
  db.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
  ).run(key, String(value));
}

/**
 * 读取整数型设置项。
 * @param {string} key 键
 * @param {number} fallback 缺省值
 * @returns {number}
 */
export function getIntSetting(key, fallback) {
  const raw = Number.parseInt(getSetting(key, ''), 10);
  return Number.isFinite(raw) ? raw : fallback;
}

/**
 * 写审计日志，用于后台操作留痕。
 * @param {string} actor 操作者（admin/user/system）
 * @param {string} action 动作标识
 * @param {object|string} detail 详情
 * @returns {void}
 */
export function audit(actor, action, detail) {
  db.prepare('INSERT INTO audit_log (actor, action, detail, at) VALUES (?, ?, ?, ?)').run(
    actor,
    action,
    typeof detail === 'string' ? detail : JSON.stringify(detail ?? {}),
    Math.floor(Date.now() / 1000),
  );
}
