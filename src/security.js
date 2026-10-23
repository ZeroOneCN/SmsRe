/**
 * 安全模块：PIN 哈希校验、会话、IP/CIDR 匹配、登录失败锁定与轻量限流。
 * 所有实现均不依赖外部服务，避免访客 IP 被发送到第三方。
 */
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { db } from './db.js';
import { config } from './config.js';

const now = () => Math.floor(Date.now() / 1000);

/* ---------------------------------- PIN ---------------------------------- */

/**
 * 生成 PIN 的 scrypt 哈希。
 * @param {string} pin 明文 PIN
 * @returns {string} `scrypt|salt|hash` 形式
 */
export function hashPin(pin) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(String(pin), salt, 64).toString('hex');
  return `scrypt|${salt}|${hash}`;
}

/**
 * 校验 PIN 是否与哈希匹配（定长比较，防时序攻击）。
 * @param {string} pin 明文 PIN
 * @param {string} stored 已存储的哈希
 * @returns {boolean}
 */
export function verifyPin(pin, stored) {
  const parts = String(stored || '').split('|');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  try {
    const expected = Buffer.from(parts[2], 'hex');
    const actual = scryptSync(String(pin), parts[1], expected.length);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

/* -------------------------------- IP / CIDR ------------------------------- */

/**
 * 归一化 IP：去掉 IPv6 方括号、端口、IPv4 映射前缀，并拒绝非法输入。
 * @param {string} raw 原始 IP
 * @returns {string|null} 归一化结果
 */
export function normalizeIp(raw) {
  if (!raw) return null;
  let ip = String(raw).trim();
  if (ip.startsWith('[')) ip = ip.slice(1, ip.indexOf(']'));
  if (ip.includes(':') && ip.includes('.') && !ip.includes('::')) {
    // 形如 1.2.3.4:8080
    const lastColon = ip.lastIndexOf(':');
    const maybePort = ip.slice(lastColon + 1);
    if (/^\d+$/.test(maybePort) && ip.indexOf(':') === lastColon) ip = ip.slice(0, lastColon);
  }
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) ip = ip.slice(7);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    return ip.split('.').every((n) => Number(n) >= 0 && Number(n) <= 255) ? ip : null;
  }
  if (ip.includes(':')) return ip;
  return null;
}

/**
 * 将 IPv4/IPv6 转为 BigInt，便于网段位运算。
 * @param {string} ip 归一化后的 IP
 * @returns {{value: bigint, bits: number}|null}
 */
export function ipToBigInt(ip) {
  const v = normalizeIp(ip);
  if (!v) return null;
  if (v.includes('.')) {
    const p = v.split('.').map(Number);
    const value = (BigInt(p[0]) << 24n) | (BigInt(p[1]) << 16n) | (BigInt(p[2]) << 8n) | BigInt(p[3]);
    return { value, bits: 32 };
  }
  let s = v;
  if (s.includes('.')) {
    const idx = s.lastIndexOf(':');
    const p = s.slice(idx + 1).split('.').map(Number);
    s = `${s.slice(0, idx + 1)}${((p[0] << 8) | p[1]).toString(16)}:${((p[2] << 8) | p[3]).toString(16)}`;
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : null;
  const parts = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  if (parts.length !== 8) return null;
  let value = 0n;
  for (const part of parts) {
    const n = Number.parseInt(part || '0', 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null;
    value = (value << 16n) | BigInt(n);
  }
  return { value, bits: 128 };
}

/**
 * 判断 IP 是否落在指定 CIDR 内（支持单 IP 与网段，IPv4/IPv6 各自匹配）。
 * @param {string} ip 待判断 IP
 * @param {string} cidr 规则，如 `1.2.3.4`、`10.0.0.0/8`、`2001:db8::/32`
 * @returns {boolean}
 */
export function ipInCidr(ip, cidr) {
  const target = ipToBigInt(ip);
  if (!target) return false;
  const [base, prefixRaw] = String(cidr).split('/');
  const net = ipToBigInt(base);
  if (!net || net.bits !== target.bits) return false;
  const prefix = prefixRaw === undefined ? net.bits : Number.parseInt(prefixRaw, 10);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > net.bits) return false;
  const shift = BigInt(net.bits - prefix);
  return target.value >> shift === net.value >> shift;
}

/**
 * 掩码显示 IP，后台列表默认脱敏，避免日志二次泄露。
 * @param {string} ip IP
 * @returns {string}
 */
export function maskIp(ip) {
  if (!ip) return '-';
  if (ip.includes('.')) {
    const p = ip.split('.');
    return `${p[0]}.${p[1]}.*.*`;
  }
  return `${ip.slice(0, 10)}…`;
}

/* ------------------------------- 会话管理 ------------------------------- */

/**
 * 创建会话并返回会话 ID。
 * @param {'user'|'admin'} kind 会话类型
 * @param {string} ip 来源 IP
 * @param {string} ua User-Agent
 * @returns {string} 会话 ID
 */
export function createSession(kind, ip, ua) {
  const id = randomBytes(24).toString('hex');
  const t = now();
  db.prepare(
    `INSERT INTO sessions (id, kind, ip, ua, created_at, last_seen_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, kind, ip, String(ua || '').slice(0, 300), t, t, t + config.sessionDays * 86400);
  return id;
}

/**
 * 校验会话是否有效，并顺带刷新活跃时间。
 * @param {string} id 会话 ID
 * @param {'user'|'admin'} kind 期望的会话类型
 * @returns {object|null} 会话记录
 */
export function getSession(id, kind) {
  if (!id) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  if (!row || row.kind !== kind || row.expires_at < now()) return null;
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now(), id);
  return row;
}

/**
 * 销毁会话。
 * @param {string} id 会话 ID
 * @returns {void}
 */
export function destroySession(id) {
  if (id) db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

/* ---------------------------- 登录失败与限流 ---------------------------- */

/**
 * 统计窗口内某 IP 的失败次数。
 * @param {string} ip 来源 IP
 * @param {string} kind 会话类型
 * @param {number} windowSec 窗口秒数
 * @returns {number}
 */
export function recentFailures(ip, kind, windowSec) {
  const row = db
    .prepare('SELECT COUNT(*) AS c FROM auth_attempts WHERE ip = ? AND kind = ? AND success = 0 AND at > ?')
    .get(ip, kind, now() - windowSec);
  return row ? Number(row.c) : 0;
}

/**
 * 记录一次登录尝试。
 * @param {string} ip 来源 IP
 * @param {string} kind 会话类型
 * @param {boolean} success 是否成功
 * @returns {void}
 */
export function recordAttempt(ip, kind, success) {
  db.prepare('INSERT INTO auth_attempts (ip, kind, success, at) VALUES (?, ?, ?, ?)').run(
    ip,
    kind,
    success ? 1 : 0,
    now(),
  );
}

const buckets = new Map();

/**
 * 内存令牌桶限流（单进程足够，重启即重置）。
 * @param {string} key 限流维度
 * @param {number} capacity 桶容量
 * @param {number} refillPerSec 每秒补充令牌数
 * @returns {boolean} 是否放行
 */
export function takeToken(key, capacity, refillPerSec) {
  const t = Date.now();
  let b = buckets.get(key);
  if (!b) {
    b = { tokens: capacity, at: t };
    buckets.set(key, b);
  }
  b.tokens = Math.min(capacity, b.tokens + ((t - b.at) / 1000) * refillPerSec);
  b.at = t;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}

/**
 * 清理过期限流桶，防止内存无限增长。
 * @returns {void}
 */
export function sweepBuckets() {
  const t = Date.now();
  for (const [key, b] of buckets) {
    if (t - b.at > 30 * 60 * 1000 && b.tokens >= 1) buckets.delete(key);
  }
}

/**
 * 取真实客户端 IP：优先 Cloudflare 头，其次 Fastify 解析后的 req.ip。
 * @param {import('fastify').FastifyRequest} req 请求对象
 * @returns {string}
 */
export function clientIp(req) {
  // 仅在显式声明"流量必经 Cloudflare"时才信任该头，否则客户端可随意伪造 IP
  if (config.trustCfHeader) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf) return normalizeIp(cf) || cf;
  }
  return normalizeIp(req.ip) || '0.0.0.0';
}
