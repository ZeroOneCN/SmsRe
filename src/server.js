/**
 * SMSFor 服务入口：接收转发短信 → 解析验证码 → SSE 推送到大屏 → 审计访问。
 * 设计原则：单进程、零外部依赖、默认关闭一切对外暴露面。
 */
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { createHash, randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { config, ROOT } from './config.js';
import { db, audit, getIntSetting, getSetting, setSetting } from './db.js';
import {
  clientIp,
  createSession,
  destroySession,
  getSession,
  hashPin,
  ipInCidr,
  ipToBigInt,
  maskIp,
  recentFailures,
  recordAttempt,
  sweepBuckets,
  takeToken,
  verifyPin,
} from './security.js';
import { extractCode } from './extract.js';

const now = () => Math.floor(Date.now() / 1000);
const ADMIN_COOKIE = 'asid';
// 16 位十六进制（64 位随机数）：足够抗猜解，又能完整显示在手机 App 的窄输入框里
const newToken = () => randomBytes(8).toString('hex');

/**
 * 枚举本机可用于局域网访问的地址，供后台生成手机端 Webhook 地址。
 * @returns {string[]} 形如 http://192.168.8.101:8080
 */
function lanBaseUrls() {
  const urls = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    if (/vmware|vethernet|loopback|virtual|docker/i.test(name)) continue;
    for (const nic of list || []) {
      if (nic.family === 'IPv4' && !nic.internal && !nic.address.startsWith('169.254.')) {
        urls.push(`http://${nic.address}:${config.port}`);
      }
    }
  }
  return urls;
}

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL || 'info' },
  trustProxy: config.trustProxy,
  bodyLimit: 64 * 1024,
  disableRequestLogging: true,
});

await app.register(fastifyCookie);
await app.register(fastifyStatic, {
  root: path.join(ROOT, 'public'),
  prefix: '/static/',
  wildcard: false,
});

/* ------------------------------ 初始化与配置 ------------------------------ */

/**
 * 首次启动的引导：写入 PIN 哈希、创建默认设备并打印 Token。
 * @returns {void}
 */
function bootstrap() {
  // 前台已改为无需 PIN 直接展示验证码，PIN 仅作为可选的历史兼容配置
  if (!getSetting('pin_hash') && config.initPin) {
    setSetting('pin_hash', hashPin(config.initPin));
  }
  if (!getSetting('admin_pin_hash')) {
    if (!config.initAdminPin) {
      console.error('[启动失败] 未配置 ADMIN_PIN。请参考 .env.example 补齐后重启。');
      process.exit(1);
    }
    setSetting('admin_pin_hash', hashPin(config.initAdminPin));
  }
  if (!getSetting('code_ttl_seconds')) setSetting('code_ttl_seconds', config.codeTtlSeconds);

  const count = db.prepare('SELECT COUNT(*) AS c FROM devices').get();
  if (!count || Number(count.c) === 0) {
    const token = newToken();
    db.prepare('INSERT INTO devices (name, token, created_at) VALUES (?, ?, ?)').run('sms-01', token, now());
    console.log('--------------------------------------------------------------');
    console.log('已创建默认设备 sms-01，转发器 Token（只显示这一次，请立即保存）：');
    console.log(`  ${token}`);
    console.log(`  Webhook 地址：https://你的域名/h/${token}`);
    console.log('--------------------------------------------------------------');
  }
}
bootstrap();

/* -------------------------------- IP 规则 -------------------------------- */

let ruleCache = { block: [], allow: [] };

/**
 * 重载 IP 规则缓存，规则变更或定时刷新时调用。
 * @returns {void}
 */
function reloadRules() {
  const t = now();
  const rows = db
    .prepare("SELECT * FROM ip_rules WHERE expires_at IS NULL OR expires_at > ?")
    .all(t);
  ruleCache = {
    block: rows.filter((r) => r.action === 'block'),
    allow: rows.filter((r) => r.action === 'allow'),
  };
}
reloadRules();

/**
 * 判断 IP 是否被拦截（allow 规则优先放行）。
 * @param {string} ip 客户端 IP
 * @returns {object|null} 命中的拦截规则
 */
function matchedBlock(ip) {
  if (ruleCache.allow.some((r) => ipInCidr(ip, r.cidr))) return null;
  return ruleCache.block.find((r) => ipInCidr(ip, r.cidr)) || null;
}

/**
 * 记录被拦截访问，同一 IP 每分钟最多记一条，避免刷库。
 * @param {string} ip 客户端 IP
 * @param {string} ua User-Agent
 * @returns {void}
 */
function logBlocked(ip, ua) {
  const t = now();
  const seen = db.prepare('SELECT at FROM blocked_seen WHERE ip = ?').get(ip);
  if (seen && t - Number(seen.at) < 60) return;
  db.prepare('INSERT INTO blocked_seen (ip, at) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET at = excluded.at').run(
    ip,
    t,
  );
  db.prepare('INSERT INTO views (ip, ua, result, viewed_at) VALUES (?, ?, ?, ?)').run(
    ip,
    String(ua || '').slice(0, 300),
    'blocked',
    t,
  );
}

/* --------------------------------- 告警 --------------------------------- */

/**
 * 触发一次告警。支持飞书机器人与通用 webhook（Bark / 自建服务）。
 * @param {string} title 标题
 * @param {string} text 正文
 * @returns {Promise<void>}
 */
async function sendAlert(title, text) {
  if (!config.alertWebhookUrl) {
    app.log.warn({ title, text }, '未配置 ALERT_WEBHOOK_URL，告警仅记录日志');
    return;
  }
  const isFeishu = config.alertWebhookUrl.includes('open.feishu.cn');
  const body = isFeishu
    ? { msg_type: 'text', content: { text: `【SMSFor】${title}\n${text}` } }
    : { title: `SMSFor ${title}`, body: text, text: `${title}\n${text}` };
  try {
    await fetch(config.alertWebhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
  } catch (err) {
    app.log.error({ err }, '告警发送失败');
  }
}

/* --------------------------------- SSE ---------------------------------- */

const sseClients = new Set();

/**
 * 向所有已连接的大屏推送事件。
 * @param {string} event 事件名
 * @param {object} data 数据
 * @returns {void}
 */
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.raw.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

/**
 * 取当前仍在有效期内的最新验证码。
 * @returns {object|null}
 */
function currentMessage() {
  return (
    db
      .prepare("SELECT * FROM messages WHERE status = 'active' AND expires_at > ? ORDER BY received_at DESC, id DESC LIMIT 1")
      .get(now()) || null
  );
}

/**
 * 组装返回给前台的验证码结构（绝不包含来源、原文等字段）。
 * @param {object|null} msg 消息行
 * @returns {object}
 */
function publicMessage(msg) {
  if (!msg) return { code: null, receivedAt: null, expiresAt: null, now: now() };
  return {
    id: msg.id,
    code: msg.code,
    receivedAt: msg.received_at,
    expiresAt: msg.expires_at,
    now: now(),
    ambiguous: msg.candidates ? JSON.parse(msg.candidates).length > 1 : false,
    alternatives: msg.candidates ? JSON.parse(msg.candidates).slice(1) : [],
  };
}

/* ------------------------------- 通用钩子 ------------------------------- */

app.addHook('onRequest', async (req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('X-Robots-Tag', 'noindex, nofollow, noarchive');
  reply.header(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  );
  // 健康检查放行，其余请求（含转发器）一律先过 IP 规则
  if (req.url === '/healthz') return;

  const ip = clientIp(req);
  // 已登录后台的会话始终放行，防止误拉黑自己的 IP 后无法进入后台解封
  const isAdmin = getSession(req.cookies?.[ADMIN_COOKIE], 'admin');
  const rule = isAdmin ? null : matchedBlock(ip);
  if (rule) {
    db.prepare('UPDATE ip_rules SET hits = hits + 1 WHERE id = ?').run(rule.id);
    logBlocked(ip, req.headers['user-agent']);
    return reply.code(403).type('text/plain').send('Forbidden');
  }
});

// 页面与接口都不缓存：验证码页面必须实时，页面更新后也不该被旧缓存顶替。
// 放在 onSend 是为了覆盖 sendFile 写入的默认 Cache-Control。
app.addHook('onSend', async (req, reply) => {
  const page = req.url === '/' || req.url === '/screen' || req.url === '/admin';
  if (page || req.url.startsWith('/api/') || req.url.startsWith('/admin/api/')) {
    reply.header('Cache-Control', 'no-store');
  }
});

app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
  done(null, Object.fromEntries(new URLSearchParams(String(body))));
});

/* --------------------------------- 页面 --------------------------------- */

app.get('/', async (_req, reply) => reply.sendFile('index.html'));
app.get('/screen', async (_req, reply) => reply.sendFile('screen.html'));
app.get('/admin', async (_req, reply) => reply.sendFile('admin.html'));
app.get('/favicon.ico', async (_req, reply) => reply.code(204).send());
app.get('/healthz', async () => ({ ok: true }));

// 记录走错路径的请求，方便排查手机端填错地址
app.setNotFoundHandler((req, reply) => {
  app.log.warn({ ip: clientIp(req), method: req.method, path: req.url }, '404：请求路径不存在');
  return reply.code(404).type('text/plain; charset=utf-8').send('not found');
});

/* ------------------------------ 接收短信 -------------------------------- */

/**
 * 校验设备 Token 并返回设备记录。
 * @param {string} token 设备 Token
 * @returns {object|null}
 */
function deviceByToken(token) {
  if (!token) return null;
  const row = db.prepare('SELECT * FROM devices WHERE token = ? AND enabled = 1').get(String(token));
  return row || null;
}

/**
 * 处理来自转发器的短信上报，/hook 与 /h 两个路径共用。
 * @param {object} req 请求
 * @param {object} reply 响应
 * @returns {Promise<void>}
 */
async function handleHook(req, reply) {
  const ip = clientIp(req);
  // 先按 IP 限流：Token 校验前就挡住刷量请求，避免伪造 Token 刷日志、消耗 CPU/数据库
  if (!takeToken(`hook-ip:${ip}`, 20, 2)) {
    app.log.warn({ ip }, '转发失败：IP 限流');
    return reply.code(429).type('text/plain').send('too many requests');
  }

  const token = String(req.params.token || '');
  const device = deviceByToken(token);
  if (!device) {
    app.log.warn({ ip, path: req.url, tokenLength: token.length }, '转发失败：Token 无效或设备已停用');
    return reply.code(403).type('text/plain').send('invalid token');
  }

  // 单设备限流：容量 3，每秒补充 2 个令牌，防止被当成公开接口刷
  if (!takeToken(`hook:${device.id}`, 3, 2)) {
    app.log.warn({ ip, device: device.name }, '转发失败：触发限流');
    return reply.code(429).type('text/plain').send('too many requests');
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const rawText =
    body.text || body.msg || body.content || body.message || (typeof req.body === 'string' ? req.body : '');
  const from = body.from || body.sender || body.phone || '';
  if (!rawText) {
    app.log.warn({ ip, device: device.name, keys: Object.keys(body) }, '转发失败：请求体里没有短信内容');
    return reply.code(400).type('text/plain').send('missing text');
  }

  const t = now();
  const { code, alternatives, ambiguous, quality } = extractCode(rawText);
  const ttl = getIntSetting('code_ttl_seconds', config.codeTtlSeconds);
  const dedupe = createHash('sha256')
    .update(`${device.id}|${code ?? ''}|${rawText.slice(0, 64)}|${Math.floor(t / 60)}`)
    .digest('hex');

  const status = quality === 'none' ? 'dropped' : 'active';
  const insert = db.prepare(
    `INSERT OR IGNORE INTO messages
       (device_id, code, code_hash, candidates, sender_tag, sender, raw_text, received_at, expires_at, dedupe_key, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const result = insert.run(
    device.id,
    status === 'active' ? code : null,
    code ? createHash('sha256').update(code).digest('hex').slice(0, 32) : null,
    ambiguous ? JSON.stringify([code, ...alternatives]) : null,
    from ? createHash('sha256').update(String(from)).digest('hex').slice(0, 16) : null,
    String(from || '').slice(0, 120),
    String(rawText).slice(0, 2000),
    t,
    t + ttl,
    dedupe,
    status,
  );

  db.prepare('UPDATE devices SET last_message_at = ? WHERE id = ?').run(t, device.id);

  if (Number(result.changes) > 0 && status === 'active') {
    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(result.lastInsertRowid);
    broadcast('code', publicMessage(msg));
  }
  app.log.info({ device: device.name, quality, hasCode: Boolean(code), ambiguous }, '短信已接收');
  // 部分转发 App 只把 200 视为成功，这里返回 200 + 明确文本，兼容性最好
  return reply.code(200).type('text/plain').send('success');
}

// /h/ 为短地址，方便在手机 App 的窄输入框里完整显示；/hook/ 保留兼容
app.post('/hook/:token', handleHook);
app.post('/h/:token', handleHook);

// 用手机浏览器直接打开该地址即可自检：能打开说明网络与 Token 都正确
for (const p of ['/h/:token', '/hook/:token']) {
  app.get(p, async (req, reply) => {
    const device = deviceByToken(req.params.token);
    if (!device) return reply.code(403).type('text/plain; charset=utf-8').send('Token 无效或设备已停用');
    return reply
      .type('text/plain; charset=utf-8')
      .send(`转发地址有效，设备：${device.name}\n请让转发 App 以 POST 方式上报短信。`);
  });
}

app.post('/api/heartbeat/:token', async (req, reply) => {
  const device = deviceByToken(req.params.token);
  if (!device) return reply.code(403).send();
  db.prepare('UPDATE devices SET last_heartbeat_at = ? WHERE id = ?').run(now(), device.id);
  return reply.code(204).send();
});

/* -------------------------------- 鉴权 ---------------------------------- */

/**
 * 校验后台会话，未通过时直接回写 401。
 * @param {import('fastify').FastifyRequest} req 请求
 * @param {import('fastify').FastifyReply} reply 响应
 * @returns {object|null} 会话
 */
function requireSession(req, reply) {
  const session = getSession(req.cookies[ADMIN_COOKIE], 'admin');
  if (!session) {
    reply.code(401).send({ ok: false, error: 'unauthorized' });
    return null;
  }
  return session;
}

app.post('/api/auth', async (req, reply) => {
  // 前台已无需登录，这里只处理后台管理会话
  const kind = 'admin';
  const ip = clientIp(req);
  const pin = String(req.body?.pin ?? '').trim();
  const ua = req.headers['user-agent'];

  if (!pin || pin.length > 32) return reply.code(400).send({ ok: false, error: 'invalid' });

  if (recentFailures(ip, kind, 900) >= 5) {
    db.prepare('INSERT INTO views (ip, ua, result, viewed_at) VALUES (?, ?, ?, ?)').run(
      ip,
      String(ua || '').slice(0, 300),
      'denied',
      now(),
    );
    return reply.code(429).send({ ok: false, error: 'locked', retryAfter: 900 });
  }

  const okPin = verifyPin(pin, getSetting('admin_pin_hash'));
  recordAttempt(ip, kind, okPin);

  if (!okPin) {
    if (recentFailures(ip, kind, 900) === 5) {
      await sendAlert('登录失败告警', `IP ${maskIp(ip)} 连续 5 次输入错误的后台 PIN，已锁定 15 分钟。`);
    }
    await new Promise((r) => setTimeout(r, 300));
    return reply.code(401).send({ ok: false, error: 'bad_pin' });
  }

  const sid = createSession(kind, ip, ua);
  reply.setCookie(ADMIN_COOKIE, sid, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
    maxAge: config.sessionDays * 86400,
  });
  return { ok: true, kind };
});

app.post('/api/auth/logout', async (req, reply) => {
  destroySession(req.cookies[ADMIN_COOKIE]);
  reply.clearCookie(ADMIN_COOKIE, { path: '/' });
  return { ok: true };
});

/* -------------------------------- 前台 ---------------------------------- */

app.get('/api/me', async (req) => ({
  admin: Boolean(getSession(req.cookies[ADMIN_COOKIE], 'admin')),
}));

app.get('/api/latest', async (req, reply) => {
  const ip = clientIp(req);
  // 公开接口：按 IP 做基础限流，防止被脚本高频抓取
  if (!takeToken(`latest:${ip}`, 30, 1)) return reply.code(429).send({ error: 'too_many_requests' });

  const msg = currentMessage();
  db.prepare('INSERT INTO views (message_id, ip, ua, result, viewed_at) VALUES (?, ?, ?, ?, ?)').run(
    msg ? msg.id : null,
    ip,
    String(req.headers['user-agent'] || '').slice(0, 300),
    'success',
    now(),
  );
  return publicMessage(msg);
});

app.post('/api/dwell', async (req, reply) => {
  const ms = Number(req.body?.ms);
  const view = db
    .prepare('SELECT id FROM views WHERE ip = ? ORDER BY id DESC LIMIT 1')
    .get(clientIp(req));
  if (view && Number.isFinite(ms) && ms > 0 && ms < 24 * 3600 * 1000) {
    db.prepare('UPDATE views SET dwell_ms = ? WHERE id = ?').run(Math.round(ms), view.id);
  }
  return reply.code(204).send();
});

app.get('/api/stream', async (req, reply) => {
  if (sseClients.size >= 200) return reply.code(503).send({ error: 'too_many_clients' });

  reply.hijack();
  reply.raw.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-store',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  reply.raw.write('retry: 3000\n\n');
  reply.raw.write(`event: code\ndata: ${JSON.stringify(publicMessage(currentMessage()))}\n\n`);

  const client = { raw: reply.raw };
  sseClients.add(client);
  const heartbeat = setInterval(() => {
    try {
      reply.raw.write(': ping\n\n');
    } catch {
      clearInterval(heartbeat);
    }
  }, 25000);

  req.raw.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(client);
  });
});

/* -------------------------------- 后台 ---------------------------------- */

/**
 * 后台接口统一鉴权 + 可选 IP 白名单。
 * @param {import('fastify').FastifyRequest} req 请求
 * @param {import('fastify').FastifyReply} reply 响应
 * @returns {object|null}
 */
function requireAdmin(req, reply) {
  if (config.adminAllowIps.length > 0) {
    const ip = clientIp(req);
    if (!config.adminAllowIps.some((cidr) => ipInCidr(ip, cidr))) {
      reply.code(403).send({ ok: false, error: 'ip_not_allowed' });
      return null;
    }
  }
  return requireSession(req, reply, 'admin');
}

app.get('/admin/api/overview', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const t = now();
  // 以北京时间 0 点为统计起点
  const start = t - ((t + 8 * 3600) % 86400);

  const one = (sql, ...args) => Number(db.prepare(sql).get(...args)?.c ?? 0);
  return {
    today: {
      views: one('SELECT COUNT(*) AS c FROM views WHERE viewed_at >= ?', start),
      uniqueIps: one('SELECT COUNT(DISTINCT ip) AS c FROM views WHERE viewed_at >= ?', start),
      denied: one("SELECT COUNT(*) AS c FROM views WHERE viewed_at >= ? AND result = 'denied'", start),
      blocked: one("SELECT COUNT(*) AS c FROM views WHERE viewed_at >= ? AND result = 'blocked'", start),
      messages: one('SELECT COUNT(*) AS c FROM messages WHERE received_at >= ?', start),
      dropped: one("SELECT COUNT(*) AS c FROM messages WHERE received_at >= ? AND status = 'dropped'", start),
    },
    online: one('SELECT COUNT(*) AS c FROM sessions WHERE kind = ? AND last_seen_at > ?', 'user', t - 300),
    onlineAdmin: one('SELECT COUNT(*) AS c FROM sessions WHERE kind = ? AND last_seen_at > ?', 'admin', t - 900),
    streams: sseClients.size,
    devices: db.prepare('SELECT * FROM devices ORDER BY id').all().map((d) => ({
      id: d.id,
      name: d.name,
      enabled: Boolean(d.enabled),
      lastHeartbeatAt: d.last_heartbeat_at,
      lastMessageAt: d.last_message_at,
      online: Boolean((d.last_heartbeat_at || d.last_message_at || 0) > t - config.offlineAlertMinutes * 60),
      tokenMasked: `${String(d.token).slice(0, 6)}…${String(d.token).slice(-4)}`,
    })),
    codeTtlSeconds: getIntSetting('code_ttl_seconds', config.codeTtlSeconds),
    current: publicMessage(currentMessage()),
    serverTime: t,
  };
});

app.get('/admin/api/stats', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const days = Math.min(Math.max(Number(req.query?.days) || 7, 1), 30);
  const start = now() - days * 86400;
  const rows = db
    .prepare(
      `SELECT strftime('%Y-%m-%d', viewed_at, 'unixepoch', 'localtime') AS day,
              COUNT(*) AS views,
              COUNT(DISTINCT ip) AS ips,
              SUM(CASE WHEN result <> 'success' THEN 1 ELSE 0 END) AS fails
         FROM views WHERE viewed_at >= ? GROUP BY day ORDER BY day`,
    )
    .all(start);
  return { days, rows };
});

app.get('/admin/api/views', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const limit = Math.min(Math.max(Number(req.query?.limit) || 50, 1), 200);
  const offset = Math.max(Number(req.query?.offset) || 0, 0);
  const ip = String(req.query?.ip || '').trim();
  const result = String(req.query?.result || '').trim();

  const where = [];
  const params = [];
  if (ip) {
    where.push('ip LIKE ?');
    params.push(`%${ip}%`);
  }
  if (['success', 'denied', 'blocked'].includes(result)) {
    where.push('result = ?');
    params.push(result);
  }
  const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = db.prepare(`SELECT COUNT(*) AS c FROM views ${sqlWhere}`).get(...params);
  const rows = db
    .prepare(`SELECT * FROM views ${sqlWhere} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset);

  return {
    total: Number(total?.c || 0),
    items: rows.map((r) => ({
      id: r.id,
      time: r.viewed_at,
      ip: maskIp(r.ip),
      ipFull: r.ip,
      ua: r.ua,
      result: r.result,
      messageId: r.message_id,
      dwellMs: r.dwell_ms,
      session: r.session_id ? `${String(r.session_id).slice(0, 8)}…` : null,
    })),
  };
});

app.get('/admin/api/ip-rules', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  return {
    items: db.prepare('SELECT * FROM ip_rules ORDER BY id DESC').all().map((r) => ({
      id: r.id,
      cidr: r.cidr,
      action: r.action,
      note: r.note,
      hits: r.hits,
      expiresAt: r.expires_at,
      createdAt: r.created_at,
    })),
  };
});

app.post('/admin/api/ip-rules', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const cidr = String(req.body?.cidr || '').trim();
  const action = req.body?.action === 'allow' ? 'allow' : 'block';
  const note = String(req.body?.note || '').slice(0, 200);
  const ttlHours = Number(req.body?.ttlHours) || 0;

  if (!cidr || cidr.length > 64) {
    return reply.code(400).send({ ok: false, error: 'invalid_cidr' });
  }
  const [base, prefixRaw] = cidr.split('/');
  const baseInfo = ipToBigInt(base);
  const prefix = prefixRaw === undefined ? null : Number.parseInt(prefixRaw, 10);
  const validPrefix = prefix === null || (Number.isFinite(prefix) && prefix >= 0 && prefix <= baseInfo?.bits);
  if (!baseInfo || !validPrefix) {
    return reply.code(400).send({ ok: false, error: 'invalid_cidr' });
  }
  const t = now();
  const info = db
    .prepare('INSERT INTO ip_rules (cidr, action, note, hits, expires_at, created_at) VALUES (?, ?, ?, 0, ?, ?)')
    .run(cidr, action, note, ttlHours > 0 ? t + ttlHours * 3600 : null, t);
  reloadRules();
  audit('admin', 'ip_rule_add', { cidr, action, note, ttlHours });
  return { ok: true, id: info.lastInsertRowid };
});

app.delete('/admin/api/ip-rules/:id', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  db.prepare('DELETE FROM ip_rules WHERE id = ?').run(Number(req.params.id));
  reloadRules();
  audit('admin', 'ip_rule_del', { id: req.params.id });
  return { ok: true };
});

app.get('/admin/api/devices', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  return {
    // 局域网访问地址：后台若通过 127.0.0.1 打开，手机端需要换成这些地址
    lanUrls: lanBaseUrls(),
    items: db.prepare('SELECT * FROM devices ORDER BY id').all().map((d) => ({
      id: d.id,
      name: d.name,
      enabled: Boolean(d.enabled),
      token: d.token,
      lastHeartbeatAt: d.last_heartbeat_at,
      lastMessageAt: d.last_message_at,
    })),
  };
});

app.post('/admin/api/devices/:id/rotate', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const id = Number(req.params.id);
  const token = newToken();
  db.prepare('UPDATE devices SET token = ? WHERE id = ?').run(token, id);
  audit('admin', 'device_rotate', { id });
  return { ok: true, token };
});

app.post('/admin/api/devices/:id/toggle', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const id = Number(req.params.id);
  const row = db.prepare('SELECT enabled FROM devices WHERE id = ?').get(id);
  if (!row) return reply.code(404).send({ ok: false });
  db.prepare('UPDATE devices SET enabled = ? WHERE id = ?').run(row.enabled ? 0 : 1, id);
  audit('admin', 'device_toggle', { id, enabled: !row.enabled });
  return { ok: true, enabled: Boolean(!row.enabled) };
});

app.get('/admin/api/messages', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const limit = Math.min(Math.max(Number(req.query?.limit) || 30, 1), 200);
  const rows = db
    .prepare(
      `SELECT id, device_id, code, code_hash, sender, raw_text, received_at, expires_at, status
         FROM messages ORDER BY id DESC LIMIT ?`,
    )
    .all(limit);
  return {
    items: rows.map((r) => ({
      id: r.id,
      deviceId: r.device_id,
      code: r.status === 'active' ? r.code : null,
      codeHash: r.code_hash,
      sender: r.sender,
      rawText: r.raw_text,
      receivedAt: r.received_at,
      expiresAt: r.expires_at,
      status: r.status,
    })),
  };
});

/**
 * 修改后台 PIN：需要当前 PIN 二次确认，避免会话被盗后直接改口令。
 */
app.post('/admin/api/pin', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  const current = String(req.body?.current || '');
  const next = String(req.body?.next || '');

  if (!verifyPin(current, getSetting('admin_pin_hash'))) {
    return reply.code(403).send({ ok: false, error: 'bad_pin' });
  }
  if (!/^\d{4,8}$/.test(next)) return reply.code(400).send({ ok: false, error: 'invalid_pin' });

  setSetting('admin_pin_hash', hashPin(next));
  audit('admin', 'pin_change', { kind: 'admin' });
  return { ok: true };
});

app.delete('/admin/api/messages', async (req, reply) => {
  const session = requireAdmin(req, reply);
  if (!session) return;
  db.prepare('DELETE FROM messages').run();
  audit('admin', 'message_clear', {});
  broadcast('code', publicMessage(null));
  return { ok: true };
});

/* ------------------------------- 后台任务 ------------------------------- */

setInterval(() => {
  const t = now();
  const stale = db.prepare("SELECT COUNT(*) AS c FROM messages WHERE status = 'active' AND expires_at <= ?").get(t);
  if (Number(stale?.c || 0) > 0) {
    db.prepare("UPDATE messages SET status = 'expired', code = NULL WHERE status = 'active' AND expires_at <= ?").run(t);
    broadcast('code', publicMessage(currentMessage()));
  }
  sweepBuckets();
}, 15000).unref();

setInterval(() => {
  const t = now();
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(t);
  db.prepare('DELETE FROM auth_attempts WHERE at < ?').run(t - 7 * 86400);
  db.prepare('DELETE FROM blocked_seen WHERE at < ?').run(t - 86400);
  db.prepare("DELETE FROM messages WHERE status = 'expired' AND received_at < ?").run(t - 30 * 86400);
}, 60 * 60 * 1000).unref();

setInterval(async () => {
  const t = now();
  for (const d of db.prepare('SELECT * FROM devices WHERE enabled = 1').all()) {
    // 只有配置了心跳的设备才做离线判断，否则平时没有短信会误报
    const last = Number(d.last_heartbeat_at || 0);
    if (!last) continue;
    const overdue = t - last > config.offlineAlertMinutes * 60;
    const quiet = !d.last_alert_at || t - Number(d.last_alert_at) > 3600;
    if (overdue && quiet) {
      db.prepare('UPDATE devices SET last_alert_at = ? WHERE id = ?').run(t, d.id);
      await sendAlert(
        '转发器离线',
        `设备「${d.name}」已 ${Math.round((t - last) / 60)} 分钟没有心跳，请检查手机是否被系统清理。`,
      );
    }
  }
  reloadRules();
}, 60 * 1000).unref();

/* -------------------------------- 启动 ---------------------------------- */

try {
  await app.listen({ port: config.port, host: config.host });
  app.log.info(`SMSFor 已启动：http://${config.host}:${config.port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
