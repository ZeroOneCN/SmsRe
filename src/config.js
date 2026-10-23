/**
 * 运行配置：统一从环境变量 / .env 读取，集中校验与默认值。
 * 所有数值型配置在启动时一次性转换，避免运行期散落的 Number() 调用。
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// 优先加载项目根目录 .env；不存在时静默跳过（Docker 场景走环境变量）
const envFile = path.join(ROOT, '.env');
if (existsSync(envFile) && typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile(envFile);
  } catch {
    /* 忽略格式错误的 .env，交由必填校验兜底 */
  }
}

/**
 * 读取布尔型环境变量。
 * @param {string} key 变量名
 * @param {boolean} fallback 缺省值
 * @returns {boolean}
 */
function bool(key, fallback) {
  const raw = process.env[key];
  if (raw === undefined || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(raw).toLowerCase());
}

/**
 * 读取整数型环境变量。
 * @param {string} key 变量名
 * @param {number} fallback 缺省值
 * @returns {number}
 */
function int(key, fallback) {
  const raw = Number.parseInt(process.env[key] ?? '', 10);
  return Number.isFinite(raw) ? raw : fallback;
}

export const config = {
  port: int('PORT', 8080),
  host: process.env.HOST || '0.0.0.0',
  dataDir: path.resolve(ROOT, process.env.DATA_DIR || 'data'),
  // 反向代理（Nginx / Cloudflare）下必须开启，否则记录的 IP 全是代理地址
  trustProxy: bool('TRUST_PROXY', true),
  // 只有确定流量经过 Cloudflare 时才可信 CF-Connecting-IP，否则客户端可伪造 IP
  trustCfHeader: bool('TRUST_CF_HEADER', false),
  // 纯 HTTP 调试时设为 false，否则浏览器不会保存会话 Cookie
  cookieSecure: bool('COOKIE_SECURE', true),
  // 会话有效期（天）
  sessionDays: int('SESSION_DAYS', 30),
  // 验证码前台可见时长（秒）
  codeTtlSeconds: int('CODE_TTL_SECONDS', 600),
  // 设备超过该时长无短信/心跳则告警（分钟）
  offlineAlertMinutes: int('OFFLINE_ALERT_MINUTES', 15),
  // 可选：飞书/Bark/自建 webhook 告警地址
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  // 后台是否仅允许指定 IP（逗号分隔，支持 CIDR）
  adminAllowIps: (process.env.ADMIN_ALLOW_IPS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  // 首次启动时写入数据库的初始 PIN（之后以数据库为准）
  initPin: process.env.PIN || '',
  initAdminPin: process.env.ADMIN_PIN || '',
};
