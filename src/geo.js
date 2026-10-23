/**
 * 离线 IP 归属地：使用随包分发的 ip2region 本地库查询，不把访客 IP 发给任何第三方。
 */
import ip2region from 'ip2region';

const IP2Region = ip2region.default || ip2region;
let searcher = null;

/**
 * 查询 IP 归属信息，命中失败或异常时返回 null。
 * @param {string} ip IPv4 或 IPv6 地址
 * @returns {object|null} ip2region 原始结果
 */
function lookup(ip) {
  if (!ip) return null;
  try {
    if (!searcher) searcher = new IP2Region();
    return searcher.search(ip) || null;
  } catch {
    return null;
  }
}

/**
 * 查询 IP 归属地。
 * @param {string} ip IPv4 或 IPv6 地址
 * @returns {string} 如「广东省深圳市 · 阿里云」，内网返回「内网」，查不到返回「-」
 */
export function ipLocation(ip) {
  const r = lookup(ip);
  if (!r) return '-';
  const parts = [r.country, r.province, r.city].filter(Boolean);
  // 省、市同名时去重（如「阿姆斯特丹阿姆斯特丹」）
  const region = parts.filter((v, i) => parts.indexOf(v) === i).join('');
  if (!region || region === '内网IP') return '内网';
  return r.isp && r.isp !== '内网IP' ? `${region} · ${r.isp}` : region;
}

/**
 * 判断 IP 是否来自海外。
 * 内网、保留地址与查询失败一律视为国内放行，避免误拦本机、局域网设备与未收录 IP。
 * @param {string} ip IPv4 或 IPv6 地址
 * @returns {boolean} true 表示海外 IP
 */
export function isOverseas(ip) {
  const r = lookup(ip);
  if (!r) return false;
  const country = String(r.country || '').trim();
  if (!country || country === '0' || country === '内网IP') return false;
  return !country.includes('中国');
}
