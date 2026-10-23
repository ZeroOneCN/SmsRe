/**
 * 离线 IP 归属地：使用随包分发的 ip2region 本地库查询，不把访客 IP 发给任何第三方。
 */
import ip2region from 'ip2region';

const IP2Region = ip2region.default || ip2region;
let searcher = null;

/**
 * 查询 IP 归属地。
 * @param {string} ip IPv4 或 IPv6 地址
 * @returns {string} 如「广东省深圳市 · 阿里云」，内网返回「内网」，查不到返回「-」
 */
export function ipLocation(ip) {
  if (!ip) return '-';
  try {
    if (!searcher) searcher = new IP2Region();
    const r = searcher.search(ip);
    if (!r) return '-';
    const parts = [r.country, r.province, r.city].filter(Boolean);
    // 省、市同名时去重（如「阿姆斯特丹阿姆斯特丹」）
    const region = parts.filter((v, i) => parts.indexOf(v) === i).join('');
    if (!region || region === '内网IP') return '内网';
    return r.isp && r.isp !== '内网IP' ? `${region} · ${r.isp}` : region;
  } catch {
    return '-';
  }
}
