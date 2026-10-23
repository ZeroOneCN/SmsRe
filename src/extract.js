/**
 * 验证码提取：从短信正文中定位 4–8 位数字，尽量避开金额、尾号、日期、订单号等干扰。
 * 纯函数实现，便于单元测试；不做任何网络请求。
 */

// 触发词：命中即视为"这里附近是验证码"
const KEYWORDS =
  /(验证码|驗證碼|校验码|校驗碼|确认码|確認碼|动态码|动态密码|安全码|激活码|提取码|口令|verification code|verification|verify|passcode|security code|one.?time|otp|\bcode\b)/gi;

// 强干扰词：出现在候选数字附近时说明这不是验证码
const STRONG_NOISE = /(尾号|卡号|账号|账户|订单|单号|积分|流量|电话|手机号|号码)/;
// 金额类干扰词：只在贴得很近时才算干扰（"支出1000元，验证码123456" 里的 元 不能误伤验证码）
const MONEY_NOISE = /(￥|¥|\$|元)/;

/**
 * 全角数字、全角冒号转半角，统一后续正则处理。
 * @param {string} text 原文
 * @returns {string}
 */
export function normalizeText(text) {
  return String(text ?? '')
    .replace(/[０-９]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0))
    .replace(/[：]/g, ':')
    .replace(/\u3000/g, ' ');
}

/**
 * 计算候选数字到最近触发词的距离（字符数）。
 * @param {number} start 候选起点
 * @param {number} end 候选终点
 * @param {Array<[number, number]>} ranges 触发词区间
 * @returns {number} 距离，未命中返回 Infinity
 */
function keywordDistance(start, end, ranges) {
  let best = Infinity;
  for (const [s, e] of ranges) {
    const d = start >= e ? start - e : end <= s ? s - end : 0;
    if (d < best) best = d;
  }
  return best;
}

/**
 * 从短信正文中提取验证码。
 * @param {string} raw 短信正文
 * @returns {{code: string|null, alternatives: string[], ambiguous: boolean, quality: 'keyword'|'fallback'|'none'}}
 */
export function extractCode(raw) {
  const text = normalizeText(raw);
  const ranges = [];
  for (const m of text.matchAll(KEYWORDS)) ranges.push([m.index, m.index + m[0].length]);

  const found = [];
  for (const m of text.matchAll(/(?<!\d)(\d{4,8})(?!\d)/g)) {
    const digits = m[1];
    const start = m.index;
    const end = start + digits.length;
    const ctx12 = text.slice(Math.max(0, start - 12), Math.min(text.length, end + 12));
    const ctx6 = text.slice(Math.max(0, start - 6), Math.min(text.length, end + 6));
    const next3 = text.slice(end, end + 3);

    // 金额：带小数点/千分位，或紧跟在货币符号后，直接排除
    if (/^\.\d{1,2}/.test(next3) || /^,\d{3}/.test(next3)) continue;
    if (/[￥¥$]\s*$/.test(text.slice(Math.max(0, start - 2), start))) continue;

    const dist = keywordDistance(start, end, ranges);
    if (STRONG_NOISE.test(ctx12) && dist > 15) continue;
    if (MONEY_NOISE.test(ctx6) && dist > 6) continue;

    // 年份、日期片段排除
    if (/^(19|20)\d\d$/.test(digits) && /(年|月|\/)/.test(ctx6)) continue;

    found.push({ digits, dist, start });
  }

  if (found.length === 0) return { code: null, alternatives: [], ambiguous: false, quality: 'none' };

  const keyed = found.filter((f) => f.dist <= 30).sort((a, b) => a.dist - b.dist || a.start - b.start);
  if (keyed.length > 0) {
    return {
      code: keyed[0].digits,
      alternatives: keyed.slice(1).map((f) => f.digits),
      ambiguous: keyed.length > 1,
      quality: 'keyword',
    };
  }

  const clean = found;
  if (clean.length === 1) {
    return { code: clean[0].digits, alternatives: [], ambiguous: false, quality: 'fallback' };
  }

  return { code: null, alternatives: [], ambiguous: false, quality: 'none' };
}
