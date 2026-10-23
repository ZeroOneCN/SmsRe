/**
 * 验证码提取单元测试：覆盖正常、干扰、歧义与无结果四类场景。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractCode, normalizeText } from '../src/extract.js';

test('全角数字归一化', () => {
  assert.equal(normalizeText('１２３４５６'), '123456');
});

test('Apple 中文短信', () => {
  const r = extractCode('您的 Apple ID 验证码为：123456。请勿与他人共享。');
  assert.equal(r.code, '123456');
  assert.equal(r.quality, 'keyword');
});

test('Apple 英文短信', () => {
  const r = extractCode("Your Apple ID code is: 556677. Don't share it with anyone.");
  assert.equal(r.code, '556677');
});

test('银行短信：尾号与金额不干扰', () => {
  const r = extractCode('【某某银行】您尾号1234的储蓄卡于10月22日支出1000.00元，验证码123456，请勿泄露。');
  assert.equal(r.code, '123456');
});

test('4 位验证码', () => {
  const r = extractCode('验证码 8317，5分钟内有效。');
  assert.equal(r.code, '8317');
});

test('订单号与日期不会被误判', () => {
  assert.equal(extractCode('【京东】订单号20241022123456789已签收，感谢您的支持。').code, null);
  assert.equal(extractCode('会议时间 10月22日 12:30，地点 A 座。').code, null);
});

test('短信无数字时返回空', () => {
  const r = extractCode('您好，您的快递已放至前台。');
  assert.equal(r.code, null);
  assert.equal(r.quality, 'none');
});

test('多个候选时标记歧义并给出备选', () => {
  const r = extractCode('验证码123456，备用码654321。');
  assert.equal(r.code, '123456');
  assert.equal(r.ambiguous, true);
  assert.ok(r.alternatives.includes('654321'));
});

test('无触发词但只有一个干净数字时仍可提取', () => {
  const r = extractCode('请使用 902144 完成登录。');
  assert.equal(r.code, '902144');
  assert.equal(r.quality, 'fallback');
});
