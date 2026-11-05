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

test('非 Apple 来源：社交与购物验证码', () => {
  assert.equal(extractCode('【腾讯科技】您的微信登录验证码为123456，5分钟内有效。').code, '123456');
  assert.equal(extractCode('【淘宝】验证码 654321，您正在登录，请勿向他人泄露。').code, '654321');
});

test('非 Apple 来源：支付与银行验证码', () => {
  assert.equal(extractCode('【某银行】消费100.00元，验证码为123456，尾号8888。').code, '123456');
  assert.equal(extractCode('【某支付】验证码 4321，银行卡尾号 8888。').code, '4321');
});

test('非 Apple 来源：国际服务英文模板', () => {
  assert.equal(extractCode('G-123456 is your Google verification code.').code, '123456');
  assert.equal(extractCode('Use 123456 as your Microsoft account security code.').code, '123456');
});

test('非 Apple 触发词：登录码/认证码/授权码/密码类', () => {
  assert.equal(extractCode('【某App】您的登录码为 123456，账号尾号 8888，请勿泄露。').code, '123456');
  assert.equal(extractCode('【某服务】认证码 123456，设备编号 88888888。').code, '123456');
  assert.equal(extractCode('【某平台】您的授权码是 123456，订单编号 202410221234。').code, '123456');
  assert.equal(extractCode('【某银行】登录密码 123456，账户尾号 8888。').code, '123456');
  assert.equal(extractCode('【某服务】短信密码为 123456，手机号 13800138000。').code, '123456');
});

test('营销短信不因「验证」字样误报', () => {
  assert.equal(extractCode('【某商城】完成验证即可领券，活动编号 20241022，客服 88888888。').code, null);
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
