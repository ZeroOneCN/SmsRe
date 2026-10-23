/**
 * 安全模块单元测试：IP 归一化、CIDR 匹配、PIN 哈希。
 * 通过临时 DATA_DIR 隔离测试数据库，避免污染开发数据。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync } from 'node:fs';

process.env.DATA_DIR = mkdtempSync(path.join(os.tmpdir(), 'smsfor-test-'));
const { ipInCidr, normalizeIp, ipToBigInt, hashPin, verifyPin, maskIp } = await import('../src/security.js');

test('IP 归一化', () => {
  assert.equal(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeIp('[2001:db8::1]:443'), '2001:db8::1');
  assert.equal(normalizeIp('999.1.1.1'), null);
});

test('IPv4 CIDR 匹配', () => {
  assert.equal(ipInCidr('1.2.3.4', '1.2.3.0/24'), true);
  assert.equal(ipInCidr('1.2.4.4', '1.2.3.0/24'), false);
  assert.equal(ipInCidr('10.0.0.9', '10.0.0.9'), true);
  assert.equal(ipInCidr('10.0.0.9', '10.0.0.0/33'), false);
});

test('IPv6 CIDR 匹配', () => {
  assert.equal(ipInCidr('2001:db8::5', '2001:db8::/32'), true);
  assert.equal(ipInCidr('2001:db9::5', '2001:db8::/32'), false);
  assert.equal(ipInCidr('::1', '::1'), true);
  assert.equal(ipInCidr('1.2.3.4', '2001:db8::/32'), false);
});

test('IPv6 转 BigInt 长度正确', () => {
  assert.equal(ipToBigInt('::1').value, 1n);
  assert.equal(ipToBigInt('::').value, 0n);
});

test('PIN 哈希可验证且不可逆', () => {
  const h = hashPin('246810');
  assert.equal(verifyPin('246810', h), true);
  assert.equal(verifyPin('246811', h), false);
  assert.ok(!h.includes('246810'));
});

test('IP 脱敏', () => {
  assert.equal(maskIp('1.2.3.4'), '1.2.*.*');
  assert.equal(maskIp('2001:db8::1'), '2001:db8::…');
  assert.equal(maskIp(''), '-');
});
