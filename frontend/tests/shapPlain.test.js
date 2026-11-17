import { test } from 'node:test';
import assert from 'node:assert/strict';
import { plainShapItem, shapContext, shapStrength } from '../src/lib/shapPlain.js';

const ctx = shapContext({ host: 'evn-thanhtoan-tiendien.top', embedded_urls: [] });

test('plain sentences use the real values of this link and contain no technical jargon', () => {
  const tld = plainShapItem({ feature: 'is_suspicious_tld', value: 1, shapValue: 2.42, direction: 'risk' }, ctx);
  assert.match(tld.text, /"\.top"/);
  const hy = plainShapItem({ feature: 'n_hyphens_host', value: 2, shapValue: 1.05, direction: 'risk' }, ctx);
  assert.match(hy.text, /2 dấu gạch ngang/);
  for (const t of [tld.text, hy.text]) {
    assert.doesNotMatch(t, /log-odds|SHAP|TLD|entropy|hostname|feature/i);
  }
});

test('0/1 flags describe the fact, and contradictory signs are flagged as inconsistent', () => {
  const https = plainShapItem({ feature: 'scheme_is_https', value: 1, shapValue: -0.4, direction: 'benign' }, ctx);
  assert.match(https.text, /HTTPS/);
  assert.equal(https.consistent, true);
  const odd = plainShapItem({ feature: 'scheme_is_https', value: 1, shapValue: 0.3, direction: 'risk' }, ctx);
  assert.equal(odd.consistent, false);
  const noKw = plainShapItem({ feature: 'phishing_keyword_count', value: 0, shapValue: -0.2, direction: 'benign' }, ctx);
  assert.match(noKw.text, /không có từ/);
});

test('strength is words + level, never a number', () => {
  assert.deepEqual(shapStrength(2.4), { level: 3, text: 'Ảnh hưởng nhiều' });
  assert.deepEqual(shapStrength(-0.5), { level: 2, text: 'Ảnh hưởng vừa' });
  assert.deepEqual(shapStrength(0.1), { level: 1, text: 'Ảnh hưởng ít' });
});

test('unknown features fall back to the backend label in a plain sentence', () => {
  const r = plainShapItem({ feature: 'future_feature_x', label: 'Một đặc điểm mới', value: 3, shapValue: 0.5, direction: 'risk' }, ctx);
  assert.equal(r.text, 'Một đặc điểm mới khiến AI nghi ngờ hơn.');
});
