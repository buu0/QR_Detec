/**
 * Static guards over the frontend source: wording rules, XSS-safe rendering, no auto-navigation,
 * no sensitive caching in the PWA config, no third-party font/script loads.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const sources = walk(join(root, 'src')).filter((p) => /\.(jsx?|css)$/.test(p));
const read = (p) => readFileSync(p, 'utf8');

test('no misleading "safe" wording anywhere in the UI source', () => {
  const forbidden = [
    { re: /['">]\s*An toàn\s*['"<(]/, why: '"An toàn" used as a label' },
    { re: /\bSAFE\b/, why: '"SAFE" label' },
    { re: /100\s*%/, why: '"100%" claim' },
    { re: /đã xác thực|được xác thực/i, why: '"xác thực" claim' },
    { re: /đã kiểm tra sạch/i, why: '"Đã kiểm tra sạch"' },
  ];
  for (const file of sources.filter((p) => /\.jsx?$/.test(p))) {
    const text = read(file);
    for (const { re, why } of forbidden) {
      assert.doesNotMatch(text, re, `${file}: ${why}`);
    }
    // "an toàn tuyệt đối" may only appear in a negated sentence ("không ... an toàn tuyệt đối")
    for (const m of text.matchAll(/[^.'"`>]*an toàn tuyệt đối/gi)) {
      assert.match(m[0], /không/i, `${file}: "an toàn tuyệt đối" must be negated: ${m[0]}`);
    }
  }
});

test('no dangerouslySetInnerHTML / innerHTML / eval', () => {
  for (const file of sources) {
    const text = read(file);
    assert.doesNotMatch(text, /dangerouslySetInnerHTML|\.innerHTML\s*=|\beval\(|new Function\(/, file);
  }
});

test('QR payloads are never rendered as links nor auto-opened', () => {
  for (const file of sources) {
    const text = read(file);
    assert.doesNotMatch(text, /<a\s[^>]*href=\{/, `${file}: dynamic href`);
    assert.doesNotMatch(text, /window\.open\(|location\.(href|assign|replace)\s*[=(]/, `${file}: navigation`);
  }
});

test('no alert()/confirm() dialogs in the UI', () => {
  for (const file of sources) {
    assert.doesNotMatch(read(file), /\b(window\.)?(alert|confirm)\(/, file);
  }
});

test('no secrets or tokens stored in localStorage/sessionStorage except UI preferences', () => {
  for (const file of sources) {
    const text = read(file);
    for (const m of text.matchAll(/(localStorage|sessionStorage)\.setItem\(([^,]+),/g)) {
      assert.match(m[2], /KEY|prefs/, `${file}: unexpected storage write ${m[0]}`);
    }
  }
});

test('PWA never caches API / stream responses and does not serve the SPA for /api', () => {
  const cfg = read(join(root, 'vite.config.js'));
  assert.match(cfg, /runtimeCaching:\s*\[\s*\]/);
  assert.match(cfg, /navigateFallbackDenylist:\s*\[[^\]]*\\\/api\\\//);
  assert.match(cfg, /registerType:\s*'prompt'/);
  assert.doesNotMatch(cfg, /An toàn/);
});

test('index.html loads no third-party resources and has no "An toàn" title', () => {
  const html = read(join(root, 'index.html'));
  assert.doesNotMatch(html, /https?:\/\//);
  assert.doesNotMatch(html, /<title>[^<]*An toàn/);
  assert.match(html, /<html lang="vi">/);
});

test('home screen contains the required headline, description and actions', () => {
  const home = read(join(root, 'src/components/HomePage.jsx'));
  for (const s of [
    'Kiểm tra mã QR trước khi sử dụng',
    'Chụp hoặc tải ảnh mã QR lên để kiểm tra dấu hiệu lừa đảo và thông tin thanh toán.',
    'Quét bằng camera',
    'Chọn ảnh hoặc PDF',
  ]) assert.ok(home.includes(s), `missing: ${s}`);
});

test('interactive targets meet the 48px token and focus is visible', () => {
  const css = read(join(root, 'src/index.css'));
  assert.match(css, /--tap:\s*3rem/);
  assert.match(css, /:focus-visible\s*\{[^}]*outline:\s*3px/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /html\[data-text-size="large"\]/);
  assert.match(css, /--color-bg:/);
  assert.match(css, /--color-surface:/);
  assert.match(css, /--color-danger:/);
  assert.match(css, /overflow-wrap:\s*anywhere/);
  assert.match(css, /grid-template-columns:\s*repeat\(3,\s*minmax\(0,\s*1fr\)\)/);
});

test('MLSensorCard uses accessible role="meter" and never computes model_score >= ml_threshold on client', () => {
  const mlCard = read(join(root, 'src/components/MLSensorCard.jsx'));
  assert.match(mlCard, /role="meter"/);
  assert.match(mlCard, /aria-valuemin=/);
  assert.match(mlCard, /aria-valuemax=/);
  assert.match(mlCard, /aria-valuenow=/);
  assert.match(mlCard, /aria-label=/);

  for (const file of sources.filter((p) => /\.jsx?$/.test(p))) {
    const text = read(file);
    assert.doesNotMatch(text, /model_score\s*>=?\s*.*threshold|score\s*>=?\s*.*threshold/, `${file}: client-side threshold comparison`);
    assert.doesNotMatch(text, /AI confidence|AI certainty|Safety score|Risk confidence|AI confirms malicious/i, `${file}: forbidden AI hype copy`);
  }
});

test('no emojis used as icons in UI components', () => {
  for (const file of sources.filter((p) => /\.jsx?$/.test(p))) {
    const text = read(file);
    assert.doesNotMatch(text, /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}]/u, `${file}: contains emoji character`);
  }
});
