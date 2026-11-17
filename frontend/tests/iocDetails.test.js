import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatIocDetails } from '../src/lib/iocDetails.js';

test('no IOC details unless the backend reports a MATCH', () => {
  assert.equal(formatIocDetails({ threat_intel: { local_ti_status: 'NO_MATCH' } }), null);
  assert.equal(formatIocDetails(null), null);
});

test('embedded-redirect IOC match is described in plain words with source, type and dates', () => {
  const d = formatIocDetails({
    host: 'vietcombank.com.vn',
    embedded_urls: ['https://aaaalimos.com/login'],
    threat_intel: {
      local_ti_status: 'MATCH',
      scope: 'ioc_embedded',
      freshness: 'fresh',
      last_checked: '2026-11-09T19:05:53Z',
      distinct_sources: 1,
      details: 'Địa chỉ đích lồng bên trong liên kết (aaaalimos.com) khớp IOC cục bộ',
      provenance: [{ source: 'Phishing.Database', verdict: 'known_malicious', indicator_type: 'phishing_domain', last_seen: '2026-10-26T00:17:47Z', confidence: 0.8, stale: false }],
    },
  });
  assert.match(d.where, /chuyển tiếp ẩn.*aaaalimos\.com/);
  assert.match(d.freshness, /Còn hiệu lực/);
  assert.equal(d.records[0].source, 'Phishing.Database');
  assert.match(d.records[0].about, /cộng đồng/);
  assert.equal(d.records[0].type, 'Tên miền lừa đảo (phishing)');
  assert.equal(d.records[0].lastSeen, '26/10/2026');
  assert.equal(d.records[0].confidence, '80%');
  assert.doesNotMatch(JSON.stringify(d), /đã xác thực|An toàn/);
});

test('direct domain and exact URL matches say where they matched', () => {
  const base = { local_ti_status: 'MATCH', provenance: [{ source: 'URLhaus (abuse.ch)', indicator_type: 'malware_url' }] };
  assert.match(formatIocDetails({ host: 'x.top', threat_intel: { ...base, details: 'Domain matched local IOC: phishing' } }).where, /Tên miền "x\.top"/);
  assert.match(formatIocDetails({ host: 'x.top', threat_intel: { ...base, details: 'Exact URL matched local IOC: malware_url' } }).where, /chính xác/);
  assert.equal(formatIocDetails({ host: 'x.top', threat_intel: base }).records[0].type, 'Liên kết phát tán mã độc');
});
