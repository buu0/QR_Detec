import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildContextNarrative, decodeIdnHost } from '../src/lib/contextNarrative.js';

const urlResult = (url, ua = {}, extra = {}) => {
  const u = new URL(url);
  return {
    payload: url,
    payload_type: 'url',
    risk_level: 'danger',
    alert_code: 'URL_MALICIOUS',
    reason_codes: [],
    ...extra,
    url_analysis: {
      original_url: url,
      normalized_url: url,
      host: u.hostname,
      scheme: u.protocol.replace(':', ''),
      embedded_urls: [],
      threat_intel: { local_ti_status: 'NO_MATCH' },
      model: { model_status: 'READY', model_score: 0.9969, ml_threshold: 0.597483, ml_prediction: 1, shap_top_risk: [{ label: 'Đuôi tên miền (TLD) có tần suất lừa đảo cao', shap_value: 2.1 }] },
      ...ua,
    },
  };
};

test('punycode hosts are decoded for display', () => {
  assert.equal(decodeIdnHost('xn--vetcombank-x2i.com.vn'), 'v\u0456etcombank.com.vn');
  assert.equal(decodeIdnHost('example.com'), 'example.com');
});

test('narrative facts and steps change with the evidence of each scan (no fixed paragraph)', () => {
  const a = buildContextNarrative(urlResult('http://vietcombank-xacthuc-otp.top/login'));
  const b = buildContextNarrative(urlResult('http://bidv-sinhtrachoc.xyz/cap-nhat'));
  assert.notDeepEqual(a.facts, b.facts);
  assert.match(a.scenario, /Vietcombank/);
  assert.match(b.scenario, /BIDV/);
  assert.ok(!a.facts.some((f) => f.includes('vietcombank-xacthuc-otp.top')), 'plain host is shown in the URL block, not repeated');
  assert.ok(a.facts.some((f) => /"mã OTP"/.test(f)));
  assert.ok(b.facts.some((f) => /sinh trắc học/.test(f)));
  assert.ok(a.steps.some((s) => s.includes('vietcombank.com.vn')));
  assert.ok(b.steps.some((s) => s.includes('bidv.com.vn')));
});

test('IDN homograph is never treated as the official brand domain', () => {
  const n = buildContextNarrative(urlResult('https://xn--vetcombank-x2i.com.vn/'));
  assert.ok(n.facts.some((f) => /U\+0456/.test(f)));
  assert.ok(n.facts.some((f) => /không phải vietcombank\.com\.vn/.test(f)));
  assert.ok(!n.facts.some((f) => /thuộc trang chính thức/.test(f)));
});

test('embedded redirect + IOC provenance are explained with source and date', () => {
  const n = buildContextNarrative(urlResult('https://vietcombank.com.vn/personal?redirect=https://aaaalimos.com/login', {
    embedded_urls: ['https://aaaalimos.com/login'],
    threat_intel: { local_ti_status: 'MATCH', scope: 'ioc_embedded', sources: ['Phishing.Database'], provenance: [{ last_seen: '2026-10-26T00:17:47Z' }], freshness: 'fresh' },
    model: { model_status: 'READY', model_score: 0.3327, ml_threshold: 0.597483, ml_prediction: 0, shap_top_risk: [] },
  }));
  assert.ok(n.facts.some((f) => f.includes('aaaalimos.com')));
  assert.ok(n.facts.some((f) => f.includes('Phishing.Database') && f.includes('thẻ Local IOC')));
  assert.ok(n.facts.some((f) => /cần cả hai lớp/.test(f)));
});

test('AI score is never displayed as a certainty', () => {
  const n = buildContextNarrative(urlResult('http://x.top/a', { model: { model_status: 'READY', model_score: 1.0, ml_threshold: 0.6, ml_prediction: 1 } }));
  assert.ok(n.facts.some((f) => /trên 99\.9%/.test(f)));
  assert.ok(!n.facts.some((f) => /100(\.0)?%/.test(f)));
});

test('VietQR narrative uses printed vs QR values and the detected context type', () => {
  const n = buildContextNarrative({
    payload_type: 'vietqr',
    risk_level: 'danger',
    alert_code: 'CRITICAL_MISMATCH',
    vietqr_data: { bank_name: 'Vietcombank (VCB)', account_number: '999988887777', account_name: 'TRAN VAN GIAN LAN', amount: '500000' },
    ocr_data: { context_type: 'donation', account_numbers: ['0123456789'], bank_names: ['Vietcombank (VCB)'], account_name: 'QUY TU THIEN', amounts: [50000] },
    match_result: { checks: [
      { field: 'account', status: 'mismatch', qr_value: '999988887777', context_value: '0123456789' },
      { field: 'amount', status: 'mismatch', qr_value: '500.000 đ', context_value: '50.000 đ' },
    ] },
  });
  assert.match(n.scenario, /quyên góp/);
  assert.ok(n.facts.some((f) => /gấp 10 lần/.test(f)));
  assert.ok(n.steps.some((s) => s.includes('STK 0123456789')));
  assert.ok(n.steps.some((s) => /website \/ fanpage chính thức/.test(s)));
});

test('Wi-Fi, tel and SMS payloads get their own explanations', () => {
  const wifi = buildContextNarrative({ payload_type: 'other', risk_level: 'info', payload: 'WIFI:S:Free_Wifi_SanBay;T:nopass;;' });
  assert.ok(wifi.facts.some((f) => f.includes('Free_Wifi_SanBay') && /mạng mở/.test(f)));
  const sms = buildContextNarrative({ payload_type: 'uri', risk_level: 'info', payload: 'SMSTO:8077:DK MK 123456', url_analysis: { scheme: 'smsto' } });
  assert.ok(sms.facts.some((f) => /đầu số ngắn/.test(f)));
  assert.ok(sms.facts.some((f) => /mật khẩu \/ OTP/.test(f)));
});

test('provisional results get no narrative (evidence incomplete)', () => {
  assert.equal(buildContextNarrative({ payload_type: 'url', is_provisional: true }), null);
});
