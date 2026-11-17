import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BANK_REMINDER,
  KID_TIP,
  VIETQR_CRC_CAVEAT,
  VIETQR_MATCH_CAVEAT,
  checksSummary,
  copyForError,
  actionBadgesForResult,
  copyForResult,
  formatAmount,
  formatLocalIocSummary,
  formatMlSensorSummary,
  formatRuleFinding,
  formatVietQrComparisonRows,
  formatVietQrFlow,
  maskAccount,
  reasonTexts,
  vietqrMismatchLines,
  warningTexts,
  worstLevel,
} from '../src/lib/riskCopy.js';

test('each backend risk level maps to the exact prompt copy', () => {
  assert.equal(copyForResult({ risk_level: 'danger' }).title, 'Nguy hiểm — không mở mã QR này');
  assert.equal(copyForResult({ risk_level: 'warning' }).title, 'Mã QR này có dấu hiệu đáng ngờ');
  const ok = copyForResult({ risk_level: 'no_known_risk' });
  assert.equal(ok.title, 'Chưa phát hiện dấu hiệu nguy hiểm đã biết');
  assert.match(ok.description, /không có nghĩa mã QR an toàn tuyệt đối/);
  assert.equal(copyForResult({ risk_level: 'unverifiable' }).title, 'Chưa thể kiểm tra đầy đủ mã QR');
  assert.equal(copyForResult({ risk_level: 'pending' }).title, 'Đang kiểm tra mã QR...');
});

test('unknown / missing risk level is treated as unverifiable (never as no-risk)', () => {
  assert.equal(copyForResult({}).level, 'unverifiable');
  assert.equal(copyForResult({ risk_level: 'safe' }).level, 'unverifiable');
});

test('no level label ever says "An toàn"', () => {
  for (const level of ['danger', 'warning', 'no_known_risk', 'unverifiable', 'info', 'pending']) {
    const c = copyForResult({ risk_level: level });
    assert.doesNotMatch(c.label, /an toàn/i);
    assert.doesNotMatch(c.title, /^an toàn/i);
  }
});

test('provisional results never read as final no-risk', () => {
  const c = copyForResult({ risk_level: 'no_known_risk', is_provisional: true, payload_type: 'url' });
  assert.equal(c.level, 'pending');
});

test('provisional danger is shown immediately, marked as initial warning', () => {
  const c = copyForResult({ risk_level: 'danger', is_provisional: true, payload_type: 'url' });
  assert.equal(c.level, 'danger');
  assert.ok(c.extra.some((l) => /cảnh báo ban đầu/.test(l)));
});

const mismatch = {
  payload_type: 'vietqr',
  risk_level: 'danger',
  alert_code: 'CRITICAL_MISMATCH',
  match_result: {
    checks: [
      { field: 'account', status: 'mismatch', qr_value: '999988887777', context_value: '123456789' },
      { field: 'bank', status: 'match', qr_value: 'VCB', context_value: 'VCB' },
    ],
  },
};

test('VietQR mismatch explains account A vs B and says not to transfer', () => {
  const c = copyForResult(mismatch);
  assert.equal(c.title, 'Cảnh báo: Thông tin nhận tiền không khớp.');
  assert.equal(c.description, 'Ảnh ghi số tài khoản 123456789 nhưng mã QR chứa số tài khoản 999988887777.');
  assert.equal(c.action, 'Không chuyển tiền. Hãy xác nhận lại trực tiếp với người nhận.');
  assert.equal(vietqrMismatchLines(mismatch).length, 1);
});

test('VietQR match always carries the "not verified owner" caveat', () => {
  const c = copyForResult({ payload_type: 'vietqr', risk_level: 'no_known_risk', alert_code: 'CONTEXT_CONSISTENT' });
  assert.equal(c.title, 'Thông tin trong mã QR trùng với chữ đọc được trên ảnh.');
  assert.equal(c.description, VIETQR_MATCH_CAVEAT);
  assert.doesNotMatch(JSON.stringify(c), /xác thực/i);
});

test('VietQR insufficient context never implies the data is correct', () => {
  const c = copyForResult({ payload_type: 'vietqr', risk_level: 'unverifiable', alert_code: 'INSUFFICIENT_CONTEXT' });
  assert.equal(c.title, 'Chưa đủ thông tin để so sánh.');
  assert.match(c.description, /không thể kết luận/);
});

test('bank reminder and kid tip texts are exact', () => {
  assert.equal(BANK_REMINDER, 'Trước khi chuyển tiền, hãy kiểm tra tên và số tài khoản người nhận trong ứng dụng ngân hàng và đối chiếu với thông tin đáng tin cậy.');
  assert.equal(KID_TIP, 'Nếu còn băn khoăn hoặc chưa rõ nguồn gốc, bạn hãy tạm dừng lại và hỏi người có kinh nghiệm hoặc liên hệ trực tiếp người gửi để xác thực.');
});

test('account masking keeps only the last 4 digits', () => {
  assert.equal(maskAccount('0123456789'), '•••••• 6789');
  assert.equal(maskAccount('1234'), '1234');
  assert.equal(maskAccount(''), '');
});

test('amount formatting', () => {
  assert.match(formatAmount('150000'), /^150[.,\s]000 đ$/);
  assert.equal(formatAmount('abc'), null);
});

test('reason texts are deduplicated and unknown codes ignored', () => {
  const out = reasonTexts(['TI_KNOWN_MALICIOUS', 'ti_known_malicious', 'SOMETHING_NEW', 'URI_SCHEME_TEL']);
  assert.equal(out.length, 2);
});

test('checks summary never claims a check that did not run', () => {
  const items = checksSummary({ local_ioc: 'error', ml_sensor: 'unavailable' });
  assert.deepEqual(items.map((i) => i.state), ['failed', 'skipped']);
  assert.deepEqual(checksSummary({}), []);
});

test('layered Local IOC and AI model state are explained honestly', () => {
  const items = checksSummary({
    local_ioc: 'not_configured', ml_sensor: 'not_configured',
  });
  assert.equal(items.length, 2);
  const byLabel = Object.fromEntries(items.map((i) => [i.label, i]));
  assert.equal(byLabel['Danh sách địa chỉ lừa đảo đã biết'].text, 'chưa có danh sách');
  const ml = byLabel['Mô hình AI nhận diện liên kết lừa đảo'];
  assert.equal(ml.state, 'skipped');
  assert.equal(ml.text, 'chưa được nạp');

  const doneMl = checksSummary({ ml_sensor: 'done' });
  assert.equal(doneMl[0].state, 'done');
  const ioc = checksSummary({ local_ioc: 'match' });
  assert.deepEqual(ioc.map((i) => i.state), ['done']);
});

test('new backend reason codes have plain explanations', () => {
  for (const code of ['TI_IOC_STALE', 'TI_EMBEDDED_URL_MATCH', 'OBFUSCATED_HOST', 'IDN_BRAND_HOMOGRAPH',
    'EMBEDDED_BRAND_LOOKALIKE', 'EMBEDDED_REDIRECT_URL']) {
    assert.equal(reasonTexts([code]).length, 1, code);
  }
  for (const text of reasonTexts(['TI_IOC_STALE', 'IDN_BRAND_HOMOGRAPH'])) {
    assert.doesNotMatch(text, /an toàn|đã xác thực|IOC|XGBoost/i);
  }
});


test('error copy falls back safely', () => {
  assert.equal(copyForError('FILE_TOO_LARGE').code, 'FILE_TOO_LARGE');
  const unknown = copyForError('WEIRD', 'Thông điệp backend');
  assert.equal(unknown.code, 'INTERNAL_ERROR');
  assert.equal(unknown.message, 'Thông điệp backend');
});

test('partial-analysis warnings are explained', () => {
  const lines = warningTexts(['PARTIAL_ANALYSIS', 'PDF_PAGE_LIMIT:20/35', 'CACHED_RESULT']);
  assert.equal(lines.length, 2);
  assert.match(lines[1], /35 trang.*20 trang/);
  const qr = warningTexts(['QR_LIMIT:20/27']);
  assert.match(qr[0], /27 mã QR.*20 mã/);
});

test('worst level ordering', () => {
  assert.equal(worstLevel([{ risk_level: 'no_known_risk' }, { risk_level: 'warning' }]), 'warning');
  assert.equal(worstLevel([{ risk_level: 'info' }, { risk_level: 'unverifiable' }]), 'unverifiable');
  assert.equal(worstLevel([]), null);
});

test('final verdict is strictly taken from backend and never altered by ML sensor score', () => {
  const highMlButBackendNoKnownRisk = {
    payload_type: 'url',
    risk_level: 'no_known_risk',
    alert_code: 'NO_KNOWN_RISK',
    url_analysis: {
      model: {
        model_status: 'OK',
        model_id: 'qrdetec-url-xgb',
        n_features: 69,
        raw_score: 0.96,
        model_score: 0.942,
        ml_threshold: 0.35,
        ml_prediction: 1,
        policy_mode: 'shadow',
      },
    },
  };
  const copy = copyForResult(highMlButBackendNoKnownRisk);
  assert.equal(copy.level, 'no_known_risk');
  assert.equal(copy.title, 'Chưa phát hiện dấu hiệu nguy hiểm đã biết');
});

test('ML sensor summary formats score, uses backend ml_prediction, and keeps null as unmeasured', () => {
  const summary = formatMlSensorSummary({
    model_status: 'OK',
    model_id: 'qrdetec-url-xgb',
    n_features: 81,
    raw_score: 0.712,
    model_score: 0.824,
    ml_threshold: 0.52,
    // Even if model_score > ml_threshold, frontend must trust backend ml_prediction
    ml_prediction: 0,
  }, ['CACHED_RESULT']);

  assert.equal(summary.modelId, 'qrdetec-url-xgb');
  assert.equal(summary.nFeatures, 81);
  assert.equal(summary.scoreLabel, '82.4%');
  assert.equal(summary.thresholdLabel, '52.0%');
  assert.equal(summary.predictionLabel, 'Không vượt ngưỡng');
  assert.equal(summary.predictionState, 'below');
  assert.equal(summary.isCached, true);
  assert.match(summary.disclaimer, /TreeSHAP/);

  const nullScore = formatMlSensorSummary({
    model_status: 'LOAD_ERROR',
    model_score: null,
    ml_threshold: 0.785,
    ml_prediction: null,
  });
  assert.equal(nullScore.scorePct, null);
  assert.equal(nullScore.scoreLabel, 'Không đo lường');
  assert.notEqual(nullScore.scoreLabel, '0%');
  assert.notEqual(nullScore.scoreLabel, '0.0%');

  const withShap = formatMlSensorSummary({
    model_status: 'READY',
    model_score: 0.0693,
    ml_threshold: 0.785,
    ml_prediction: 0,
    shap_base_value: -0.0738,
    shap_top_risk: [
      { feature: 'hostname_confusable_brand_match', label: 'Tên miền giả mạo thương hiệu', value: 1, shap_value: 0.9152, direction: 'risk' },
    ],
    shap_top_benign: [
      { feature: 'scheme_is_https', label: 'Giao thức HTTPS', value: 1, shap_value: -1.1944, direction: 'benign' },
    ],
  });
  assert.equal(withShap.shapBaseValue, -0.0738);
  assert.equal(withShap.shapBaseProbLabel, '48.2%');
  assert.match(withShap.shapGuideText, /Điểm xuất phát trung bình/);
  assert.equal(withShap.shapTopRisk.length, 1);
  assert.equal(withShap.shapTopRisk[0].shapLabel, '+0.92');
  assert.equal(withShap.shapTopRisk[0].impactLabel, 'Tăng rủi ro');
  assert.equal(withShap.shapTopRisk[0].humanValueLabel, 'Có phát hiện trong liên kết');
  assert.match(withShap.shapTopRisk[0].plainExplanation, /Cộng thêm \+0\.92 điểm nghi vấn/);
  assert.equal(withShap.shapTopBenign.length, 1);
  assert.equal(withShap.shapTopBenign[0].shapLabel, '-1.19');
  assert.equal(withShap.shapTopBenign[0].impactLabel, 'Giảm mạnh nghi vấn');
  assert.equal(withShap.shapTopBenign[0].humanValueLabel, 'Đang dùng kết nối HTTPS');
  assert.match(withShap.shapTopBenign[0].plainExplanation, /Trừ bớt -1\.19 điểm nghi vấn/);
});

test('Local IOC state mappings cover all 6 backend states and never render NO_MATCH as SAFE', () => {
  const mMatch = formatLocalIocSummary({ local_ti_status: 'MATCH', freshness: 'fresh' });
  assert.equal(mMatch.label, 'Có IOC khớp');
  assert.equal(mMatch.tone, 'danger');

  const mNoMatch = formatLocalIocSummary({ local_ti_status: 'NO_MATCH' });
  assert.equal(mNoMatch.label, 'Đã tra cứu — không khớp IOC đã biết');
  assert.doesNotMatch(JSON.stringify(mNoMatch), /safe|an toàn/i);

  const mNotCfg = formatLocalIocSummary({ local_ti_status: 'NOT_CONFIGURED' });
  assert.equal(mNotCfg.label, 'Chưa cấu hình');

  const mIntegrity = formatLocalIocSummary({ local_ti_status: 'INTEGRITY_FAILED' });
  assert.equal(mIntegrity.label, 'Không thể xác minh toàn vẹn nguồn IOC');

  const mLoadErr = formatLocalIocSummary({ local_ti_status: 'LOAD_ERROR' });
  assert.equal(mLoadErr.label, 'Không thể tải Local IOC');

  const mNa = formatLocalIocSummary({ local_ti_status: 'NOT_APPLICABLE' });
  assert.equal(mNa.label, 'Không áp dụng');
});

test('Static rule finding formatter maps severity, title, and short explanation', () => {
  const f = formatRuleFinding({
    code: 'BRAND_LOOKALIKE_DOMAIN',
    severity: 'high',
    description: 'Lookalike brand domain',
  });
  assert.equal(f.severityLabel, 'Cao');
  assert.equal(f.tone, 'danger');
  assert.equal(f.title, 'Tên miền giả mạo thương hiệu');
  assert.match(f.explanation, /giả mạo/);
});

test('VietQR progressive flow and field-by-field comparison mappings', () => {
  const provisionalFlow = formatVietQrFlow({
    payload_type: 'vietqr',
    is_provisional: true,
    vietqr_data: { crc_valid: true },
  });
  assert.equal(provisionalFlow.structuralStep.detail, 'Đã hoàn tất kiểm tra cấu trúc');
  assert.equal(provisionalFlow.contextStep.detail, 'Đang kiểm tra ngữ cảnh hiển thị');

  const finalConsistentFlow = formatVietQrFlow({
    payload_type: 'vietqr',
    is_provisional: false,
    alert_code: 'CONTEXT_CONSISTENT',
    vietqr_data: { crc_valid: true },
  });
  assert.equal(finalConsistentFlow.conclusionStep.label, 'Kết luận ngữ cảnh');
  assert.equal(finalConsistentFlow.conclusionStep.detail, 'Nhất quán ngữ cảnh');
  assert.doesNotMatch(JSON.stringify(finalConsistentFlow), /\bSAFE\b|An toàn/);
  assert.match(VIETQR_CRC_CAVEAT, /CRC hợp lệ ≠ xác thực người nhận/);

  const rows = formatVietQrComparisonRows({
    checks: [
      { field: 'account', status: 'match', qr_value: '0123456789', context_value: '0123456789' },
      { field: 'amount', status: 'conflict', qr_value: '500000', context_value: '50000' },
      { field: 'recipient', status: 'unknown', qr_value: 'NGUYEN VAN A', context_value: null },
    ],
  });
  assert.equal(rows.length, 3);
  assert.equal(rows[0].statusCode, 'MATCH');
  assert.equal(rows[1].statusCode, 'CONFLICT');
  assert.equal(rows[2].statusCode, 'UNKNOWN');
});


test('context-specific warning badges and steps adapt to VietQR vs URL attack types', () => {
  const vqDanger = {
    payload_type: 'vietqr',
    risk_level: 'danger',
    alert_code: 'CRITICAL_MISMATCH',
    match_result: { checks: [{ field: 'account', status: 'mismatch', qr_value: '999', context_value: '111' }] },
  };
  const vqBadges = actionBadgesForResult(vqDanger);
  assert.ok(vqBadges.some((b) => /chuyển khoản/i.test(b.text)));
  assert.ok(!vqBadges.some((b) => /liên kết/i.test(b.text)));
  assert.equal(copyForResult(vqDanger).steps.length, 3);

  const idnWarn = {
    payload_type: 'url',
    risk_level: 'warning',
    alert_code: 'SUSPICIOUS_URL',
    reason_codes: ['IDN_BRAND_HOMOGRAPH'],
  };
  const idnCopy = copyForResult(idnWarn);
  assert.match(idnCopy.description, /Punycode xn--/);
  assert.equal(idnCopy.steps.length, 3);
  assert.ok(actionBadgesForResult(idnWarn).some((b) => /ký tự đồng hình/i.test(b.text)));
});
