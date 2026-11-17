import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeQrEvent, mergeQrEvents, orderedQrs, stageIndex, isTerminalStatus } from '../src/lib/scanState.js';
import { scanReducer, initialScanState } from '../src/lib/scanReducer.js';
import { precheckFile, isPdf } from '../src/lib/fileCheck.js';

const prov = (i, extra = {}) => ({ type: 'provisional_result', qr_index: i, total: 2, result: { is_provisional: true, risk_level: 'pending', ...extra } });
const fin = (i, extra = {}) => ({ type: 'qr_result', qr_index: i, total: 2, result: { is_provisional: false, risk_level: 'no_known_risk', ...extra } });

test('final result replaces provisional for the same QR', () => {
  let q = mergeQrEvent({}, prov(0));
  q = mergeQrEvent(q, fin(0));
  assert.equal(q[0].final, true);
  assert.equal(q[0].result.risk_level, 'no_known_risk');
});

test('a late provisional never overrides a final result', () => {
  let q = mergeQrEvent({}, fin(0, { risk_level: 'danger' }));
  const before = q;
  q = mergeQrEvent(q, prov(0));
  assert.equal(q, before);
  assert.equal(q[0].result.risk_level, 'danger');
});

test('replayed events (polling + stream) do not duplicate QR cards', () => {
  const events = [prov(0), fin(0), prov(1), fin(0), prov(1)];
  const q = mergeQrEvents({}, events);
  assert.deepEqual(orderedQrs(q).map((x) => x.index), [0, 1]);
});

test('malformed events are ignored', () => {
  const q = {};
  assert.equal(mergeQrEvent(q, null), q);
  assert.equal(mergeQrEvent(q, { type: 'qr_result', qr_index: -1, result: {} }), q);
  assert.equal(mergeQrEvent(q, { type: 'qr_result', qr_index: 'x', result: {} }), q);
});

test('backend steps map to real stages (no fake progress)', () => {
  assert.equal(stageIndex('queued'), 0);
  assert.equal(stageIndex('qr_decode'), 1);
  assert.equal(stageIndex('url_enrich'), 2);
  assert.equal(stageIndex('ocr'), 2);
  assert.equal(stageIndex('anything', 'completed'), 4);
  assert.equal(stageIndex('unknown_step'), 0);
  assert.ok(isTerminalStatus('FAILED'));
  assert.ok(!isTerminalStatus('processing'));
});

test('reducer: full provisional → final flow', () => {
  let s = scanReducer(initialScanState, { type: 'START', file: { name: 'a.png', size: 10, isPdf: false }, now: 1 });
  assert.equal(s.phase, 'uploading');
  s = scanReducer(s, { type: 'UPLOADED', jobId: 'j1' });
  assert.equal(s.phase, 'processing');
  s = scanReducer(s, { type: 'PROGRESS', update: { step: 'decoded', message: 'Đã đọc được 1 mã QR.', qr_total: 1 } });
  assert.equal(s.qrTotal, 1);
  s = scanReducer(s, { type: 'QR', event: prov(0, { risk_level: 'warning' }) });
  assert.equal(s.qrs[0].final, false);
  s = scanReducer(s, { type: 'RESULT', result: { status: 'completed', is_final: true, qr_codes: [{ risk_level: 'warning' }] } });
  assert.equal(s.phase, 'done');
  // Events arriving after completion are ignored (no flicker / duplicates)
  const after = scanReducer(s, { type: 'QR', event: prov(0) });
  assert.equal(after, s);
});

test('reducer: failed backend result becomes a friendly error, not a verdict', () => {
  let s = scanReducer(initialScanState, { type: 'START', file: { name: 'a', size: 1 }, now: 1 });
  s = scanReducer(s, { type: 'UPLOADED', jobId: 'j' });
  s = scanReducer(s, { type: 'RESULT', result: { status: 'failed', error_code: 'JOB_TIMEOUT', is_final: true } });
  assert.equal(s.phase, 'error');
  assert.equal(s.error.code, 'JOB_TIMEOUT');
  assert.ok(s.error.action);
});

test('reducer: non-final polling payload is not treated as a result', () => {
  let s = scanReducer(initialScanState, { type: 'START', file: { name: 'a', size: 1 }, now: 1 });
  s = scanReducer(s, { type: 'UPLOADED', jobId: 'j' });
  const same = scanReducer(s, { type: 'RESULT', result: { status: 'processing', is_final: false } });
  assert.equal(same, s);
});

test('reducer: inline validation error keeps the user on the home screen', () => {
  const s = scanReducer(initialScanState, { type: 'INLINE_ERROR', code: 'FILE_TOO_LARGE' });
  assert.equal(s.phase, 'idle');
  assert.equal(s.inlineError.code, 'FILE_TOO_LARGE');
});

test('file precheck', () => {
  assert.equal(precheckFile(null), 'EMPTY_FILE');
  assert.equal(precheckFile({ name: 'a.png', type: 'image/png', size: 0 }), 'EMPTY_FILE');
  assert.equal(precheckFile({ name: 'a.png', type: 'image/png', size: 60 * 1024 * 1024 }), 'FILE_TOO_LARGE');
  assert.equal(precheckFile({ name: 'a.exe', type: 'application/x-msdownload', size: 10 }), 'UNSUPPORTED_FILE_TYPE');
  assert.equal(precheckFile({ name: 'a.svg', type: 'image/svg+xml', size: 10 }), 'UNSUPPORTED_FILE_TYPE');
  assert.equal(precheckFile({ name: 'photo.jpg', type: '', size: 10 }), null);
  assert.equal(precheckFile({ name: 'doc.pdf', type: 'application/pdf', size: 10 }), null);
  assert.ok(isPdf({ name: 'x.PDF', type: '' }));
});
