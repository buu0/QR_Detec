/**
 * Pure scan-state helpers (no React, unit-testable with node:test).
 *
 * Event semantics come from the backend:
 *   provisional_result  → fast-path result for one QR (is_provisional = true)
 *   qr_result           → final result for one QR
 *   result              → whole job finished (authoritative list in data.qr_codes)
 * A provisional result never replaces a final one, and the same QR (qr_index) is never shown twice.
 */

export const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled']);

export function isTerminalStatus(status) {
  return TERMINAL_STATUSES.has(String(status || '').toLowerCase());
}

/**
 * Merge one per-QR event into a map { [qr_index]: { result, final } }.
 * Returns the same object when nothing changes (cheap React bail-out).
 */
export function mergeQrEvent(qrs, event) {
  if (!event || event.result == null || event.qr_index == null) return qrs;
  const index = Number(event.qr_index);
  if (!Number.isInteger(index) || index < 0) return qrs;
  const isFinal = event.type === 'qr_result'
    || (event.type !== 'provisional_result' && event.result.is_provisional === false);
  const existing = qrs[index];
  if (existing && existing.final && !isFinal) return qrs; // never downgrade final → provisional
  if (existing && existing.final === isFinal && existing.result === event.result) return qrs;
  return { ...qrs, [index]: { result: event.result, final: isFinal } };
}

/** Apply a list of replayed events (e.g. `partial_results` from polling). */
export function mergeQrEvents(qrs, events = []) {
  let next = qrs;
  for (const ev of events) next = mergeQrEvent(next, ev);
  return next;
}

/** Ordered array of per-QR entries for rendering. */
export function orderedQrs(qrs) {
  return Object.keys(qrs)
    .map(Number)
    .sort((a, b) => a - b)
    .map((index) => ({ index, ...qrs[index] }));
}

/**
 * Real backend steps → 4 simple stages shown to the user.
 * Returns the index of the stage currently in progress (0..3); 4 = everything done.
 */
export const STAGES = [
  { key: 'receive', label: 'Nhận tệp' },
  { key: 'read', label: 'Đọc mã QR' },
  { key: 'check', label: 'Kiểm tra dấu hiệu đáng ngờ' },
  { key: 'done', label: 'Có kết quả' },
];

const STEP_TO_STAGE = {
  uploading: 0,
  queued: 0,
  pending: 0,
  validate: 0,
  prepare: 0,
  qr_decode: 1,
  decoded: 2,
  url_check: 2,
  url_enrich: 2,
  payment_check: 2,
  ocr: 2,
  complete: 4,
};

export function stageIndex(step, status) {
  if (String(status || '').toLowerCase() === 'completed') return 4;
  const idx = STEP_TO_STAGE[String(step || '').toLowerCase()];
  return idx == null ? 0 : idx;
}
