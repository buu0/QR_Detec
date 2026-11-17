/**
 * Scan flow reducer (pure — unit-tested with node:test).
 *
 * phase: idle → uploading → processing → done | error
 * The final verdicts always come from the backend result; this reducer only tracks UI state.
 */
import { copyForError } from './riskCopy.js';
import { mergeQrEvent, mergeQrEvents, isTerminalStatus } from './scanState.js';

export const initialScanState = {
  phase: 'idle',
  file: null, // { name, size, isPdf }
  jobId: null,
  step: null,
  status: null,
  message: null,
  qrTotal: null,
  qrs: {},
  result: null,
  error: null, // { code, message, action }
  inlineError: null, // pre-upload validation error shown on the home screen
  connection: null,
  startedAt: null,
};

function errorFromCode(code, backendMessage, backendAction) {
  const copy = copyForError(code, backendMessage);
  // Known codes use curated frontend copy; unknown codes fall back to the backend's safe text.
  if (copy.code === 'INTERNAL_ERROR' && code !== 'INTERNAL_ERROR' && backendMessage) {
    return { code: code || 'INTERNAL_ERROR', message: backendMessage, action: backendAction || copy.action };
  }
  return copy;
}

export function scanReducer(state, action) {
  switch (action.type) {
    case 'INLINE_ERROR':
      return { ...initialScanState, inlineError: errorFromCode(action.code) };

    case 'START':
      return {
        ...initialScanState,
        phase: 'uploading',
        file: action.file,
        step: 'uploading',
        message: 'Đang gửi tệp lên để kiểm tra...',
        startedAt: action.now,
      };

    case 'UPLOADED':
      if (state.phase !== 'uploading') return state;
      return { ...state, phase: 'processing', jobId: action.jobId, step: 'queued', message: 'Đã nhận tệp. Đang chờ kiểm tra...' };

    case 'PROGRESS': {
      if (state.phase !== 'processing') return state;
      const u = action.update || {};
      const next = { ...state };
      if (u.step) next.step = u.step;
      if (u.status) next.status = u.status;
      if (typeof u.message === 'string' && u.message) next.message = u.message;
      if (Number.isInteger(u.qr_total)) next.qrTotal = u.qr_total;
      return next;
    }

    case 'QR': {
      if (state.phase !== 'processing') return state;
      const qrs = mergeQrEvent(state.qrs, action.event);
      const total = Number.isInteger(action.event?.total) ? action.event.total : state.qrTotal;
      if (qrs === state.qrs && total === state.qrTotal) return state;
      return { ...state, qrs, qrTotal: total };
    }

    case 'QRS':
      if (state.phase !== 'processing') return state;
      return { ...state, qrs: mergeQrEvents(state.qrs, action.events) };

    case 'CONNECTION':
      if (state.phase !== 'processing') return state;
      return { ...state, connection: action.state };

    case 'RESULT': {
      if (state.phase !== 'processing' && state.phase !== 'uploading') return state;
      const r = action.result || {};
      const status = String(r.status || '').toLowerCase();
      if (status === 'failed' || status === 'cancelled') {
        const code = r.error_code || (status === 'cancelled' ? 'CANCELLED' : 'PROCESSING_ERROR');
        return { ...state, phase: 'error', result: r, error: errorFromCode(code, r.user_message, r.recommended_action) };
      }
      if (!isTerminalStatus(status) && r.is_final !== true) return state;
      return { ...state, phase: 'done', result: r, connection: null };
    }

    case 'ERROR':
      return { ...state, phase: 'error', error: errorFromCode(action.code, action.message, action.action) };

    case 'RESET':
      return initialScanState;

    default:
      return state;
  }
}
