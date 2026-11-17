/**
 * API service layer — talks to the FastAPI backend through the same origin (nginx / Vite proxy).
 *
 * Security notes:
 *  - The guest session lives in an HttpOnly cookie set by the server; nothing secret is stored in
 *    JS, localStorage or URLs. Requests use `credentials: 'same-origin'`.
 *  - State-changing requests send the `X-QRGuard-Request: 1` header (CSRF defence; the server also
 *    checks Origin).
 *  - Every request uses `cache: 'no-store'`; scan results are private and must never be cached.
 */

const API_BASE = '/api';
const CSRF_HEADER = { 'X-QRGuard-Request': '1' };

/** Stable, user-presentable error carrying a backend error code. */
export class ApiError extends Error {
  constructor(code, { message, action, status, retryAfter } = {}) {
    super(message || code);
    this.name = 'ApiError';
    this.code = code;
    this.action = action || null;
    this.status = status || 0;
    this.retryAfter = retryAfter || null;
  }
}

const STATUS_FALLBACK = {
  400: 'EMPTY_FILE',
  403: 'CSRF_REJECTED',
  404: 'JOB_NOT_FOUND',
  413: 'FILE_TOO_LARGE',
  415: 'UNSUPPORTED_FILE_TYPE',
  422: 'INVALID_FILE',
  429: 'RATE_LIMITED',
  502: 'SERVICE_UNAVAILABLE',
  503: 'SERVICE_UNAVAILABLE',
  504: 'SERVICE_UNAVAILABLE',
};

async function toApiError(response) {
  let body = {};
  try {
    body = await response.json();
  } catch {
    body = {};
  }
  const retry = Number.parseInt(response.headers.get('Retry-After') || '', 10);
  const code = typeof body.error_code === 'string' ? body.error_code : (STATUS_FALLBACK[response.status] || 'INTERNAL_ERROR');
  return new ApiError(code, {
    message: typeof body.message === 'string' ? body.message : undefined,
    action: typeof body.recommended_action === 'string' ? body.recommended_action : undefined,
    status: response.status,
    retryAfter: Number.isFinite(retry) ? retry : null,
  });
}

function networkError() {
  const offline = typeof navigator !== 'undefined' && navigator.onLine === false;
  return new ApiError(offline ? 'OFFLINE' : 'NETWORK_ERROR');
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
    });
  } catch (err) {
    if (err && err.name === 'AbortError') throw err;
    throw networkError();
  }
  if (!response.ok) throw await toApiError(response);
  return response.json();
}

export function uploadFile(file, { signal } = {}) {
  const formData = new FormData();
  formData.append('file', file, file.name || 'qr.jpg');
  return request('/upload', { method: 'POST', body: formData, headers: CSRF_HEADER, signal });
}

export function getResult(jobId, { signal } = {}) {
  return request(`/result/${encodeURIComponent(jobId)}`, { signal });
}

export function cancelJob(jobId) {
  return request(`/job/${encodeURIComponent(jobId)}`, { method: 'DELETE', headers: CSRF_HEADER });
}

/* ────────────────────────────────────────────────────────────────────────────
 * Realtime subscription: WebSocket → SSE → polling, with a polling safety net.
 *
 * Handlers:
 *   onProgress(update)     real backend step/message (never synthetic percentages)
 *   onQR(event)            provisional_result / qr_result for one QR code
 *   onResult(result)       final job result (status completed | failed | cancelled) — called once
 *   onError(ApiError)      the job can no longer be followed (expired, unauthorized, client timeout)
 *   onConnection(state)    'live' | 'reconnecting' | 'polling' | 'offline'
 *
 * A dropped stream is NOT a job failure: we fall back and keep following the job.
 * Returns { close() } which removes every listener, socket and timer.
 * ──────────────────────────────────────────────────────────────────────────── */

const POLL_MS = 4000;
const MAX_POLL_BACKOFF_MS = 15000;
export const CLIENT_TIMEOUT_MS = 6 * 60 * 1000;

/** Plain HTTP on a non-localhost host: browsers drop the Secure session cookie there. */
export function insecureOrigin(env) {
  const loc = env && env.location;
  if (!loc || loc.protocol !== 'http:') return false;
  const host = String(loc.hostname || '').toLowerCase();
  return !(host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1');
}

export function subscribeJob(jobId, handlers = {}, options = {}) {
  const { onProgress, onQR, onResult, onError, onConnection } = handlers;
  const pollMs = options.pollMs || POLL_MS;
  const timeoutMs = options.timeoutMs || CLIENT_TIMEOUT_MS;
  const env = options.env || (typeof window !== 'undefined' ? window : null);

  let finished = false;
  let ws = null;
  let es = null;
  let pingTimer = null;
  let pollTimer = null;
  let timeoutTimer = null;
  let resultFetchTimer = null;
  let pollDelay = pollMs;
  let notFoundCount = 0;
  let transport = 'none';
  let connState = null;
  let pollController = null;

  const setConn = (state) => {
    if (finished || state === connState) return;
    connState = state;
    if (onConnection) onConnection(state);
  };

  function closeStreams() {
    if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
    if (ws) {
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      try { ws.close(); } catch { /* ignore */ }
      ws = null;
    }
    if (es) {
      es.onopen = es.onmessage = es.onerror = null;
      try { es.close(); } catch { /* ignore */ }
      es = null;
    }
  }

  function cleanup() {
    finished = true;
    closeStreams();
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    if (timeoutTimer) { clearTimeout(timeoutTimer); timeoutTimer = null; }
    if (resultFetchTimer) { clearTimeout(resultFetchTimer); resultFetchTimer = null; }
    if (pollController) { try { pollController.abort(); } catch { /* ignore */ } pollController = null; }
    if (env && env.removeEventListener) {
      env.removeEventListener('online', handleOnline);
      env.removeEventListener('offline', handleOffline);
    }
  }

  function finish(result) {
    if (finished || !result) return;
    cleanup();
    if (onResult) onResult(result);
  }

  function fail(err) {
    if (finished) return;
    cleanup();
    if (onError) onError(err);
  }

  /** Terminal progress seen but the `result` event may be lost: fetch it explicitly. */
  function fetchResultSoon(delay = 800) {
    if (finished || resultFetchTimer) return;
    resultFetchTimer = setTimeout(() => {
      resultFetchTimer = null;
      pollOnce();
    }, delay);
  }

  function handleMessage(data) {
    if (finished || !data || typeof data !== 'object') return;
    if (data.type === 'pong') return;
    if (data.type === 'provisional_result' || data.type === 'qr_result') {
      if (onQR) onQR(data);
      return;
    }
    if (data.type === 'result') {
      finish(data.data);
      return;
    }
    if (data.type === 'stream_timeout' || data.type === 'stream_error') {
      nextTransport();
      return;
    }
    if (data.step || data.status) {
      if (onProgress) onProgress(data);
      const status = String(data.status || '').toLowerCase();
      if (status === 'completed' || status === 'failed' || status === 'cancelled') fetchResultSoon();
    }
  }

  function parse(raw) {
    if (!raw || typeof raw !== 'string') return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  function openWebSocket() {
    if (!env || typeof env.WebSocket !== 'function') return false;
    try {
      const proto = env.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new env.WebSocket(`${proto}//${env.location.host}/ws/${encodeURIComponent(jobId)}`);
    } catch {
      ws = null;
      return false;
    }
    transport = 'ws';
    ws.onopen = () => {
      setConn('live');
      pingTimer = setInterval(() => {
        if (ws && ws.readyState === 1) ws.send('ping');
      }, 20000);
    };
    ws.onmessage = (ev) => handleMessage(parse(ev.data));
    ws.onerror = () => { /* onclose follows */ };
    ws.onclose = () => {
      if (!finished && transport === 'ws') nextTransport();
    };
    return true;
  }

  function openSSE() {
    if (!env || typeof env.EventSource !== 'function') return false;
    try {
      es = new env.EventSource(`${API_BASE}/sse/${encodeURIComponent(jobId)}`, { withCredentials: true });
    } catch {
      es = null;
      return false;
    }
    transport = 'sse';
    es.onopen = () => setConn('live');
    es.onmessage = (ev) => handleMessage(parse(ev.data));
    es.onerror = () => {
      // Never let EventSource auto-reconnect forever: hand over to polling.
      if (!finished && transport === 'sse') nextTransport();
    };
    return true;
  }

  function nextTransport() {
    if (finished) return;
    const from = transport;
    closeStreams();
    if (from === 'ws') {
      setConn('reconnecting');
      if (openSSE()) return;
    }
    transport = 'poll';
    setConn(env && env.navigator && env.navigator.onLine === false ? 'offline' : 'polling');
    schedulePoll(0);
  }

  async function pollOnce() {
    if (finished) return;
    if (pollController) return; // a request is already in flight
    pollController = typeof AbortController === 'function' ? new AbortController() : null;
    try {
      const data = await getResult(jobId, { signal: pollController ? pollController.signal : undefined });
      pollController = null;
      if (finished) return;
      notFoundCount = 0;
      pollDelay = pollMs;
      if (transport === 'poll') setConn('polling');
      if (Array.isArray(data.partial_results) && onQR) data.partial_results.forEach((ev) => onQR(ev));
      if (data.is_final === true || Array.isArray(data.qr_codes)) {
        finish(data);
        return;
      }
      if (onProgress && (data.step || data.status)) onProgress(data);
      const status = String(data.status || '').toLowerCase();
      if (status === 'cancelled') finish({ ...data, error_code: data.error_code || 'CANCELLED', is_final: true });
    } catch (err) {
      pollController = null;
      if (finished || (err && err.name === 'AbortError')) return;
      if (err instanceof ApiError && err.code === 'JOB_NOT_FOUND') {
        notFoundCount += 1;
        if (notFoundCount >= 3) { fail(insecureOrigin(env) ? new ApiError('HTTPS_REQUIRED', { status: 404 }) : err); return; }
      } else if (err instanceof ApiError && (err.code === 'OFFLINE' || err.code === 'NETWORK_ERROR')) {
        setConn(err.code === 'OFFLINE' ? 'offline' : 'reconnecting');
        pollDelay = Math.min(pollDelay * 2, MAX_POLL_BACKOFF_MS);
      } else if (err instanceof ApiError && err.retryAfter) {
        pollDelay = Math.min(Math.max(err.retryAfter * 1000, pollMs), MAX_POLL_BACKOFF_MS);
      }
    }
  }

  // Polling runs in every mode as a slow safety net (catches missed events); faster when it is
  // the only transport.
  function schedulePoll(delay) {
    if (finished) return;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(async () => {
      pollTimer = null;
      await pollOnce();
      schedulePoll(transport === 'poll' ? pollDelay : Math.max(pollDelay, pollMs * 2));
    }, delay);
  }

  function handleOnline() {
    if (finished) return;
    setConn(transport === 'poll' ? 'polling' : 'reconnecting');
    pollDelay = pollMs;
    schedulePoll(0);
  }

  function handleOffline() {
    setConn('offline');
  }

  if (env && env.addEventListener) {
    env.addEventListener('online', handleOnline);
    env.addEventListener('offline', handleOffline);
  }

  timeoutTimer = setTimeout(() => fail(new ApiError('CHECK_TOO_LONG')), timeoutMs);

  if (!openWebSocket() && !openSSE()) {
    transport = 'poll';
    setConn('polling');
  }
  schedulePoll(transport === 'poll' ? 0 : pollMs * 2);

  return { close: cleanup };
}
