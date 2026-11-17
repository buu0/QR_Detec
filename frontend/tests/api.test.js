import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, subscribeJob, uploadFile, cancelJob, insecureOrigin } from '../src/services/api.js';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function jsonResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[k] ?? headers[k.toLowerCase()] ?? null },
    json: async () => body,
  };
}

/** Fake browser environment: WebSocket/EventSource that immediately fail, tracked listeners. */
function fakeEnv({ wsFails = true, sseFails = true } = {}) {
  const listeners = new Map();
  const sockets = [];
  class FakeWS {
    constructor(url) { this.url = url; this.readyState = 0; sockets.push(this); if (wsFails) setTimeout(() => this.onclose && this.onclose(), 5); }
    send() {}
    close() { this.closed = true; }
  }
  class FakeES {
    constructor(url, opts) { this.url = url; this.opts = opts; sockets.push(this); if (sseFails) setTimeout(() => this.onerror && this.onerror(), 5); }
    close() { this.closed = true; }
  }
  return {
    location: { protocol: 'https:', host: 'qr.example' },
    navigator: { onLine: true },
    WebSocket: FakeWS,
    EventSource: FakeES,
    sockets,
    listeners,
    addEventListener: (t, fn) => listeners.set(t, fn),
    removeEventListener: (t) => listeners.delete(t),
  };
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('upload sends CSRF header, same-origin credentials and no-store', async () => {
  let captured;
  globalThis.fetch = async (url, opts) => { captured = { url, opts }; return jsonResponse(200, { job_id: 'abc' }); };
  const res = await uploadFile(new Blob(['x']));
  assert.equal(res.job_id, 'abc');
  assert.equal(captured.url, '/api/upload');
  assert.equal(captured.opts.method, 'POST');
  assert.equal(captured.opts.headers['X-QRGuard-Request'], '1');
  assert.equal(captured.opts.credentials, 'same-origin');
  assert.equal(captured.opts.cache, 'no-store');
});

test('cancel uses DELETE with CSRF header', async () => {
  let captured;
  globalThis.fetch = async (url, opts) => { captured = { url, opts }; return jsonResponse(200, { status: 'cancelled' }); };
  await cancelJob('11111111-1111-4111-8111-111111111111');
  assert.equal(captured.opts.method, 'DELETE');
  assert.equal(captured.opts.headers['X-QRGuard-Request'], '1');
});

test('API errors surface stable codes + Retry-After, never raw text', async () => {
  globalThis.fetch = async () => jsonResponse(429, { error_code: 'TOO_MANY_ACTIVE_JOBS', message: 'm', recommended_action: 'a' }, { 'Retry-After': '15' });
  await assert.rejects(uploadFile(new Blob(['x'])), (err) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.code, 'TOO_MANY_ACTIVE_JOBS');
    assert.equal(err.retryAfter, 15);
    return true;
  });
  globalThis.fetch = async () => jsonResponse(502, '<html>Bad gateway</html>');
  await assert.rejects(uploadFile(new Blob(['x'])), (err) => err.code === 'SERVICE_UNAVAILABLE');
  globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
  await assert.rejects(uploadFile(new Blob(['x'])), (err) => err.code === 'NETWORK_ERROR');
});

test('stream failures fall back WS → SSE → polling and deliver the result exactly once', async () => {
  const env = fakeEnv();
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls === 1) return jsonResponse(200, { status: 'processing', step: 'qr_decode', is_final: false, partial_results: [{ type: 'provisional_result', qr_index: 0, result: { is_provisional: true } }] });
    return jsonResponse(200, { status: 'completed', is_final: true, qr_codes: [] });
  };
  const seen = { results: 0, qr: 0, conn: [], errors: 0 };
  const sub = subscribeJob('job-1', {
    onResult: () => { seen.results += 1; },
    onQR: () => { seen.qr += 1; },
    onConnection: (s) => seen.conn.push(s),
    onError: () => { seen.errors += 1; },
  }, { env, pollMs: 15, timeoutMs: 5000 });
  await wait(200);
  sub.close();
  assert.equal(seen.results, 1);
  assert.equal(seen.errors, 0, 'a dropped stream must not be reported as a failed job');
  assert.ok(seen.qr >= 1);
  assert.ok(seen.conn.includes('polling'));
  assert.ok(env.sockets[0].url.startsWith('wss://qr.example/ws/'));
  assert.equal(env.sockets[1].opts.withCredentials, true);
  assert.equal(env.listeners.size, 0, 'online/offline listeners must be removed');
});

test('three consecutive 404 → JOB_NOT_FOUND (expired / not owned)', async () => {
  const env = fakeEnv();
  globalThis.fetch = async () => jsonResponse(404, { error_code: 'JOB_NOT_FOUND' });
  let error = null;
  subscribeJob('job-x', { onError: (e) => { error = e; } }, { env, pollMs: 10, timeoutMs: 5000 });
  await wait(250);
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, 'JOB_NOT_FOUND');
  assert.equal(env.listeners.size, 0);
});

test('network errors back off without failing the job', async () => {
  const env = fakeEnv();
  let n = 0;
  globalThis.fetch = async () => { n += 1; if (n < 3) throw new TypeError('offline'); return jsonResponse(200, { status: 'completed', is_final: true, qr_codes: [] }); };
  let done = 0; let failed = 0;
  subscribeJob('job-n', { onResult: () => { done += 1; }, onError: () => { failed += 1; } }, { env, pollMs: 10, timeoutMs: 5000 });
  await wait(400);
  assert.equal(failed, 0);
  assert.equal(done, 1);
});

test('client timeout reports CHECK_TOO_LONG and cleans up', async () => {
  const env = fakeEnv();
  globalThis.fetch = async () => jsonResponse(200, { status: 'processing', is_final: false });
  let error = null;
  subscribeJob('job-t', { onError: (e) => { error = e; } }, { env, pollMs: 10, timeoutMs: 60 });
  await wait(150);
  assert.equal(error?.code, 'CHECK_TOO_LONG');
  assert.equal(env.listeners.size, 0);
});

test('stream messages: per-QR events forwarded, result event finishes, close() is idempotent', async () => {
  const env = fakeEnv({ wsFails: false });
  globalThis.fetch = async () => jsonResponse(200, { status: 'processing', is_final: false });
  const got = { qr: [], result: null, progress: [] };
  const sub = subscribeJob('job-s', {
    onQR: (e) => got.qr.push(e.type),
    onResult: (r) => { got.result = r; },
    onProgress: (p) => got.progress.push(p.step),
  }, { env, pollMs: 1000, timeoutMs: 5000 });
  const ws = env.sockets[0];
  ws.onopen();
  const onmsg = ws.onmessage;
  onmsg({ data: JSON.stringify({ step: 'decoded', status: 'processing' }) });
  onmsg({ data: JSON.stringify({ type: 'provisional_result', qr_index: 0, result: {} }) });
  onmsg({ data: 'not json' });
  onmsg({ data: JSON.stringify({ type: 'result', data: { status: 'completed', is_final: true, qr_codes: [] } }) });
  onmsg({ data: JSON.stringify({ type: 'qr_result', qr_index: 0, result: {} }) }); // after finish: ignored
  assert.deepEqual(got.qr, ['provisional_result']);
  assert.deepEqual(got.progress, ['decoded']);
  assert.equal(got.result.status, 'completed');
  assert.ok(ws.closed);
  assert.equal(ws.onmessage, null, 'socket handlers are detached after completion');
  assert.equal(env.listeners.size, 0);
  sub.close();
  sub.close();
});

test('insecureOrigin: only plain HTTP on a non-localhost host', () => {
  assert.equal(insecureOrigin({ location: { protocol: 'http:', hostname: '192.168.1.20' } }), true);
  assert.equal(insecureOrigin({ location: { protocol: 'http:', hostname: 'localhost' } }), false);
  assert.equal(insecureOrigin({ location: { protocol: 'http:', hostname: '127.0.0.1' } }), false);
  assert.equal(insecureOrigin({ location: { protocol: 'https:', hostname: '192.168.1.20' } }), false);
  assert.equal(insecureOrigin(null), false);
});

test('repeated 404 over plain HTTP on LAN → HTTPS_REQUIRED instead of "session expired"', async () => {
  const env = fakeEnv();
  env.location = { protocol: 'http:', host: '192.168.1.20:8080', hostname: '192.168.1.20' };
  globalThis.fetch = async () => jsonResponse(404, { error_code: 'JOB_NOT_FOUND' });
  let error = null;
  subscribeJob('job-lan', { onError: (e) => { error = e; } }, { env, pollMs: 10, timeoutMs: 5000 });
  await wait(250);
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, 'HTTPS_REQUIRED');
  assert.equal(env.listeners.size, 0);
});
