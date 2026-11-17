/**
 * useScan — orchestrates upload → realtime follow-up → final result.
 * Owns exactly one subscription at a time and always cleans it up (unmount, reset, new scan).
 */
import { useCallback, useEffect, useReducer, useRef } from 'react';
import { ApiError, cancelJob, subscribeJob, uploadFile } from '../services/api';
import { initialScanState, scanReducer } from '../lib/scanReducer';
import { isPdf, precheckFile } from '../lib/fileCheck';

export function useScan() {
  const [state, dispatch] = useReducer(scanReducer, initialScanState);
  const subRef = useRef(null);
  const uploadAbortRef = useRef(null);
  const lastFileRef = useRef(null);
  const jobIdRef = useRef(null);

  const stopFollowing = useCallback(() => {
    if (subRef.current) {
      subRef.current.close();
      subRef.current = null;
    }
    if (uploadAbortRef.current) {
      uploadAbortRef.current.abort();
      uploadAbortRef.current = null;
    }
  }, []);

  useEffect(() => stopFollowing, [stopFollowing]);

  const startScan = useCallback(async (file) => {
    const problem = precheckFile(file);
    if (problem) {
      dispatch({ type: 'INLINE_ERROR', code: problem });
      return;
    }
    stopFollowing();
    lastFileRef.current = file;
    jobIdRef.current = null;
    dispatch({
      type: 'START',
      file: { name: String(file.name || 'Ảnh chụp'), size: file.size, isPdf: isPdf(file) },
      now: Date.now(),
    });

    const controller = new AbortController();
    uploadAbortRef.current = controller;
    let jobId;
    try {
      const res = await uploadFile(file, { signal: controller.signal });
      jobId = res.job_id;
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      uploadAbortRef.current = null;
      const code = err instanceof ApiError ? err.code : 'NETWORK_ERROR';
      dispatch({ type: 'ERROR', code, message: err?.message, action: err?.action });
      return;
    }
    if (uploadAbortRef.current !== controller) return; // superseded / reset meanwhile
    uploadAbortRef.current = null;
    jobIdRef.current = jobId;
    dispatch({ type: 'UPLOADED', jobId });

    subRef.current = subscribeJob(jobId, {
      onProgress: (update) => dispatch({ type: 'PROGRESS', update }),
      onQR: (event) => dispatch({ type: 'QR', event }),
      onResult: (result) => {
        subRef.current = null;
        dispatch({ type: 'RESULT', result });
      },
      onError: (err) => {
        subRef.current = null;
        dispatch({ type: 'ERROR', code: err instanceof ApiError ? err.code : 'INTERNAL_ERROR' });
      },
      onConnection: (connection) => dispatch({ type: 'CONNECTION', state: connection }),
    });
  }, [stopFollowing]);

  const cancel = useCallback(() => {
    const jobId = jobIdRef.current;
    stopFollowing();
    if (jobId) cancelJob(jobId).catch(() => { /* best effort; server TTL cleans up anyway */ });
    jobIdRef.current = null;
    dispatch({ type: 'RESET' });
  }, [stopFollowing]);

  const reset = useCallback(() => {
    stopFollowing();
    jobIdRef.current = null;
    dispatch({ type: 'RESET' });
  }, [stopFollowing]);

  const retry = useCallback(() => {
    if (lastFileRef.current) startScan(lastFileRef.current);
    else reset();
  }, [startScan, reset]);

  return { state, startScan, cancel, reset, retry, canRetry: !!state.file };
}
