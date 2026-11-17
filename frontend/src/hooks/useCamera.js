/**
 * useCamera Hook
 * Quản lý MediaDevices.getUserMedia() và capture frame.
 * Permission is requested only when `start()` is called (i.e. after the user taps the button),
 * and every track is stopped on `stop()` / unmount.
 */
import { useState, useRef, useCallback, useEffect } from 'react';

/** Map DOMException names to stable codes the UI can explain in plain words. */
export function cameraErrorCode(err) {
  const name = err && err.name;
  if (name === 'NotAllowedError' || name === 'PermissionDeniedError' || name === 'SecurityError') return 'denied';
  if (name === 'NotFoundError' || name === 'DevicesNotFoundError' || name === 'OverconstrainedError') return 'not_found';
  if (name === 'NotReadableError' || name === 'TrackStartError' || name === 'AbortError') return 'busy';
  return 'unknown';
}

export function useCamera() {
  const videoRef = useRef(null);
  const streamRef = useRef(null);
  const startingRef = useRef(false);
  const mountedRef = useRef(true);
  const [status, setStatus] = useState('idle'); // idle | starting | active | error
  const [error, setError] = useState(null); // denied | not_found | busy | insecure | unknown

  const stop = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    if (mountedRef.current) setStatus('idle');
  }, []);

  const start = useCallback(async () => {
    if (startingRef.current) return;
    setError(null);
    if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setError('insecure');
      setStatus('error');
      return;
    }
    startingRef.current = true;
    setStatus('starting');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          facingMode: { ideal: 'environment' }, // Back camera preferred
          width: { ideal: 1920 },
          height: { ideal: 1080 },
        },
      });
      if (!mountedRef.current) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        try { await videoRef.current.play(); } catch { /* autoplay policies: video still shows after user gesture */ }
      }
      setStatus('active');
    } catch (err) {
      if (mountedRef.current) {
        setError(cameraErrorCode(err));
        setStatus('error');
      }
    } finally {
      startingRef.current = false;
    }
  }, []);

  const capture = useCallback(() => {
    const video = videoRef.current;
    if (!video || !video.videoWidth) return Promise.resolve(null);
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    return new Promise((resolve) => {
      canvas.toBlob((blob) => resolve(blob), 'image/jpeg', 0.92);
    });
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      stop();
    };
  }, [stop]);

  return { videoRef, status, isActive: status === 'active', error, start, stop, capture };
}
