/**
 * UpdatePrompt — PWA update notice + offline banner.
 * The service worker never caches API results (see vite.config.js), so offline we clearly say
 * that no check can be done instead of showing an old verdict.
 */
import { useEffect, useState } from 'react';
import { useRegisterSW } from 'virtual:pwa-register/react';
import { IconRefresh, IconX, IconAlertTriangle } from './Icons';

export default function UpdatePrompt() {
  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW();
  const [online, setOnline] = useState(typeof navigator === 'undefined' ? true : navigator.onLine !== false);

  useEffect(() => {
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener('online', up);
    window.addEventListener('offline', down);
    return () => {
      window.removeEventListener('online', up);
      window.removeEventListener('offline', down);
    };
  }, []);

  return (
    <>
      {!online && (
        <div className="offline-banner" role="status">
          <IconAlertTriangle size={16} />
          <span>Bạn đang ngoại tuyến. Cần có mạng để kiểm tra mã QR.</span>
        </div>
      )}
      {needRefresh && (
        <aside className="update-toast" role="status" aria-live="polite">
          <div className="update-toast-icon" aria-hidden="true">
            <IconRefresh size={18} />
          </div>
          <div className="update-toast-body">
            <div className="update-toast-header">
              <strong className="update-toast-title">Cập nhật phiên bản mới</strong>
              <button
                type="button"
                className="update-toast-close"
                onClick={() => setNeedRefresh(false)}
                aria-label="Đóng thông báo cập nhật"
              >
                <IconX size={14} />
              </button>
            </div>
            <p className="update-toast-desc">Tải lại để dùng bản mới nhất. Kết quả đang xem sẽ không bị mất nếu bạn chọn &ldquo;Để sau&rdquo;.</p>
            <div className="update-toast-actions">
              <button
                type="button"
                className="btn-update-apply"
                onClick={() => updateServiceWorker(true)}
              >
                <IconRefresh size={13} />
                <span>Cập nhật ngay</span>
              </button>
              <button
                type="button"
                className="btn-update-dismiss"
                onClick={() => setNeedRefresh(false)}
              >
                Để sau
              </button>
            </div>
          </div>
        </aside>
      )}
    </>
  );
}
