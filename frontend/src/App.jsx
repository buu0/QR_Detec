/**
 * QR Guard — app shell.
 * Flow: Home (camera | file) → Progress (real backend steps) → Final Result | Error.
 * The backend decides every risk level; the UI only explains it in plain Vietnamese.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useScan } from './hooks/useScan';
import { usePWAInstall } from './hooks/usePWAInstall';
import HomePage from './components/HomePage';
import CameraScanner from './components/CameraScanner';
import ProgressTracker from './components/ProgressTracker';
import ResultSummary from './components/ResultSummary';
import ErrorState from './components/ErrorState';
import UpdatePrompt from './components/UpdatePrompt';
import InstallGuideModal from './components/InstallGuideModal';
import UploadZone, { FilePicker } from './components/UploadZone';
import { IconDownload, IconSmartphone } from './components/Icons';

export default function App() {
  const { state, startScan, cancel, reset, retry, canRetry } = useScan();
  const {
    canInstall,
    isInstalled,
    isIOS,
    canPrompt,
    guideOpen,
    openGuide,
    closeGuide,
    triggerInstall,
  } = usePWAInstall();
  const [cameraOpen, setCameraOpen] = useState(false);
  const [online, setOnline] = useState(() => (typeof navigator !== 'undefined' ? navigator.onLine : true));
  const pickerRef = useRef(null);
  const focusRef = useRef(null);

  useEffect(() => {
    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const handleFile = useCallback((file) => {
    setCameraOpen(false);
    startScan(file);
  }, [startScan]);

  const openPicker = useCallback(() => pickerRef.current?.open(), []);

  const goHome = useCallback(() => {
    setCameraOpen(false);
    reset();
  }, [reset]);

  const retake = useCallback(() => {
    reset();
    setCameraOpen(true);
  }, [reset]);

  // Move keyboard / screen-reader focus to the new main heading when the outcome is ready.
  useEffect(() => {
    if (state.phase === 'done' || state.phase === 'error') {
      focusRef.current?.focus();
    }
  }, [state.phase]);

  const busy = state.phase === 'uploading' || state.phase === 'processing';

  useEffect(() => {
    const handlePaste = (e) => {
      if (busy) return;
      const items = e.clipboardData && e.clipboardData.files;
      if (items && items.length > 0) {
        e.preventDefault();
        handleFile(items[0]);
      }
    };
    window.addEventListener('paste', handlePaste);
    return () => window.removeEventListener('paste', handlePaste);
  }, [busy, handleFile]);

  return (
    <div className="app" data-online={online}>
      <a className="skip-link" href="#main">Bỏ qua, tới nội dung chính</a>

      <header className="topbar">
        <div className="topbar-inner">
          <button type="button" className="brand" onClick={goHome} aria-label="QRDetec — về trang đầu" disabled={busy}>
            <svg className="brand-mark" width="26" height="26" viewBox="0 0 26 26" aria-hidden="true" focusable="false">
              <rect x="1" y="1" width="10" height="10" rx="1.5" fill="none" stroke="currentColor" strokeWidth="2" />
              <rect x="4.5" y="4.5" width="3" height="3" fill="currentColor" />
              <rect x="15" y="1" width="10" height="10" rx="1.5" fill="none" stroke="currentColor" strokeWidth="2" />
              <rect x="18.5" y="4.5" width="3" height="3" fill="currentColor" />
              <rect x="1" y="15" width="10" height="10" rx="1.5" fill="none" stroke="currentColor" strokeWidth="2" />
              <rect x="4.5" y="18.5" width="3" height="3" fill="currentColor" />
              <rect x="15" y="15" width="4" height="4" fill="currentColor" />
              <rect x="21" y="21" width="4" height="4" fill="var(--danger-accent)" />
            </svg>
            <div className="brand-text">
              <span className="brand-name">QRDetec</span>
              <span className="brand-sub">Phân tích rủi ro bảo mật từ mã QR</span>
            </div>
          </button>
          <div className="topbar-actions">
            {canInstall && !busy && (
              <button
                type="button"
                id="btn-install-pwa"
                className="btn-pwa-install"
                onClick={triggerInstall}
                title={isIOS ? "Xem hướng dẫn cài đặt lên màn hình chính" : "Cài đặt ứng dụng lên thiết bị"}
                aria-label="Cài đặt ứng dụng"
              >
                <IconDownload size={16} />
                <span className="topbar-btn-label">Thêm ứng dụng</span>
              </button>
            )}
            {!busy && !isInstalled && (
              <button
                type="button"
                id="btn-pwa-guide"
                className="btn-pwa-guide"
                onClick={openGuide}
                title="Hướng dẫn cài đặt ứng dụng cho điện thoại (iPhone & Android)"
                aria-label="Hướng dẫn cài đặt ứng dụng"
              >
                <IconSmartphone size={16} />
                <span className="topbar-btn-label">Hướng dẫn cài đặt</span>
              </button>
            )}
          </div>
        </div>
      </header>

      <UpdatePrompt />
      <FilePicker ref={pickerRef} onFile={handleFile} />

      <main id="main" className={`main ${state.phase === 'done' ? 'main-wide' : ''}`} tabIndex={-1}>
        {state.phase === 'idle' && !cameraOpen && (
          <HomePage
            onFile={handleFile}
            onOpenCamera={() => setCameraOpen(true)}
            onOpenPicker={openPicker}
            inlineError={state.inlineError}
          />
        )}

        {state.phase === 'idle' && cameraOpen && (
          <CameraScanner
            onCapture={handleFile}
            onClose={() => setCameraOpen(false)}
            onChooseFile={() => { setCameraOpen(false); openPicker(); }}
          />
        )}

        {busy && (
          <ProgressTracker scan={state} onCancel={cancel} />
        )}

        {state.phase === 'done' && state.result && (
          <UploadZone onFile={handleFile}>
            <ResultSummary
              ref={focusRef}
              result={state.result}
              onAgain={goHome}
              onOpenPicker={openPicker}
              onRetake={retake}
            />
          </UploadZone>
        )}

        {state.phase === 'error' && (
          <ErrorState ref={focusRef} error={state.error} onRetry={retry} onHome={goHome} onPickFile={openPicker} canRetry={canRetry} />
        )}
      </main>

      <footer className="footer">
        <p>Kết quả kiểm tra không bảo đảm mã QR an toàn tuyệt đối.</p>
        <p>Tệp bạn gửi được xóa sau khi kiểm tra; kết quả chỉ được lưu tạm thời rồi tự xóa. Chúng tôi không tự mở liên kết trong mã QR.</p>
      </footer>

      <InstallGuideModal
        isOpen={guideOpen}
        onClose={closeGuide}
        isIOS={isIOS}
        canPrompt={canPrompt}
        onTriggerInstall={triggerInstall}
      />
    </div>
  );
}
