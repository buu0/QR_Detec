/**
 * ErrorState — one stable error code → short Vietnamese message + what to do next.
 * Never shows stack traces or internal details.
 */
import { forwardRef } from 'react';
import { IconAlertTriangle, IconRefresh, IconUploadCloud } from './Icons';

// Re-sending the same file would fail again: offer "choose another file" instead of "retry".
const FILE_PROBLEMS = new Set(['UNSUPPORTED_FILE_TYPE', 'FILE_TOO_LARGE', 'EMPTY_FILE', 'INVALID_FILE', 'FILE_RESOURCE_LIMIT', 'PDF_ENCRYPTED', 'NO_QR_FOUND']);

const ErrorState = forwardRef(function ErrorState({ error, onRetry, onHome, onPickFile, canRetry }, headingRef) {
  const isCancel = error?.code === 'CANCELLED';
  const fileProblem = FILE_PROBLEMS.has(error?.code) && !!onPickFile;
  const showRetry = canRetry && !isCancel && !fileProblem;
  return (
    <section className="card error-state" aria-labelledby="error-title">
      <div className={`notice ${isCancel ? 'notice-info' : 'notice-unknown'}`} role={isCancel ? 'status' : 'alert'}>
        <IconAlertTriangle size={28} className="notice-icon" />
        <div>
          <h2 id="error-title" ref={headingRef} tabIndex={-1} className="notice-title">{error?.message}</h2>
          <p>{error?.action}</p>
          {!isCancel && (
            <p className="muted small">Khi chưa kiểm tra được, đừng vội mở liên kết hoặc chuyển tiền.</p>
          )}
        </div>
      </div>
      <div className="btn-row btn-row-main">
        {showRetry && (
          <button type="button" id="btn-retry" className="btn btn-primary btn-xl" onClick={onRetry}>
            <IconRefresh size={24} />
            <span>Thử lại</span>
          </button>
        )}
        {fileProblem && (
          <button type="button" id="btn-pick-other" className="btn btn-primary btn-xl" onClick={onPickFile}>
            <IconUploadCloud size={24} />
            <span>Chọn tệp khác</span>
          </button>
        )}
        <button type="button" id="btn-home" className={`btn ${showRetry || fileProblem ? 'btn-secondary' : 'btn-primary'} btn-xl`} onClick={onHome}>
          <span>Về trang đầu</span>
        </button>
      </div>
      {error?.code && <p className="error-code">Mã lỗi: <span className="mono">{error.code}</span></p>}
    </section>
  );
});

export default ErrorState;
