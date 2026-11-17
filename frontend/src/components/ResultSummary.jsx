/**
 * ResultSummary — final result screen. Most severe QR first; job-level warnings are explicit.
 */
import { forwardRef, useMemo } from 'react';
import AlertBanner from './AlertBanner';
import { RISK_ORDER, copyForError, warningTexts, worstLevel } from '../lib/riskCopy';
import { IconAlertTriangle, IconCamera, IconRefresh } from './Icons';

const SUMMARY_TEXT = {
  danger: 'Có mã QR nguy hiểm. Hãy đọc kỹ cảnh báo bên dưới.',
  warning: 'Có mã QR có dấu hiệu đáng ngờ. Hãy đọc kỹ cảnh báo bên dưới.',
  unverifiable: 'Có mã QR chưa kiểm tra được đầy đủ.',
  no_known_risk: 'Chưa phát hiện dấu hiệu nguy hiểm đã biết ở các mã QR.',
  info: 'Các mã QR chỉ chứa thông tin, không phải liên kết hay mã chuyển tiền.',
  pending: 'Một số mã QR chưa kiểm tra xong.',
};

const ResultSummary = forwardRef(function ResultSummary({ result, onAgain, onOpenPicker, onRetake }, headingRef) {
  const items = useMemo(() => {
    const list = (result.qr_codes || []).map((r, i) => ({ r, i }));
    // Stable sort: most severe first, then original order
    return list.sort((a, b) => (RISK_ORDER[a.r.risk_level] ?? 9) - (RISK_ORDER[b.r.risk_level] ?? 9) || a.i - b.i);
  }, [result]);

  const warnings = result.warnings || [];
  const warnLines = warningTexts(warnings);
  const total = items.length;
  const noQr = total === 0;
  const noQrCopy = copyForError('NO_QR_FOUND');
  const worst = worstLevel(items.map((x) => x.r));

  return (
    <section className="results" aria-labelledby="results-title">
      <div className="results-header-block">
        <h2 id="results-title" ref={headingRef} tabIndex={-1} className="results-title">
          {noQr ? 'Không phát hiện mã QR' : total > 1 ? `Kết quả phân tích ${total} mã QR` : 'Kết quả phân tích mã QR'}
        </h2>
        {total > 1 && worst && <p className="results-summary">{SUMMARY_TEXT[worst]}</p>}
        <div className="results-header-actions">
          <button type="button" className="btn btn-secondary" onClick={onOpenPicker || onAgain}>
            <IconRefresh size={18} />
            <span>Chọn ảnh / PDF khác</span>
          </button>
        </div>
      </div>

      {warnLines.length > 0 && (
        <div className="notice notice-warning" role="note">
          <IconAlertTriangle size={22} className="notice-icon" />
          <div>
            <p className="notice-title">Kết quả phân tích chưa đầy đủ</p>
            <ul className="plain-list">
              {warnLines.map((w) => <li key={w}>{w}</li>)}
            </ul>
          </div>
        </div>
      )}

      {noQr ? (
        <article className="risk-card tone-unknown" aria-labelledby="noqr-title">
          <header className="risk-head">
            <span className="risk-icon" aria-hidden="true"><IconAlertTriangle size={28} /></span>
            <div className="risk-head-text">
              <span className="risk-badge-label">Chưa đọc được dữ liệu</span>
              <h3 id="noqr-title" className="risk-title">{noQrCopy.message}</h3>
            </div>
          </header>
          <div className="risk-body">
            <p className="risk-desc">Ảnh có thể bị mờ, lóa sáng hoặc mã QR nằm ngoài phạm vi quét.</p>
            <div className="risk-action">
              <div className="action-lead">
                <IconAlertTriangle size={18} />
                <strong>Gợi ý xử lý:</strong>
              </div>
              <p className="action-content">{noQrCopy.action} Nếu vẫn không kiểm tra được, không nên mở liên kết hoặc chuyển tiền.</p>
            </div>
          </div>
        </article>
      ) : (
        <div className="card-list">
          {items.map(({ r, i }) => (
            <AlertBanner key={i} result={r} index={i} total={total} warnings={warnings} />
          ))}
        </div>
      )}

      <div className="btn-row btn-row-main">
        {noQr && (
          <button type="button" className="btn btn-primary btn-xl" onClick={onRetake}>
            <IconCamera size={24} />
            <span>Chụp lại ảnh</span>
          </button>
        )}
        <button type="button" id="btn-scan-again" className={`btn ${noQr ? 'btn-secondary' : 'btn-primary'} btn-xl`} onClick={onAgain}>
          <IconRefresh size={24} />
          <span>Kiểm tra mã khác</span>
        </button>
      </div>
    </section>
  );
});

export default ResultSummary;
