/**
 * AlertBanner — the per-QR security analysis result card.
 *
 * Hierarchy (Section 10):
 *   1. Final Backend Verdict (visually dominant)
 *   2. Raw QR payload ("Dữ liệu gốc trong mã QR") for side-by-side comparison
 *   3. Evidence Summary (reasons + checks performed)
 *   4. Evidence Layers ("Bằng chứng phân tích URL": XGBoost AI Model | Local IOC)
 *
 * The final verdict comes strictly from the backend (`risk_level` / `alert_code`);
 * this component never computes or overrides risk on the client.
 */
import { memo } from 'react';
import {
  actionBadgesForResult,
  checksSummary,
  copyForResult,
  formatLocalIocSummary,
  reasonTexts,
} from '../lib/riskCopy';
import { buildContextNarrative } from '../lib/contextNarrative';
import { formatIocDetails } from '../lib/iocDetails';
import VietQRResult from './VietQRResult';
import QRPayload from './QRPayload';
import MLSensorCard from './MLSensorCard';
import {
  IconAlertOctagon,
  IconAlertTriangle,
  IconArrowRight,
  IconCheck,
  IconDatabase,
  IconFileText,
  IconInfo,
  IconRefresh,
  IconShield,
  IconX,
} from './Icons';

const TONE_ICON = {
  danger: IconAlertOctagon,
  warning: IconAlertTriangle,
  ok: IconShield,
  unknown: IconInfo,
  info: IconFileText,
  pending: IconRefresh,
};

const CHECK_ICON = { done: IconCheck, skipped: IconInfo, pending: IconRefresh, failed: IconX };
const CHECK_TEXT = { done: 'đã kiểm tra', skipped: 'không thực hiện', pending: 'đang kiểm tra', failed: 'chưa kiểm tra được' };

function LocalIOCCard({ urlAnalysis, checkState }) {
  const threatIntel = urlAnalysis?.threat_intel;
  const ioc = formatLocalIocSummary(threatIntel, checkState);
  const details = formatIocDetails(urlAnalysis);
  let badgeClass = 'badge badge-secondary';
  if (ioc.tone === 'danger') badgeClass = 'badge badge-danger';
  else if (ioc.tone === 'warning') badgeClass = 'badge badge-warning';

  const ToneIcon = ioc.tone === 'danger'
    ? IconAlertOctagon
    : ioc.tone === 'warning'
      ? IconAlertTriangle
      : IconInfo;

  return (
    <div className={`evidence-card local-ioc-card tone-${ioc.tone}`}>
      <div className="evidence-card-header">
        <div className="evidence-card-title-group">
          <IconDatabase size={18} className="evidence-card-icon" />
          <div>
            <h5 className="evidence-card-title">Local IOC</h5>
            <span className="evidence-card-subtitle">Danh sách chỉ báo độc hại cục bộ</span>
          </div>
        </div>
        <span className={`${badgeClass} mono`}>{ioc.status}</span>
      </div>

      <div className={`ioc-status-banner tone-${ioc.tone}`} role="status">
        <ToneIcon size={16} />
        <strong>{ioc.label}</strong>
      </div>

      <p className="evidence-card-desc">{ioc.description}</p>

      {details && (
        <div className="ioc-details">
          <dl className="ioc-detail-list">
            <div className="ioc-detail-row"><dt>Khớp ở đâu</dt><dd>{details.where}</dd></div>
            {details.freshness && <div className="ioc-detail-row"><dt>Độ mới</dt><dd>{details.freshness}</dd></div>}
            <div className="ioc-detail-row"><dt>Số nguồn ghi nhận</dt><dd>{details.distinctSources}</dd></div>
            {details.checkedAt && <div className="ioc-detail-row"><dt>Tra cứu ngày</dt><dd>{details.checkedAt}</dd></div>}
          </dl>
          {details.records.map((r, i) => (
            <div key={`${r.source}-${i}`} className="ioc-record">
              <p className="ioc-record-source">{r.source}</p>
              {r.about && <p className="ioc-record-about">{r.about}</p>}
              <dl className="ioc-detail-list">
                {r.type && <div className="ioc-detail-row"><dt>Loại chỉ báo</dt><dd>{r.type}</dd></div>}
                {r.verdict && <div className="ioc-detail-row"><dt>Đánh giá của nguồn</dt><dd>{r.verdict}</dd></div>}
                {r.firstSeen && <div className="ioc-detail-row"><dt>Ghi nhận lần đầu</dt><dd>{r.firstSeen}</dd></div>}
                {r.lastSeen && <div className="ioc-detail-row"><dt>Ghi nhận gần nhất</dt><dd>{r.lastSeen}{r.stale ? ' (dữ liệu cũ)' : ''}</dd></div>}
                {r.expires && <div className="ioc-detail-row"><dt>Hết hạn</dt><dd>{r.expires}</dd></div>}
                {r.confidence && <div className="ioc-detail-row"><dt>Độ tin cậy của nguồn</dt><dd>{r.confidence}</dd></div>}
              </dl>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AlertBanner({ result, index = 0, total = 1, warnings }) {
  const copy = copyForResult(result);
  const Icon = TONE_ICON[copy.tone] || IconInfo;
  const type = String(result.payload_type || '').toLowerCase();
  const provisional = !!result.is_provisional;
  const reasons = reasonTexts([...(result.reason_codes || []), ...(result.url_analysis?.reason_codes || [])]);
  const checks = checksSummary(result.url_analysis?.checks_performed, result.url_analysis?.model);
  const badges = actionBadgesForResult(result);
  const narrative = buildContextNarrative(result);
  const steps = narrative && narrative.steps.length > 0 ? narrative.steps : copy.steps;
  const hasFacts = !!narrative && narrative.facts.length > 0;
  // The generic lead / extra lines / badges repeat what the per-scan story says, so they are only
  // shown when there is no story. Exception: URL "no known risk" keeps its "not absolute" caveat.
  const nonWebScheme = type === 'uri' && (result.reason_codes || []).includes('UNSUPPORTED_URI_SCHEME');
  const showLead = !hasFacts || nonWebScheme || (type === 'url' && copy.level === 'no_known_risk');
  const showBadges = !hasFacts;
  const urlAnalysis = result.url_analysis;
  const isWebUrl = (type === 'url' || type === 'uri') && urlAnalysis && (urlAnalysis.scheme === 'http' || urlAnalysis.scheme === 'https');
  const titleId = `qr-title-${index}`;

  return (
    <article className={`risk-card tone-${copy.tone}`} aria-labelledby={titleId}>
      {/* 1. FINAL BACKEND VERDICT (Visually Dominant) */}
      <header className="risk-head">
        <span className="risk-icon" aria-hidden="true"><Icon size={28} /></span>
        <div className="risk-head-text">
          <div className="risk-meta-row">
            <span className="risk-verdict-tag">Phán quyết cuối cùng: {copy.label}</span>
            {total > 1 && <span className="risk-index-badge">Mã QR {index + 1}/{total}</span>}
            {provisional && <span className="badge badge-provisional">Kết quả sơ bộ</span>}
          </div>
          <h3 id={titleId} className="risk-title">{copy.title}</h3>
        </div>
      </header>

      <div className="risk-body">
        {!provisional && <QRPayload result={result} />}

        {showLead && <p className="risk-desc">{copy.description}</p>}
        {!hasFacts && copy.extra.map((line) => <p key={line} className="risk-desc risk-desc-extra">{line}</p>)}

        {showBadges && badges.length > 0 && (
          <div className="action-badges" aria-label="Đặc điểm cảnh báo">
            {badges.map((b, i) => (
              <span key={i} className={`action-badge badge-${b.type}`}>
                {b.text}
              </span>
            ))}
          </div>
        )}

        {narrative && narrative.facts.length > 0 && (
          <section className="context-narrative" aria-label="Phân tích riêng cho mã QR này">
            <h4 className="context-narrative-title">
              <IconInfo size={18} />
              <span>{narrative.scenario || 'Phân tích riêng cho mã QR này'}</span>
            </h4>
            <ul className="context-narrative-facts">
              {narrative.facts.map((f) => <li key={f}>{f}</li>)}
            </ul>
          </section>
        )}

        <div className="risk-action">
          <div className="action-lead">
            <IconArrowRight size={18} />
            <strong>Bạn nên làm gì</strong>
          </div>
          <p className="action-content">{copy.action}</p>
          {Array.isArray(steps) && steps.length > 0 && (
            <ol className="action-steps-list" aria-label="Các bước xử lý cụ thể">
              {steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ol>
          )}
        </div>

        {/* 2. PAYLOAD / URL / VIETQR */}
        {type === 'vietqr' && <VietQRResult data={result.vietqr_data} result={result} idSuffix={index} hideReminder={hasFacts} />}

        {/* 3. EVIDENCE SUMMARY */}
        {!provisional && !hasFacts && (reasons.length > 0 || checks.length > 0) && (
          <section className="evidence-summary-box" aria-label="Tóm tắt bằng chứng bảo mật">
            <h4 className="evidence-summary-title">
              <IconShield size={18} />
              <span>Tóm tắt bằng chứng &amp; Cơ sở đánh giá</span>
            </h4>
            {reasons.length > 0 ? (
              <ul className="why-list">
                {reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
            ) : (
              <p className="muted small">Kết luận được tổng hợp từ các tầng kiểm tra bên dưới.</p>
            )}
            {checks.length > 0 && (
              <ul className="check-list" aria-label="Trạng thái các tầng kiểm tra">
                {checks.map((c) => {
                  const CIcon = CHECK_ICON[c.state] || IconInfo;
                  return (
                    <li key={c.label} className={`check-${c.state}`}>
                      <CIcon size={16} />
                      <span>{c.label}: <strong>{c.text || CHECK_TEXT[c.state]}</strong></span>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        )}

        {/* 4. EVIDENCE LAYERS ("Bằng chứng phân tích URL") */}
        {!provisional && isWebUrl && (
          <section className="url-evidence-section" aria-label="Bằng chứng phân tích URL">
            <div className="url-evidence-head">
              <h4 className="url-evidence-title">
                <IconShield size={18} />
                <span>Bằng chứng phân tích URL</span>
              </h4>
              <div className="policy-flow-bar" aria-label="Luồng tổng hợp chính sách backend">
                <span className="flow-node">XGBoost AI ({urlAnalysis.model?.n_features ?? 81} Features) + Local IOC</span>
                <span className="flow-arrow" aria-hidden="true">→</span>
                <span className="flow-node">Backend Policy</span>
                <span className="flow-arrow" aria-hidden="true">→</span>
                <span className="flow-node flow-node-verdict">{copy.label}</span>
              </div>
            </div>

            <div className="url-evidence-grid">
              <MLSensorCard
                model={urlAnalysis.model}
                urlAnalysis={urlAnalysis}
                warnings={warnings}
              />
              <LocalIOCCard
                urlAnalysis={urlAnalysis}
                checkState={urlAnalysis.checks_performed?.local_ioc}
              />
            </div>
          </section>
        )}
      </div>
    </article>
  );
}

export default memo(AlertBanner);
