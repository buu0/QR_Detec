/**
 * MLSensorCard — calibrated XGBoost result explained for everyday users.
 *
 * Visible by default:
 *   - "Mức nghi ngờ của AI" meter (role="meter") with the backend operating threshold
 *   - "Vì sao AI đánh giá như vậy?": TreeSHAP contributions rewritten as plain Vietnamese facts about
 *     THIS link, with a 3-step strength meter instead of numbers
 * Exact log-odds values stay in the API response (url_analysis.model) for auditing; the UI shows
 *   only the plain-language explanation.
 * The prediction label comes from backend `ml_prediction`; nothing is compared on the client.
 */
import { memo } from 'react';
import { formatMlSensorSummary } from '../lib/riskCopy';
import { plainShapItem, shapContext, shapStrength } from '../lib/shapPlain';
import { IconCpu, IconAlertTriangle } from './Icons';

const MAX_METER_PCT = 10 * 10;
const MAX_REASONS = 4;

function Strength({ value }) {
  const s = shapStrength(value);
  return (
    <span className={`ml-plain-strength lvl-${s.level}`}>
      <span className="ml-plain-dots" aria-hidden="true"><i /><i /><i /></span>
      <span>{s.text}</span>
    </span>
  );
}

function ReasonList({ items, ctx, tone }) {
  const rows = items
    .map((it) => ({ it, ...plainShapItem(it, ctx) }))
    .filter((r) => r.consistent)
    .slice(0, MAX_REASONS);
  if (rows.length === 0) return null;
  return (
    <ul className="ml-plain-list">
      {rows.map(({ it, text }) => (
        <li key={`${tone}-${it.feature}`} className={`ml-plain-item ${tone}`}>
          <span className="ml-plain-text">{text}</span>
          <Strength value={it.shapValue} />
        </li>
      ))}
    </ul>
  );
}

export function MLSensorCard({ model, urlAnalysis, warnings = [] }) {
  if (!model) return null;

  const info = formatMlSensorSummary(model, warnings);
  if (!info) return null;

  if (info.status === 'NOT_APPLICABLE') {
    return (
      <div className="evidence-card ml-sensor-card status-na">
        <div className="evidence-card-header">
          <div className="evidence-card-title-group">
            <IconCpu size={18} className="evidence-card-icon" />
            <div>
              <h5 className="evidence-card-title">Đánh giá của AI</h5>
              <span className="evidence-card-subtitle mono">{info.modelId}</span>
            </div>
          </div>
          <span className="badge badge-secondary">Không áp dụng</span>
        </div>
        <p className="evidence-card-desc">
          AI chỉ đánh giá liên kết trang web (http/https), không áp dụng cho loại mã này.
        </p>
      </div>
    );
  }

  let predClass = 'pred-unknown';
  let predText = 'Chưa có đánh giá';
  if (info.predictionState === 'exceeded') {
    predClass = 'pred-exceeded';
    predText = 'AI nghi ngờ';
  } else if (info.predictionState === 'below') {
    predClass = 'pred-normal';
    predText = 'AI chưa thấy đáng ngờ';
  }

  const clampedScore = info.modelScore != null ? Math.max(0, Math.min(1, info.modelScore)) : null;
  const scorePercentNum = clampedScore != null ? Number((clampedScore * MAX_METER_PCT).toFixed(1)) : null;
  const thresholdPercentNum = typeof info.threshold === 'number' && Number.isFinite(info.threshold)
    ? Math.max(0, Math.min(MAX_METER_PCT, Number((info.threshold * MAX_METER_PCT).toFixed(1))))
    : null;

  const ctx = shapContext(urlAnalysis);
  const hasShap = info.shapTopRisk.length > 0 || info.shapTopBenign.length > 0;
  const lead = 'Những điều AI nhìn thấy trong liên kết này, xếp theo mức ảnh hưởng:';

  return (
    <div className="evidence-card ml-sensor-card">
      <div className="evidence-card-header">
        <div className="evidence-card-title-group">
          <IconCpu size={18} className="evidence-card-icon" />
          <div>
            <h5 className="evidence-card-title">Đánh giá của AI</h5>
            <span className="evidence-card-subtitle mono">XGBoost · {info.nFeatures} đặc trưng</span>
          </div>
        </div>
        <div className="ml-sensor-badges">
          <span className={`badge ${predClass}`} title="Kết luận riêng của mô hình AI (từ backend)">{predText}</span>
        </div>
      </div>

      {info.isCached && (
        <p className="ml-cached-notice" role="status">Kết quả AI lấy lại từ lần kiểm tra gần đây của cùng tệp này.</p>
      )}

      {scorePercentNum != null ? (
        <div className="ml-meter-section">
          <div className="ml-meter-labels">
            <span className="ml-meter-label">Mức nghi ngờ của AI</span>
            <span className="ml-meter-value mono"><strong>{info.scoreLabel}</strong></span>
          </div>
          <div
            className="ml-meter-track"
            role="meter"
            aria-label="Mức nghi ngờ của AI"
            aria-valuemin={0}
            aria-valuemax={MAX_METER_PCT}
            aria-valuenow={scorePercentNum}
            aria-valuetext={`${info.scoreLabel} (ngưỡng cảnh báo ${info.thresholdLabel})`}
          >
            <div
              className={`ml-meter-fill ${info.predictionState === 'exceeded' ? 'fill-high' : 'fill-low'}`}
              style={{ width: `${scorePercentNum.toFixed(1)}%` }}
            />
            {thresholdPercentNum != null && (
              <div
                className="ml-meter-threshold-marker"
                style={{ left: `${thresholdPercentNum.toFixed(1)}%` }}
                title={`Ngưỡng cảnh báo: ${info.thresholdLabel}`}
              />
            )}
          </div>
          <div className="ml-meter-legend">
            <span>Thấp</span>
            {info.threshold != null && <span className="ml-threshold-tag">Vạch đen: ngưỡng cảnh báo {info.thresholdLabel}</span>}
            <span>Cao</span>
          </div>
        </div>
      ) : (
        <div className="ml-unmeasured-notice" role="status">
          <IconAlertTriangle size={16} />
          <span>AI chưa đánh giá được liên kết này.</span>
        </div>
      )}

      {hasShap && (
        <div className="ml-shap-section" aria-label="Vì sao AI đánh giá như vậy">
          <h6 className="ml-shap-title">Vì sao AI đánh giá như vậy?</h6>
          <p className="ml-shap-guide">{lead}</p>

          <div className={`ml-shap-groups${info.predictionState === 'below' ? ' benign-first' : ''}`}>
            {info.shapTopRisk.length > 0 && (
              <div className="ml-shap-group group-risk">
                <p className="ml-shap-group-label risk">Khiến AI nghi ngờ hơn</p>
                <ReasonList items={info.shapTopRisk} ctx={ctx} tone="risk" />
              </div>
            )}
            {info.shapTopBenign.length > 0 && (
              <div className="ml-shap-group group-benign">
                <p className="ml-shap-group-label benign">Khiến AI bớt nghi ngờ</p>
                <ReasonList items={info.shapTopBenign} ctx={ctx} tone="benign" />
              </div>
            )}
          </div>
          <p className="ml-shap-footnote">Kết luận cuối cùng còn dựa vào danh sách lừa đảo và các kiểm tra khác.</p>
        </div>
      )}

    </div>
  );
}

export default memo(MLSensorCard);
