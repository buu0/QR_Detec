/**
 * VietQRResult — structural inspection, progressive/final 3-step flow, and field-by-field
 * payment context comparison (QR payload vs OCR image text).
 * Never claims the account is bank-verified; explicitly states "CRC hợp lệ ≠ xác thực người nhận".
 */
import { useState } from 'react';
import {
  BANK_REMINDER,
  VIETQR_CRC_CAVEAT,
  formatAmount,
  formatVietQrComparisonRows,
  formatVietQrFlow,
  maskAccount,
} from '../lib/riskCopy';
import {
  IconCreditCard,
  IconCopy,
  IconCheck,
  IconAlertTriangle,
  IconAlertOctagon,
  IconInfo,
} from './Icons';

function StatusIcon({ tone }) {
  if (tone === 'ok' || tone === 'done') return <IconCheck size={14} />;
  if (tone === 'danger' || tone === 'error') return <IconAlertOctagon size={14} />;
  if (tone === 'warning') return <IconAlertTriangle size={14} />;
  return <IconInfo size={14} />;
}

export default function VietQRResult({ data, result, idSuffix, hideReminder = false }) {
  const [showAccount, setShowAccount] = useState(false);
  const [copied, setCopied] = useState(false);
  const vq = data || result?.vietqr_data;
  if (!vq) return null;

  const isCard = vq.service_code === 'QRIBFTTC';
  const serviceLabel = isCard
    ? 'QRIBFTTC (Chuyển nhanh NAPAS 247 qua số thẻ)'
    : vq.service_code === 'QRIBFTTA'
      ? 'QRIBFTTA (Chuyển nhanh NAPAS 247 qua tài khoản)'
      : (vq.service_code || 'EMVCo / VietQR');
  const crcStatus = vq.crc_valid === false ? 'Không hợp lệ' : 'Hợp lệ (chuẩn EMVCo TLV/CRC-16)';
  const amount = vq.amount ? formatAmount(vq.amount) : null;
  const accountId = `acc-${idSuffix}`;

  const flow = formatVietQrFlow(result || { vietqr_data: vq });
  const comparisonRows = formatVietQrComparisonRows(result?.match_result);

  const handleCopy = async () => {
    if (!vq.account_number) return;
    try {
      await navigator.clipboard.writeText(vq.account_number);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback or ignore if blocked in restricted iframe
    }
  };

  return (
    <div className="vietqr">
      {/* 1. 3-Step VietQR Verification Flow: Structural -> Context -> Conclusion */}
      <div className="vietqr-flow-box" aria-label="Quy trình kiểm tra VietQR">
        <h4 className="section-title">
          <IconCreditCard size={18} />
          <span>Quy trình phân tích VietQR</span>
        </h4>
        <ol className="vietqr-flow-steps">
          <li className={`vietqr-flow-step state-${flow.structuralStep.state}`}>
            <span className="vietqr-step-head">
              <StatusIcon tone={flow.structuralStep.state} />
              <strong>1. {flow.structuralStep.label}</strong>
            </span>
            <span className="vietqr-step-detail">{flow.structuralStep.detail}</span>
          </li>
          <li className={`vietqr-flow-step state-${flow.contextStep.state}`}>
            <span className="vietqr-step-head">
              <StatusIcon tone={flow.contextStep.state === 'done' ? 'ok' : 'info'} />
              <strong>2. {flow.contextStep.label}</strong>
            </span>
            <span className="vietqr-step-detail">{flow.contextStep.detail}</span>
          </li>
          <li className={`vietqr-flow-step state-${flow.conclusionStep.tone}`}>
            <span className="vietqr-step-head">
              <StatusIcon tone={flow.conclusionStep.tone} />
              <strong>3. {flow.conclusionStep.label}</strong>
            </span>
            <span className="vietqr-step-detail">
              <strong>{flow.conclusionStep.detail}</strong>
            </span>
          </li>
        </ol>
      </div>

      {/* 2. VietQR Structural & Payment Details */}
      <div className="vietqr-structural-box">
        <h4 className="section-title">
          <IconCreditCard size={18} />
          <span>Kiểm tra cấu trúc &amp; Thông tin nhận tiền trong mã QR</span>
        </h4>
        <dl className="info-list">
          <div className="info-row">
            <dt>Cấu trúc TLV / CRC</dt>
            <dd>
              <span className={`status-inline-tag tone-${vq.crc_valid === false ? 'danger' : 'info'}`}>
                <StatusIcon tone={vq.crc_valid === false ? 'danger' : 'info'} />
                <span>{crcStatus}</span>
              </span>
            </dd>
          </div>
          <div className="info-row">
            <dt>Trường dịch vụ NAPAS</dt>
            <dd className="mono">{serviceLabel}</dd>
          </div>
          <div className="info-row">
            <dt>Ngân hàng</dt>
            <dd>{vq.bank_name || (vq.bank_bin ? `Mã ngân hàng ${vq.bank_bin}` : 'Không rõ')}</dd>
          </div>
          {vq.account_number && (
            <div className="info-row">
              <dt>{isCard ? 'Số thẻ' : 'Số tài khoản'}</dt>
              <dd className="info-account">
                <span id={accountId} className="mono">
                  {showAccount ? vq.account_number : maskAccount(vq.account_number)}
                </span>
                <button
                  type="button"
                  className="btn btn-link"
                  aria-pressed={showAccount}
                  aria-controls={accountId}
                  onClick={() => setShowAccount((v) => !v)}
                >
                  {showAccount ? 'Ẩn số' : 'Hiện số'}
                </button>
                <button
                  type="button"
                  className={`btn btn-copy ${copied ? 'btn-copy-copied' : ''}`}
                  aria-label={copied ? 'Đã sao chép số' : `Sao chép ${isCard ? 'số thẻ' : 'số tài khoản'}`}
                  onClick={handleCopy}
                >
                  {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                  <span>{copied ? 'Đã chép' : 'Sao chép'}</span>
                </button>
              </dd>
            </div>
          )}
          {vq.account_name && (
            <div className="info-row">
              <dt>Tên người nhận</dt>
              <dd>{vq.account_name}</dd>
            </div>
          )}
          {amount && (
            <div className="info-row">
              <dt>Số tiền</dt>
              <dd className="info-amount">{amount}</dd>
            </div>
          )}
          {vq.description && (
            <div className="info-row">
              <dt>Nội dung chuyển khoản</dt>
              <dd>{vq.description}</dd>
            </div>
          )}
        </dl>

        <div className="vietqr-crc-caveat" role="note">
          <IconInfo size={16} />
          <span>{VIETQR_CRC_CAVEAT}</span>
        </div>
      </div>

      {/* 3. Field-by-field Payment Context Comparison (QR vs OCR context) */}
      <div className="vietqr-comparison-box">
        <div className="vietqr-comparison-header">
          <h4 className="section-title">
            <IconInfo size={18} />
            <span>Đối chiếu ngữ cảnh thanh toán (QR vs Văn bản hiển thị)</span>
          </h4>
        </div>

        {flow.isProvisional ? (
          <p className="vietqr-progressive-notice" role="status">
            Đã hoàn tất kiểm tra cấu trúc. Đang kiểm tra ngữ cảnh hiển thị trên ảnh để đối chiếu từng trường thông tin...
          </p>
        ) : comparisonRows.length > 0 ? (
          <div className="comparison-list" role="region" aria-label="Bảng đối chiếu từng trường VietQR">
            {comparisonRows.map((row) => (
              <div key={row.key} className={`comparison-row tone-${row.tone}`}>
                <div className="comparison-row-head">
                  <strong className="comparison-field">{row.fieldLabel}</strong>
                  <span className={`comparison-status-badge tone-${row.tone}`}>
                    <StatusIcon tone={row.tone} />
                    <span className="mono">{row.statusCode}</span>
                    <span>— {row.statusLabel}</span>
                  </span>
                </div>
                <div className="comparison-values">
                  <div className="comparison-val-col">
                    <span className="comparison-val-label">Giá trị trong mã QR</span>
                    <span className="comparison-val-text mono">{row.qrValue}</span>
                  </div>
                  <div className="comparison-val-col">
                    <span className="comparison-val-label">Giá trị ngữ cảnh (OCR trên ảnh)</span>
                    <span className="comparison-val-text mono">{row.contextValue}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted small">
            {flow.conclusionStep.summary}
          </p>
        )}
      </div>

      {!hideReminder && (
        <div className="reminder" role="note">
          <IconAlertTriangle size={18} className="reminder-icon" />
          <div>
            <strong>Lưu ý quan trọng: </strong>
            <span>{BANK_REMINDER}</span>
          </div>
        </div>
      )}
    </div>
  );
}

