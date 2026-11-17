/**
 * QRPayload — "Dữ liệu gốc trong mã QR": the exact decoded string, shown near the top of the result
 * so it can be compared field-by-field with the analysis below.
 * - URL / URI: raw string first, then the normalised form only when it differs (e.g. IDN → punycode).
 * - VietQR: raw EMVCo string, shown in full so it can be compared with the parsed fields.
 * - Text / Wi-Fi / SMS: raw string.
 * Never rendered as a link and never auto-opened.
 */
import { useState } from 'react';
import { IconCheck, IconCopy } from './Icons';

export default function QRPayload({ result }) {
  const [copied, setCopied] = useState(false);
  const raw = String(result?.payload || '');
  if (!raw) return null;

  const ua = result?.url_analysis;
  // Show the normalised form only when it really differs (not just a trailing '/' or letter case).
  const same = (a, b) => a.replace(/\/+$/, '').toLowerCase() === b.replace(/\/+$/, '').toLowerCase();
  const normalized = ua?.normalized_url && !same(ua.normalized_url, raw.trim()) ? ua.normalized_url : null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(raw);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard may be blocked; nothing else to do
    }
  };

  return (
    <section className="qr-payload" aria-label="Dữ liệu gốc trong mã QR">
      <div className="qr-payload-head">
        <h4 className="section-title">Dữ liệu gốc trong mã QR</h4>
        <div className="qr-payload-actions">
          <button
            type="button"
            className={`btn btn-copy ${copied ? 'btn-copy-copied' : ''}`}
            aria-label={copied ? 'Đã sao chép dữ liệu gốc' : 'Sao chép dữ liệu gốc'}
            onClick={handleCopy}
          >
            {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
            <span>{copied ? 'Đã chép' : 'Sao chép'}</span>
          </button>
        </div>
      </div>
      <dl className="qr-payload-list">
        <div className="qr-payload-row">
          {normalized && <dt>Nguyên văn trong mã QR</dt>}
          <dd><pre className="qr-payload-raw mono">{raw}</pre></dd>
        </div>
        {normalized && (
          <div className="qr-payload-row">
            <dt>Sau khi chuẩn hóa (địa chỉ thật sẽ mở)</dt>
            <dd><pre className="qr-payload-raw mono">{normalized}</pre></dd>
          </div>
        )}
      </dl>
    </section>
  );
}
