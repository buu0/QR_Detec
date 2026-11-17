/**
 * ProgressTracker — shows REAL backend progress as a few simple steps.
 * No fake percentages, no bar that creeps to 99%. Screen readers hear stage changes only
 * (not every intermediate message).
 */
import { useEffect, useState } from 'react';
import { STAGES, stageIndex } from '../lib/scanState';
import { IconCheck, IconFileText } from './Icons';
import { formatFileSize } from '../lib/fileCheck';

const SLOW_MS_IMAGE = 15000;
const SLOW_MS_PDF = 45000;

const CONNECTION_TEXT = {
  reconnecting: 'Mất kết nối tạm thời. Đang kết nối lại — kết quả của bạn không bị mất.',
  offline: 'Bạn đang ngoại tuyến. Việc kiểm tra sẽ tiếp tục hiển thị khi có mạng trở lại.',
};

export default function ProgressTracker({ scan, onCancel }) {
  const { phase, step, status, message, qrTotal, connection, startedAt, file } = scan;
  const current = phase === 'uploading' ? 0 : stageIndex(step, status);
  const [slow, setSlow] = useState(false);

  useEffect(() => {
    setSlow(false);
    if (!startedAt) return undefined;
    const limit = file && file.isPdf ? SLOW_MS_PDF : SLOW_MS_IMAGE;
    const remaining = Math.max(0, limit - (Date.now() - startedAt));
    const t = setTimeout(() => setSlow(true), remaining);
    return () => clearTimeout(t);
  }, [startedAt, file]);

  const stageLabel = STAGES[Math.min(current, STAGES.length - 1)].label;
  const liveText = qrTotal && current >= 2
    ? `${stageLabel}. Đã đọc được ${qrTotal} mã QR.`
    : `${stageLabel}.`;

  return (
    <section className="card progress" aria-labelledby="progress-title" aria-busy="true">
      <h2 id="progress-title" className="progress-title">Đang phân tích mã QR...</h2>
      <p className="progress-lead">
        Hệ thống đang giải mã và kiểm tra dấu hiệu rủi ro bảo mật từ nội dung mã QR.
      </p>

      {file && (
        <p className="progress-file">
          <IconFileText size={18} />
          <span className="progress-file-name">{file.name}</span>
          {typeof file.size === 'number' && <span className="muted"> · {formatFileSize(file.size)}</span>}
        </p>
      )}

      <ol className="steps">
        {STAGES.map((s, i) => {
          const state = i < current ? 'done' : i === current ? 'current' : 'todo';
          return (
            <li key={s.key} className={`step step-${state}`} aria-current={state === 'current' ? 'step' : undefined}>
              <span className="step-marker" aria-hidden="true">
                {state === 'done' ? <IconCheck size={18} /> : i + 1}
              </span>
              <span className="step-label">{s.label}</span>
              <span className="visually-hidden">
                {state === 'done' ? ' — đã xong' : state === 'current' ? ' — đang thực hiện' : ' — chưa tới'}
              </span>
            </li>
          );
        })}
      </ol>

      {message && <p className="progress-message">{message}</p>}
      <p className="progress-hint">Bạn không cần thao tác thêm.</p>

      {slow && (
        <p className="notice notice-info">Việc kiểm tra đang mất nhiều thời gian hơn dự kiến. Bạn vẫn có thể chờ thêm.</p>
      )}
      {CONNECTION_TEXT[connection] && (
        <p className="notice notice-unknown" role="status">{CONNECTION_TEXT[connection]}</p>
      )}

      <p className="visually-hidden" aria-live="polite" aria-atomic="true">{liveText}</p>

      <button type="button" id="btn-cancel-scan" className="btn btn-ghost" onClick={onCancel}>
        Hủy kiểm tra
      </button>
    </section>
  );
}
