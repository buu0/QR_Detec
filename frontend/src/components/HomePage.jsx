/**
 * HomePage - editorial entry screen: statement + actions on the left, what-we-check list on the right.
 */
import { useEffect, useRef } from 'react';
import UploadZone from './UploadZone';
import { IconCamera, IconUploadCloud, IconAlertTriangle } from './Icons';
import { MAX_FILE_MB } from '../lib/fileCheck';

const CHECKS = [
  {
    no: '01',
    title: 'Kiểm tra tệp trước khi đọc',
    text: 'Chặn tệp giả định dạng, ảnh quá khổ và PDF khóa mật khẩu trước khi giải mã QR.',
  },
  {
    no: '02',
    title: 'Liên kết web',
    text: 'Đối chiếu danh sách lừa đảo cục bộ và mô hình AI 81 đặc trưng. Hệ thống không bao giờ tự mở liên kết.',
  },
  {
    no: '03',
    title: 'Mã chuyển tiền VietQR',
    text: 'So số tài khoản, tên, ngân hàng và số tiền trong mã với chữ in trên ảnh để phát hiện mã bị dán đè.',
  },
];

export default function HomePage({ onFile, onOpenCamera, onOpenPicker, inlineError }) {
  const errorRef = useRef(null);

  useEffect(() => {
    if (inlineError) errorRef.current?.focus();
  }, [inlineError]);

  return (
    <UploadZone onFile={onFile}>
      <section className="home home-v2" aria-labelledby="home-title">
        <div className="home-intro">
          <p className="home-eyebrow">QRDetec · quét trước, tin sau</p>
          <h1 id="home-title" className="home-title">Kiểm tra mã QR trước khi sử dụng</h1>
          <p className="home-lead">
            Chụp hoặc tải ảnh mã QR lên để kiểm tra dấu hiệu lừa đảo và thông tin thanh toán.
          </p>

          {inlineError && (
            <div className="notice notice-warning" role="alert" tabIndex={-1} ref={errorRef}>
              <IconAlertTriangle size={22} className="notice-icon" />
              <div>
                <p className="notice-title">{inlineError.message}</p>
                <p>{inlineError.action}</p>
              </div>
            </div>
          )}

          <div className="scanner-actions">
            <button type="button" id="btn-choose-file" className="btn btn-primary btn-lg" onClick={onOpenPicker}>
              <IconUploadCloud size={20} />
              <span>Chọn ảnh hoặc PDF</span>
            </button>
            <button type="button" id="btn-open-camera" className="btn btn-secondary btn-lg" onClick={onOpenCamera}>
              <IconCamera size={20} />
              <span>Quét bằng camera</span>
            </button>
          </div>
          <p className="home-formats">
            JPG, PNG, WEBP hoặc PDF, tối đa {MAX_FILE_MB} MB.<span className="hint-pointer"> Có thể kéo thả hoặc dán ảnh bằng <span className="kbd-combo"><kbd>Ctrl</kbd> + <kbd>V</kbd></span>.</span>
          </p>
        </div>

        <div className="home-aside">
          <ol className="home-checks" aria-label="Những gì hệ thống kiểm tra">
            {CHECKS.map((c) => (
              <li key={c.no}>
                <span className="check-no" aria-hidden="true">{c.no}</span>
                <h2>{c.title}</h2>
                <p>{c.text}</p>
              </li>
            ))}
          </ol>
          <p className="home-checks-caption">Mỗi kết quả kèm phần giải thích riêng, ghép từ bằng chứng của chính lần quét đó.</p>
        </div>
      </section>
    </UploadZone>
  );
}
