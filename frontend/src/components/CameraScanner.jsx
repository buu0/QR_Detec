/**
 * CameraScanner — opens the camera only after the user asked for it, shows a guide frame and one
 * large capture button. Friendly recovery when the camera cannot be used.
 */
import { useEffect, useRef, useState } from 'react';
import { useCamera } from '../hooks/useCamera';
import { IconCamera, IconRefresh, IconUploadCloud, IconX } from './Icons';

const CAMERA_ERRORS = {
  denied: {
    title: 'Bạn chưa cho phép dùng camera.',
    action: 'Hãy cho phép quyền camera trong cài đặt trình duyệt rồi nhấn "Thử lại", hoặc chọn ảnh có sẵn.',
  },
  not_found: {
    title: 'Không tìm thấy camera trên thiết bị này.',
    action: 'Hãy chọn ảnh mã QR có sẵn trong máy.',
  },
  busy: {
    title: 'Camera đang được ứng dụng khác sử dụng.',
    action: 'Hãy đóng ứng dụng đang dùng camera rồi nhấn "Thử lại".',
  },
  insecure: {
    title: 'Trình duyệt không cho mở camera trên trang này.',
    action: 'Hãy dùng nút "Chọn ảnh hoặc PDF". Trên điện thoại, bạn có thể chụp ảnh ngay trong bước chọn ảnh.',
  },
  unknown: {
    title: 'Không mở được camera.',
    action: 'Hãy nhấn "Thử lại" hoặc chọn ảnh có sẵn.',
  },
};

export default function CameraScanner({ onCapture, onClose, onChooseFile }) {
  const { videoRef, status, error, start, stop, capture } = useCamera();
  const [capturing, setCapturing] = useState(false);
  const headingRef = useRef(null);

  useEffect(() => {
    headingRef.current?.focus();
    start();
  }, [start]);

  const handleCapture = async () => {
    if (capturing) return;
    setCapturing(true);
    const blob = await capture();
    if (!blob) {
      setCapturing(false);
      return;
    }
    stop();
    onCapture(new File([blob], 'anh-chup-camera.jpg', { type: 'image/jpeg' }));
  };

  const err = status === 'error' ? CAMERA_ERRORS[error] || CAMERA_ERRORS.unknown : null;

  return (
    <section className="card camera" aria-labelledby="camera-title">
      <div className="camera-header">
        <h2 id="camera-title" ref={headingRef} tabIndex={-1}>Quét bằng camera</h2>
        <button type="button" className="btn btn-ghost btn-icon" onClick={() => { stop(); onClose(); }} aria-label="Đóng camera">
          <IconX size={24} />
        </button>
      </div>

      {!err && (
        <>
          <p className="camera-hint" id="camera-hint">
            Đưa mã QR vào giữa khung, giữ máy yên rồi nhấn <strong>Chụp ảnh</strong>.
          </p>
          <div className="camera-view">
            <video ref={videoRef} playsInline muted aria-describedby="camera-hint" />
            <div className="camera-frame" aria-hidden="true" />
            {status !== 'active' && (
              <p className="camera-status" role="status">Đang mở camera... Nếu trình duyệt hỏi, hãy chọn “Cho phép”.</p>
            )}
          </div>
          <button
            type="button"
            className="btn btn-primary btn-xl btn-block"
            onClick={handleCapture}
            disabled={status !== 'active' || capturing}
          >
            <IconCamera size={26} />
            <span>{capturing ? 'Đang chụp...' : 'Chụp ảnh'}</span>
          </button>
        </>
      )}

      {err && (
        <div className="notice notice-unknown" role="alert">
          <p className="notice-title">{err.title}</p>
          <p>{err.action}</p>
          <div className="btn-row">
            {error !== 'insecure' && error !== 'not_found' && (
              <button type="button" className="btn btn-secondary" onClick={start}>
                <IconRefresh size={20} />
                <span>Thử lại</span>
              </button>
            )}
            <button type="button" className="btn btn-primary" onClick={() => { stop(); onChooseFile(); }}>
              <IconUploadCloud size={20} />
              <span>Chọn ảnh hoặc PDF</span>
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
