/**
 * InstallGuideModal — Hướng dẫn chi tiết cài đặt PWA cho iOS (iPhone/iPad) và Android.
 * Hỗ trợ chuyển đổi tab thiết bị, tự động nhận diện nền tảng, và tương thích trợ năng.
 */
import { useEffect, useRef, useState } from 'react';
import {
  IconApple,
  IconAndroid,
  IconShare,
  IconPlusSquare,
  IconMoreVertical,
  IconDownload,
  IconCheck,
  IconX,
} from './Icons';

export default function InstallGuideModal({
  isOpen,
  onClose,
  isIOS = false,
  canPrompt = false,
  onTriggerInstall = null,
}) {
  const [tab, setTab] = useState(isIOS ? 'ios' : 'android');
  const dialogRef = useRef(null);
  const closeRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      setTab(isIOS ? 'ios' : 'android');
    }
  }, [isOpen, isIOS]);

  useEffect(() => {
    if (!isOpen) return undefined;
    const prevOverflow = document.body.style.overflow;
    const opener = document.activeElement;
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus();
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      if (e.key !== 'Tab' || !dialogRef.current) return;
      const items = [...dialogRef.current.querySelectorAll('button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])')];
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener('keydown', handleKeyDown);
      if (opener && typeof opener.focus === 'function') opener.focus();
    };
  }, [isOpen, onClose]);

  const onTabKey = (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const next = tab === 'ios' ? 'android' : 'ios';
      setTab(next);
      document.getElementById(`pwa-tab-${next}`)?.focus();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        ref={dialogRef}
        className="modal-card install-guide-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="pwa-guide-title"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="modal-header-text">
            <h2 id="pwa-guide-title" className="modal-title">Cài đặt ứng dụng QRDetec</h2>
            <p className="modal-subtitle">
              Mở nhanh từ màn hình chính, chạy toàn màn hình như ứng dụng thật.
            </p>
          </div>
          <button
            ref={closeRef}
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Đóng cửa sổ hướng dẫn"
          >
            <IconX size={18} />
          </button>
        </div>

        {/* Bộ chọn nền tảng (Tabs) */}
        <div className="guide-tabs" role="tablist" aria-label="Chọn hệ điều hành">
          <button
            type="button"
            role="tab"
            id="pwa-tab-ios"
            aria-selected={tab === 'ios'}
            aria-controls="pwa-panel"
            tabIndex={tab === 'ios' ? 0 : -1}
            className={`guide-tab ${tab === 'ios' ? 'tab-active' : ''}`}
            onClick={() => setTab('ios')}
            onKeyDown={onTabKey}
          >
            <IconApple size={16} />
            <span>iPhone / iPad</span>
          </button>
          <button
            type="button"
            role="tab"
            id="pwa-tab-android"
            aria-selected={tab === 'android'}
            aria-controls="pwa-panel"
            tabIndex={tab === 'android' ? 0 : -1}
            className={`guide-tab ${tab === 'android' ? 'tab-active' : ''}`}
            onClick={() => setTab('android')}
            onKeyDown={onTabKey}
          >
            <IconAndroid size={16} />
            <span>Android</span>
          </button>
        </div>

        <div className="modal-scroll-area">
          {/* Nội dung Hướng dẫn cho iPhone (Safari) */}
          {tab === 'ios' && (
            <div className="guide-content" role="tabpanel" id="pwa-panel" aria-labelledby="pwa-tab-ios">
              <div className="guide-callout callout-ios">
                <span className="callout-badge">Lưu ý quan trọng</span>
                <p>
                  Apple yêu cầu mở trang web bằng trình duyệt <strong>Safari</strong> để cài đặt. Nếu bạn đang mở từ Zalo hoặc Facebook, hãy bấm dấu 3 chấm và chọn <em>&quot;Mở bằng Safari&quot;</em>.
                </p>
              </div>

              <ol className="guide-steps">
                <li className="guide-step-item">
                  <div className="step-num">1</div>
                  <div className="step-body">
                    <strong>Nhấn nút Chia sẻ</strong>
                    <p>
                      Ở thanh công cụ dưới đáy màn hình Safari, nhấn biểu tượng <strong>Chia sẻ</strong> (<IconShare size={14} className="inline-icon" /> hình ô vuông có mũi tên hướng lên).
                    </p>
                  </div>
                </li>
                <li className="guide-step-item">
                  <div className="step-num">2</div>
                  <div className="step-body">
                    <strong>Chọn &quot;Thêm vào MH chính&quot;</strong>
                    <p>
                      Cuộn bảng tùy chọn xuống dưới và chọn dòng <strong>&quot;Thêm vào MH chính&quot;</strong> (<IconPlusSquare size={14} className="inline-icon" /> Add to Home Screen).
                    </p>
                  </div>
                </li>
                <li className="guide-step-item">
                  <div className="step-num">3</div>
                  <div className="step-body">
                    <strong>Xác nhận Thêm</strong>
                    <p>
                      Nhấn nút <strong>&quot;Thêm&quot; (Add)</strong> ở góc trên bên phải màn hình. Biểu tượng QRDetec sẽ xuất hiện ngay trên màn hình chính của bạn.
                    </p>
                  </div>
                </li>
              </ol>
            </div>
          )}

          {/* Nội dung Hướng dẫn cho Android (Chrome) */}
          {tab === 'android' && (
            <div className="guide-content" role="tabpanel" id="pwa-panel" aria-labelledby="pwa-tab-android">
              {canPrompt && onTriggerInstall && (
                <div className="guide-quick-action">
                  <p>Trình duyệt đã sẵn sàng để cài đặt tự động:</p>
                  <button
                    type="button"
                    className="btn-quick-install"
                    onClick={() => {
                      onTriggerInstall();
                      onClose();
                    }}
                  >
                    <IconDownload size={16} />
                    <span>Cài đặt ứng dụng ngay</span>
                  </button>
                </div>
              )}

              <div className="guide-callout callout-android">
                <span className="callout-badge">Khuyên dùng</span>
                <p>Mở trang web trên trình duyệt <strong>Google Chrome</strong>, <strong>Samsung Internet</strong> hoặc <strong>Cốc Cốc</strong>.</p>
              </div>

              <ol className="guide-steps">
                <li className="guide-step-item">
                  <div className="step-num">1</div>
                  <div className="step-body">
                    <strong>Mở Menu trình duyệt</strong>
                    <p>
                      Nhấn vào biểu tượng <strong>Menu 3 dấu chấm</strong> (<IconMoreVertical size={14} className="inline-icon" />) ở góc trên bên phải thanh địa chỉ.
                    </p>
                  </div>
                </li>
                <li className="guide-step-item">
                  <div className="step-num">2</div>
                  <div className="step-body">
                    <strong>Chọn &quot;Cài đặt ứng dụng&quot;</strong>
                    <p>
                      Tìm và chọn dòng <strong>&quot;Cài đặt ứng dụng&quot;</strong> (Install app) hoặc <strong>&quot;Thêm vào màn hình chính&quot;</strong>.
                    </p>
                  </div>
                </li>
                <li className="guide-step-item">
                  <div className="step-num">3</div>
                  <div className="step-body">
                    <strong>Xác nhận Cài đặt</strong>
                    <p>
                      Nhấn <strong>&quot;Cài đặt&quot; (Install)</strong> trong hộp thoại thông báo để hoàn tất.
                    </p>
                  </div>
                </li>
              </ol>
            </div>
          )}

          {/* Quyền lợi khi cài đặt PWA */}
          <div className="guide-perks">
            <div className="perk-item">
              <IconCheck size={14} className="perk-icon" />
              <span>Mở bằng một chạm từ màn hình chính</span>
            </div>
            <div className="perk-item">
              <IconCheck size={14} className="perk-icon" />
              <span>Toàn màn hình, không có thanh địa chỉ</span>
            </div>
            <div className="perk-item">
              <IconCheck size={14} className="perk-icon" />
              <span>Dung lượng nhỏ, cài trong vài giây</span>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" className="btn-modal-done" onClick={onClose}>
            Đã hiểu
          </button>
        </div>
      </div>
    </div>
  );
}
