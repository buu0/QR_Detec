/**
 * usePWAInstall Hook
 * Quản lý sự kiện beforeinstallprompt, phát hiện nền tảng iOS/Android,
 * và điều khiển modal hướng dẫn cài đặt PWA.
 */
import { useState, useEffect, useCallback } from 'react';

export function usePWAInstall() {
  const [installPrompt, setInstallPrompt] = useState(null);
  const [isInstalled, setIsInstalled] = useState(false);
  const [isIOS, setIsIOS] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Kiểm tra đã chạy ở chế độ PWA (standalone) chưa — và theo dõi khi người dùng mở app đã cài
    const mq = window.matchMedia('(display-mode: standalone)');
    const syncMode = () => setIsInstalled(mq.matches || window.navigator.standalone === true);
    syncMode();
    mq.addEventListener?.('change', syncMode);
    if (mq.matches || window.navigator.standalone === true) {
      return () => mq.removeEventListener?.('change', syncMode);
    }

    // Kiểm tra iOS (Safari không hỗ trợ beforeinstallprompt)
    const ios = /iphone|ipad|ipod/i.test(navigator.userAgent) && !window.MSStream;
    setIsIOS(ios);

    // Android / Chrome: lắng nghe sự kiện
    const handler = (e) => {
      e.preventDefault();
      setInstallPrompt(e);
    };
    window.addEventListener('beforeinstallprompt', handler);

    // Lắng nghe khi cài đặt thành công
    const onInstalled = () => {
      setIsInstalled(true);
      setInstallPrompt(null);
      setGuideOpen(false);
    };
    window.addEventListener('appinstalled', onInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handler);
      window.removeEventListener('appinstalled', onInstalled);
      mq.removeEventListener?.('change', syncMode);
    };
  }, []);

  const triggerInstall = useCallback(async () => {
    if (installPrompt) {
      try {
        installPrompt.prompt();
        const { outcome } = await installPrompt.userChoice;
        if (outcome === 'accepted') {
          setIsInstalled(true);
          setInstallPrompt(null);
          return;
        }
      } catch {
        // Fallback mở hướng dẫn nếu người dùng hủy hoặc trình duyệt lỗi
      }
    }
    // Mở popup hướng dẫn cho iOS hoặc thiết bị chưa kích hoạt prompt tự động
    setGuideOpen(true);
  }, [installPrompt]);

  const openGuide = useCallback(() => setGuideOpen(true), []);
  const closeGuide = useCallback(() => setGuideOpen(false), []);

  const canInstall = !isInstalled;

  return {
    canInstall,
    isInstalled,
    isIOS,
    canPrompt: !!installPrompt,
    guideOpen,
    openGuide,
    closeGuide,
    triggerInstall,
  };
}
