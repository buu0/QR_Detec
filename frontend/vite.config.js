import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      // 'prompt': the user is told when a new version exists (UpdatePrompt) instead of silently
      // running stale code; security fixes are applied on the next "Cập nhật ngay".
      registerType: 'prompt',
      includeAssets: ['favicon.svg', 'apple-touch-icon.png', 'pwa-maskable-512x512.png'],
      manifest: {
        id: '/',
        name: 'QRDetec — Kiểm tra mã QR trước khi sử dụng',
        short_name: 'QRDetec',
        description: 'Kiểm tra dấu hiệu lừa đảo trong mã QR và thông tin chuyển tiền VietQR.',
        lang: 'vi',
        theme_color: '#f5f3ee',
        background_color: '#f5f3ee',
        display: 'standalone',
        orientation: 'portrait',
        start_url: '/',
        scope: '/',
        categories: ['security', 'utilities', 'finance'],
        icons: [
          { src: 'pwa-192x192.png', sizes: '192x192', type: 'image/png' },
          { src: 'pwa-512x512.png', sizes: '512x512', type: 'image/png' },
          { src: 'pwa-maskable-512x512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg,png,ico,webmanifest,woff2}'],
        // Security requirement: never cache dynamic API responses, SSE/WS streams or scan results.
        runtimeCaching: [],
        navigateFallback: '/index.html',
        navigateFallbackDenylist: [/^\/api\//, /^\/ws\//],
        cleanupOutdatedCaches: true,
      },
    }),
  ],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: false },
      '/ws': { target: 'ws://localhost:8000', ws: true, changeOrigin: false },
    },
  },
})
