/**
 * Client-side pre-check before upload (UX only — the server re-validates everything:
 * magic bytes, MIME consistency, size, pixels, pages). Never trust this as a security control.
 */

export const MAX_FILE_MB = 50;
export const MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024;

const ALLOWED_TYPES = new Set([
  'image/jpeg', 'image/jpg', 'image/pjpeg', 'image/png', 'image/webp', 'image/bmp', 'image/x-ms-bmp',
  'image/gif', 'image/tiff', 'application/pdf',
]);
const ALLOWED_EXT = /\.(jpe?g|png|webp|bmp|gif|tiff?|pdf)$/i;

export const ACCEPT_ATTR =
  'image/jpeg,image/png,image/webp,image/bmp,image/gif,image/tiff,application/pdf,.jpg,.jpeg,.png,.webp,.bmp,.gif,.tif,.tiff,.pdf';

/**
 * Returns null when the file looks acceptable, otherwise an error code understood by
 * `copyForError` (riskCopy.js): EMPTY_FILE | FILE_TOO_LARGE | UNSUPPORTED_FILE_TYPE.
 */
export function precheckFile(file) {
  if (!file) return 'EMPTY_FILE';
  if (typeof file.size === 'number' && file.size === 0) return 'EMPTY_FILE';
  if (typeof file.size === 'number' && file.size > MAX_FILE_BYTES) return 'FILE_TOO_LARGE';
  const type = String(file.type || '').toLowerCase();
  const name = String(file.name || '');
  // Some mobile browsers send an empty MIME type for camera images: fall back to the extension.
  if (type ? !ALLOWED_TYPES.has(type) : !ALLOWED_EXT.test(name)) return 'UNSUPPORTED_FILE_TYPE';
  return null;
}

export function isPdf(file) {
  return String(file?.type || '').toLowerCase() === 'application/pdf' || /\.pdf$/i.test(String(file?.name || ''));
}

export function formatFileSize(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
