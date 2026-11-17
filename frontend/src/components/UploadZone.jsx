/**
 * UploadZone — drag & drop area + hidden file input.
 * The input stays mounted for the whole app life so any screen (home, camera error) can open the
 * picker synchronously inside a user gesture. Validation here is UX only; the server re-validates.
 */
import { forwardRef, useImperativeHandle, useRef, useState } from 'react';
import { ACCEPT_ATTR } from '../lib/fileCheck';

/** Invisible picker. `ref.current.open()` opens the system file dialog. */
export const FilePicker = forwardRef(function FilePicker({ onFile }, ref) {
  const inputRef = useRef(null);
  useImperativeHandle(ref, () => ({
    open: () => inputRef.current?.click(),
  }), []);
  return (
    <input
      ref={inputRef}
      id="file-input"
      type="file"
      accept={ACCEPT_ATTR}
      className="visually-hidden"
      tabIndex={-1}
      aria-hidden="true"
      onChange={(e) => {
        const file = e.target.files && e.target.files[0];
        e.target.value = ''; // allow choosing the same file again
        if (file) onFile(file);
      }}
    />
  );
});

/** Wraps children with drag-and-drop support (desktop). */
export default function UploadZone({ onFile, children }) {
  const [dragging, setDragging] = useState(false);
  const depth = useRef(0);

  return (
    <div
      className={`drop-zone${dragging ? ' is-dragging' : ''}`}
      onDragEnter={(e) => {
        e.preventDefault();
        depth.current += 1;
        setDragging(true);
      }}
      onDragOver={(e) => e.preventDefault()}
      onDragLeave={() => {
        depth.current = Math.max(0, depth.current - 1);
        if (depth.current === 0) setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        depth.current = 0;
        setDragging(false);
        const file = e.dataTransfer.files && e.dataTransfer.files[0];
        if (file) onFile(file);
      }}
    >
      {children}
      {dragging && (
        <div className="drop-overlay" aria-hidden="true">
          <span>Thả ảnh hoặc PDF vào đây</span>
        </div>
      )}
    </div>
  );
}
