# QRDetec — Hệ thống phân tích rủi ro bảo mật từ mã QR

QRDetec là hệ thống phân tích tĩnh mã QR nhằm phát hiện liên kết lừa đảo (Quishing) và kiểm tra tính nhất quán ngữ cảnh thanh toán VietQR trên hình ảnh hoặc tài liệu PDF. Hệ thống bao gồm giao diện web lũy tiến (React PWA) và cụm dịch vụ xử lý cô lập phía máy chủ (Nginx, FastAPI, Redis, Celery).

Toàn bộ quá trình kiểm tra tuân thủ nguyên tắc **Target-Fetch-Free (Zero-Egress / Zero-SSRF)**: hệ thống chỉ giải mã và phân tích cấu trúc dữ liệu bên trong mã QR cùng văn bản hiển thị trên ảnh/PDF, không truy cập hay gửi yêu cầu mạng tới URL đích.

---

## 1. Kiến trúc tổng thể

```text
                       Trình duyệt / Thiết bị di động (React PWA)
                                           │
                                           ▼
                              Nginx Reverse Proxy (Port 80)
                  [Giới hạn tần suất 2 req/s, Security Headers, kiểm tra CSRF]
                                           │
                                           ▼
                               FastAPI Upload Security Gate
                  [Đọc tệp theo luồng, tính SHA-256, kiểm tra Magic Bytes]
                                           │
                                           ▼
                               Redis Task Broker & Result Store
                      [Xác thực ACL, cô lập mạng nội bộ, lưu đệm kết quả]
                                           │
                                           ▼
                                  Celery Worker Sandbox
                    [Tài khoản appuser UID 1000, read-only rootfs, cap_drop ALL]
                                           │
                ┌──────────────────────────┴──────────────────────────┐
                ▼                                                     ▼
      Xử lý Ảnh / Tài liệu PDF                              Giải mã QR Kép (Dual-Stage)
 [Kiểm tra kích thước Pillow / PyMuPDF]            [WeChatQRCode CNN + ZBar UTF-8 Repair & IoU]
                │                                                     │
                └──────────────────────────┬──────────────────────────┘
                                           ▼
                                 Phân loại nội dung QR
                                           │
          ┌────────────────────────────────┴────────────────────────────────┐
          ▼                                                                 ▼
 A. LUỒNG PHÂN TÍCH BẢO MẬT URL                                  B. LUỒNG ĐỐI CHIẾU VIETQR
 (URL HTTP/HTTPS & Giao thức URI)                                (Mã thanh toán EMVCo / NAPAS)
          │                                                                 │
 1. Chuẩn hóa & kiểm tra giao thức URL                           1. Phân tích cấu trúc TLV nghiêm ngặt
    (Punycode/IDNA, userinfo, IP literal, độ dài)                2. Kiểm tra mã toàn vẹn CRC-16 (CCITT-FALSE)
 2. Trích xuất 81 đặc trưng tĩnh (Feature Extractor)             3. Kiểm tra ngữ nghĩa (VND=704, VN, GUID NAPAS)
    (Cấu trúc, Entropy, Thương hiệu VN, IDN UTS #39)                -> Phát kết quả cấu trúc tạm thời (Provisional)
 3. Cảm biến máy học XGBoost + Giải thích TreeSHAP               4. Nhận dạng văn bản OCR (PaddleOCR) trên ảnh render
    (676 cây, Xác suất Isotonic 96 nút, ngưỡng t*=0.5975 & log-odds)       kết hợp lọc văn bản gốc từ PDF (_span_visible)
 4. Tra cứu chỉ báo độc hại cục bộ (Local IOC)                   5. Gom cụm không gian 2D & gắn kết trường thanh toán
    (Đối chiếu 593.049 IOC ngoại tuyến đã ghim SHA-256)              (Ngân hàng, Số tài khoản/thẻ, Tên, Số tiền)
 5. Tổng hợp tại Central Policy Engine                           6. Đối chiếu từng trường QR vs văn bản hiển thị
          │                                                         -> Phát kết luận ngữ cảnh cuối cùng (Final)
          └────────────────────────────────┬────────────────────────────────┘
                                           ▼
               Phán quyết cuối cùng, Giải thích XAI & Các bước khuyến nghị theo ngữ cảnh
                            (Truyền về giao diện qua WebSocket / SSE)
```

---

## 2. Nguyên tắc xử lý và phân định trách nhiệm

### 2.1. Giải mã QR kép và khử trùng lặp không gian (`qr_decoder.py`)
- Hệ thống kết hợp bộ giải mã **ZBar (`pyzbar`)** và mô hình CNN **OpenCV `WeChatQRCode`** trên nhiều phép tiền xử lý ảnh.
- Tự động khôi phục chuỗi **UTF-8** bị `libzbar` diễn giải nhầm sang bảng mã `Big5` (`_repair_zbar_utf8`, ví dụ các ký tự Kirin đồng hình trong tên miền IDN Homograph) và gộp trùng lặp theo độ chồng lấp khung bao hình học (`IoU >= 0.70`), đảm bảo mỗi mã QR vật lý chỉ xuất ra một payload chuẩn xác duy nhất.

### 2.2. Phân tích bảo mật URL (Đơn pha)
Đối với liên kết web (`http://`, `https://`), worker thực hiện một pha phân tích hoàn chỉnh trước khi trả kết quả:

1. **Chuẩn hóa và phân loại giao thức (`normalizer.py`)**:
   - Các URI có khả năng thực thi hoặc truy cập cục bộ (`javascript:`, `data:`, `file:`, `intent:`, `blob:`, `vbscript:`) được gắn nhãn `SUSPICIOUS` ngay ở bước phân loại.
   - Các URI gọi ứng dụng liên lạc (`mailto:`, `tel:`, `sms:`) được phân loại là `NO_KNOWN_RISK` kèm mã cảnh báo `UNSUPPORTED_URI` để người dùng tự kiểm tra số điện thoại hoặc địa chỉ nhận.
   - Các giao thức phi web khác (`ftp:`, `ssh:`, `wifi:`, `smsto:`, ...) được trả về `UNVERIFIABLE`; giao diện vẫn diễn giải nội dung mã (tên mạng Wi-Fi, mạng mở hay có mật khẩu, đầu số và nội dung tin nhắn soạn sẵn) để người dùng tự quyết định.
   - Kiểm tra cấu trúc RFC 3986, giới hạn độ dài `4096` ký tự, giải mã Punycode/IDNA, và phát hiện thành phần xác thực `userinfo (@)` hoặc địa chỉ IP nội bộ/cục bộ (`PRIVATE_OR_LOCAL_HOST`).
2. **Cảm biến máy học XGBoost & Giải thích cục bộ TreeSHAP (`model_service.py`)**:
   - Sử dụng gói mô hình chuẩn hóa `qrdetec-url-xgb` với **81 đặc trưng** trích xuất tĩnh từ chuỗi URL (huấn luyện trên `92.006` URL chia 4 tập tách biệt hoàn toàn theo `60.836` cụm tên miền `eTLD+1`).
   - Xác suất thô từ mô hình (`raw_score`) được hiệu chuẩn qua bộ hiệu chuẩn Isotonic (`calibrator.json`, 96 nút) thành `model_score` và so sánh với ngưỡng vận hành tối ưu `0.597483` (`t* = 0.5975`, `ml_prediction`).
   - Tích hợp **TreeSHAP (`pred_contribs=True`)** phân rã chính xác điểm `log-odds` ($z = \phi_0 + \sum_{i=1}^{81} \phi_i$) trên 676 cây hoạt động (`best_iteration = 675`) để trích xuất các đặc trưng đẩy rủi ro tăng (`shap_top_risk`) và kéo rủi ro giảm (`shap_top_benign`). Giao diện diễn giải các đóng góp này thành câu tiếng Việt đời thường (xem mục 3).
3. **Tình báo mối đe dọa cục bộ (`threat_intel.py`)**:
   - Đối chiếu tên miền và URL đã chuẩn hóa với tệp dữ liệu cục bộ (`ti_feed/ioc_feed.jsonl` chứa `593.049` chỉ báo độc hại gồm `502.442` tên miền và `90.607` mã băm SHA-256 URL chính xác).
   - Trả về đúng trạng thái thực tế: `MATCH`, `NO_MATCH`, `NOT_CONFIGURED`, `INTEGRITY_FAILED`, `LOAD_ERROR`, hoặc `NOT_APPLICABLE`. Khi trùng khớp chỉ báo còn hiệu lực (`MATCH`), chính sách trung tâm lập tức nâng phán quyết lên `MALICIOUS`.
4. **Chính sách hợp nhất (`policy.py`) & Hướng dẫn xử lý theo ngữ cảnh (`riskCopy.js`)**:
   - `policy.py` là thành phần duy nhất đưa ra phán quyết cuối cùng (`MALICIOUS`, `SUSPICIOUS`, `NO_KNOWN_RISK`, `UNVERIFIABLE`, `INVALID`) từ sự kết hợp trực tiếp giữa Kiểm tra giao thức, Local Threat Intelligence và Cảm biến máy học XGBoost 81 đặc trưng (`URL_MODEL_HIGH_THRESHOLD = 0.597483`, `URL_MODEL_MEDIUM_THRESHOLD = 0.5000`).
   - Giao diện frontend chỉ hiển thị phán quyết từ backend (không tự suy luận hay so ngưỡng) và **ghép phần giải thích + các bước xử lý từ bằng chứng thật của từng lần quét** (`contextNarrative.js`), xem mục 3.

### 2.3. Đối chiếu ngữ cảnh thanh toán VietQR (Lũy tiến)
Đối với mã thanh toán theo chuẩn EMVCo / NAPAS VietQR:

1. **Kiểm tra cấu trúc**: Giải mã cây TLV, kiểm tra thẻ trùng lặp, xác thực GUID NAPAS (`A000000727`), mã dịch vụ (`QRIBFTTA` chuyển qua tài khoản hoặc `QRIBFTTC` chuyển qua số thẻ), mã tiền tệ (`704`), mã quốc gia (`VN`) và mã kiểm tra `CRC-16/CCITT-FALSE`. Ngay khi bước này hoàn tất, worker gửi thông tin cấu trúc tạm thời (*provisional*) về giao diện để người dùng nắm được thông tin tài khoản thụ hưởng trong mã QR.
2. **Kiểm tra ngữ cảnh hiển thị**: Nếu ảnh hoặc trang PDF có văn bản đi kèm (hóa đơn, bảng giá, standee quầy thu ngân), hệ thống trích xuất văn bản bằng PaddleOCR (kết hợp lọc các lớp chữ ẩn/trong suốt trên PDF số), chuẩn hóa các ký tự số dễ nhầm lẫn theo ngữ cảnh số (`O/o` $\to$ `0`, `l/I` $\to$ `1`), xử lý nhãn bị dính chữ hoặc tách dòng (`Chủ TK:`, `Số tiền:`), khôi phục chữ `I` hoa bị OCR đọc thành `l` thường trong từ in hoa, loại trừ tiêu đề/khẩu hiệu in hoa và ưu tiên đối chiếu theo độ tin cậy nguồn (`keyword` > `standee_adjacent` > `upper`) cho từng trường (`Ngân hàng`, `Số tài khoản / Số thẻ`, `Tên người nhận`, `Số tiền`, `Nội dung`).
3. **Kết luận ngữ cảnh**: Trả về một trong các trạng thái `CONTEXT_CONSISTENT` (khớp ngữ cảnh), `PARTIAL_MATCH` (khớp một phần), `CRITICAL_MISMATCH` (mâu thuẫn thông tin nhận tiền — dấu hiệu dán đè hoặc tráo mã QR), `INSUFFICIENT_CONTEXT` (ảnh không đủ chữ để đối chiếu), hoặc `INVALID_PAYLOAD` (lỗi cấu trúc TLV/CRC).

### 2.4. Giới hạn ngữ nghĩa và các khẳng định không đưa ra (Non-Claims)
- **`NO_KNOWN_RISK` không đồng nghĩa với "An toàn"**: Trạng thái này chỉ phản ánh rằng các bước kiểm tra tĩnh và danh sách Local IOC hiện có chưa ghi nhận dấu hiệu độc hại đã biết. Hệ thống không bao giờ hiển thị nhãn khẳng định "An toàn tuyệt đối".
- **`CRC-16 hợp lệ` không xác thực người nhận**: Mã kiểm tra CRC-16 chỉ đảm bảo chuỗi dữ liệu QR không bị lỗi truyền tải hoặc sửa đổi ngoài ý muốn; kẻ tấn công hoàn toàn có thể tạo mã QR mới với CRC-16 hợp lệ cho tài khoản của họ.
- **`CONTEXT_CONSISTENT` không thay thế bước xác nhận trên ứng dụng ngân hàng**: Việc thông tin trong mã QR khớp với chữ in trên ảnh giúp phát hiện hành vi dán đè mã QR giả lên bảng thông tin thật, nhưng không chứng minh bản thân tờ hóa đơn/standee đó thuộc về đơn vị uy tín.

---

## 3. Giao diện người dùng (React PWA)

### 3.1. Giải thích theo ngữ cảnh, không gán cứng (`frontend/src/lib/contextNarrative.js`)
Mỗi kết quả có khung **"Tình huống: …"** và mục **"Bạn nên làm gì"** được ghép từ dữ liệu thật của chính lần quét đó, không dùng đoạn văn cố định theo mã cảnh báo:
- **URL**: tên miền IDN được giải mã Punycode và chỉ ra ký tự đồng hình (ví dụ `і` U+0456 chữ Kirin), tên thương hiệu bị mượn so với tên miền chính thức, đuôi tên miền giá rẻ, từ khóa dụ dỗ (`đăng nhập`, `OTP`, `sinh trắc học`…), địa chỉ chuyển tiếp ẩn, nguồn Local IOC kèm ngày ghi nhận, và cách lớp IOC phối hợp với mô hình AI.
- **VietQR**: loại ngữ cảnh OCR (hóa đơn / kêu gọi quyên góp / standee), từng trường lệch giữa chữ in và mã QR (kể cả tỉ lệ số tiền, ví dụ "gấp 10 lần"), và bước xử lý dùng đúng STK/tên in trên ảnh.
- **Mã phi web**: Wi-Fi (tên mạng, mạng mở), SMS/điện thoại (đầu số ngắn, nội dung có OTP), email.
- Mỗi thông tin chỉ xuất hiện một lần trên trang: *Kết luận → Dữ liệu gốc trong mã QR → Vì sao → Bạn nên làm gì → Bằng chứng chi tiết*. Dữ liệu gốc (chuỗi giải mã nguyên văn, kèm dạng sau chuẩn hóa nếu khác) nằm ngay dưới kết luận để đối sánh với các trường đã phân tích.
- Khi khớp **Local IOC**, thẻ bằng chứng hiển thị thông tin chỉ báo bằng lời thường (`frontend/src/lib/iocDetails.js`): khớp ở đâu (tên miền / toàn bộ URL / địa chỉ chuyển tiếp ẩn), nguồn (Phishing.Database, URLhaus, CERT Polska, ChongLuaDao VN) kèm mô tả, loại chỉ báo, ngày ghi nhận, hạn, độ tin cậy và độ mới.

### 3.2. TreeSHAP cho người dùng phổ thông (`frontend/src/lib/shapPlain.js`)
Đóng góp TreeSHAP của 81 đặc trưng được chuyển thành câu mô tả điều AI nhìn thấy trong liên kết (ví dụ *"Tên miền dùng đuôi ".top", loại đuôi hay gặp ở các trang lừa đảo"*) kèm mức ảnh hưởng bằng chữ (*nhiều / vừa / ít*), không hiển thị log-odds. Các số liệu chính xác (`raw_score`, `model_score`, `ml_threshold`, `shap_base_value`, SHAP từng đặc trưng) vẫn có trong phản hồi API (`url_analysis.model`) để kiểm tra.

### 3.3. Thiết kế và PWA
- Lớp thiết kế `frontend/src/styles/redesign.css`: nền giấy ấm + chữ mực, màu chỉ dùng cho kết luận; hỗ trợ sáng/tối, cỡ chữ lớn, giảm chuyển động.
- Font **Be Vietnam Pro** và **JetBrains Mono** được đóng gói cục bộ qua `@fontsource` (không gọi CDN bên thứ ba) và được precache để dùng offline.
- Manifest PWA: tên `QRDetec`, `id`/`scope` = `/`, icon thường + icon maskable riêng; khi chạy ở chế độ đã cài (standalone) giao diện ẩn nút cài đặt và tôn trọng vùng an toàn (tai thỏ, thanh home).
- Service worker không bao giờ cache kết quả API/SSE/WebSocket (`runtimeCaching: []`).

---

## 4. Cơ chế bảo vệ an toàn thực thi

- **Kiểm soát tệp tải lên (`body_limit.py`, `file_safety.py`, `routes.py`)**:
  - Chặn sớm dung lượng yêu cầu ngay tại tầng ASGI (`BodySizeLimitMiddleware`) và đọc dữ liệu tải lên theo từng khối (chunked streaming), giới hạn dung lượng tối đa `50 MB` (`MAX_FILE_SIZE_MB`) kể cả khi yêu cầu lược bỏ header `Content-Length`.
  - Xác thực định dạng thực tế (PNG, JPEG, WebP, PDF) bằng chữ ký byte đầu tệp (Magic Bytes), không phụ thuộc vào header `Content-Type` từ phía client.
  - Lưu tệp tạm bằng tên định danh UUID do máy chủ sinh ra, kiểm tra đường dẫn thực (`os.path.realpath`) và xóa ngay sau khi xử lý xong.
- **Kiểm soát phiên, CSRF, Origin và chống ngập hàng đợi (`security.py`, `routes.py`, `qrguard_server.conf`)**:
  - Xác thực `Origin` theo bộ ba `(scheme, hostname, port)` nghiêm ngặt (chỉ chấp nhận `https://` khi `ENVIRONMENT=production` và từ chối khởi động nếu `SESSION_COOKIE_SECURE=false`), kết hợp bắt buộc header `X-QRGuard-Request: 1` đối với các yêu cầu tải tệp.
  - Quản lý hạn ngạch đồng thời nguyên tử bằng kịch bản **Redis Lua (`EVAL`)**: giới hạn tối đa `3` tác vụ/phiên (`MAX_ACTIVE_JOBS_PER_SESSION`), `8` tác vụ/mạng máy khách IPv4 hoặc IPv6 `/64` độc lập với cookie (`MAX_ACTIVE_JOBS_PER_CLIENT`), `40` tác vụ toàn hệ thống (`MAX_GLOBAL_ACTIVE_JOBS`), và `6` kết nối luồng SSE/WebSocket trên mỗi phiên (`MAX_STREAMS_PER_SESSION`).
  - Giới hạn tốc độ khung tin nhắn WebSocket chiều lên (`10` tin nhắn / `10 giây` qua `WS_MAX_INBOUND_MESSAGES`) và ẩn đường dẫn kiểm tra nội bộ `/api/health/ready` (`404` tại Nginx).
- **Chống tấn công cạn kiệt tài nguyên (Decompression Bomb)**:
  - Với ảnh: kiểm tra kích thước từ header qua Pillow trước khi giải mã điểm ảnh; từ chối tệp vượt quá `8000×8000 px` hoặc `36 MP` (`MAX_IMAGE_PIXELS`).
  - Với PDF: tính số điểm ảnh dự kiến trước khi raster hóa từng trang; giới hạn tối đa `10 trang` (`MAX_PDF_PAGES`), `16 MP/trang` (`MAX_PDF_PAGE_PIXELS`) và `50 MP` tổng cộng toàn tài liệu (`MAX_TOTAL_RENDERED_PIXELS`).
- **Cô lập container (`docker-compose.yml`)**:
  - Các dịch vụ chạy bằng tài khoản không đặc quyền (`appuser`, UID 1000), hệ thống tệp gốc chỉ đọc (`read_only: true`), gỡ bỏ toàn bộ Linux capabilities (`cap_drop: ALL`) và bật `no-new-privileges: true`.
  - Thư mục tạm được gắn qua `tmpfs` với cờ `noexec,nosuid`.
  - Cổng `8000` của FastAPI và `6379` của Redis chỉ mở trong mạng nội bộ container; chỉ cổng `80` của Nginx tiếp nhận kết nối từ bên ngoài.
- **Đảm bảo toàn vẹn mô hình máy học (`backend/models/url_xgb/`)**:
  - Khi worker khởi động, gói mô hình được kiểm tra chữ ký `SHA-256` cho toàn bộ tệp thành phần (`model.ubj`, `feature_schema.json`, `feature_names.json`, `calibrator.json`, `thresholds.json`, `metrics.json`) và chạy kiểm chuẩn trên 16 vector chuẩn (`golden_vectors.json`).
  - Nếu thiếu tệp, lệch mã băm hoặc sai lệch kết quả suy luận mẫu, dịch vụ mô hình tự động chuyển sang trạng thái `INVALID_ARTIFACT` / `INCOMPATIBLE_FEATURE_SCHEMA` và hệ thống tiếp tục phân tích bằng Kiểm tra giao thức cùng Local IOC mà không làm gián đoạn dịch vụ.

---

## 5. Cấu trúc thư mục

```text
QRDetec/
├── backend/                        # Dịch vụ API Gateway (FastAPI) và Worker xử lý nền (Celery)
│   ├── app/
│   │   ├── api/                    # Định tuyến tải tệp, luồng sự kiện SSE/WebSocket và kiểm tra phiên
│   │   ├── core/                   # Cấu hình hệ thống, giới hạn luồng ASGI, bảo mật phiên/CSRF/Lua và mã lỗi
│   │   ├── models/                 # Lược đồ dữ liệu Pydantic (Schemas)
│   │   ├── services/               # Giải mã QR, OCR, phân tích VietQR, đối chiếu không gian và bảo mật URL
│   │   └── worker/                 # Khởi tạo Celery worker và điều phối luồng xử lý
│   ├── models/url_xgb/             # Gói mô hình runtime 81 đặc trưng kèm SHA256SUMS và golden_vectors.json
│   └── scripts/verify_url_model.py # Kịch bản kiểm tra tính toàn vẹn của mô hình runtime
├── frontend/                       # Giao diện người dùng React 18 + Vite 5 (Progressive Web App)
│   └── src/
│       ├── components/             # Các thành phần giao diện hiển thị phán quyết, bằng chứng URL (TreeSHAP) và VietQR
│       ├── hooks/                  # Quản lý camera, luồng quét và cài đặt PWA
│       ├── lib/                    # Văn bản cảnh báo, giải thích theo ngữ cảnh (contextNarrative), TreeSHAP dễ hiểu (shapPlain)
│       ├── styles/                 # Lớp thiết kế giao diện (redesign.css)
│       └── services/               # Giao tiếp API, tự động chuyển đổi dự phòng WebSocket -> SSE -> Polling
├── demo_samples/                   # Mẫu 01–21 & kịch bản kiểm thử 8 lớp bảo vệ (HUONG_DAN_DEMO.md)
│   └── tinh_huong_thuc_te/         # 12 ảnh QR tình huống thực tế tại Việt Nam (22–33) + bảng kết quả mong đợi
├── nginx/                          # Cấu hình Nginx reverse proxy, giới hạn tốc độ và security headers
├── redis/                          # Cấu hình Redis và mẫu phân quyền ACL
├── scripts/                        # Công cụ sinh khóa bí mật (generate_secrets.py) và xây dựng Local IOC (build_ioc_feed.py)
├── ti_feed/                        # Thư mục chứa tệp dữ liệu Local IOC ngoại tuyến
├── docker-compose.yml              # Cấu hình triển khai container mặc định
└── docker-compose.dev.yml          # Cấu hình ghi đè khi chạy phát triển qua giao thức HTTP nội bộ
```

---

## 6. Biến môi trường chính

| Biến môi trường | Giá trị mặc định | Mô tả |
|---|---|---|
| `ENVIRONMENT` | `production` (trong Compose) | Chế độ vận hành (`development` hoặc `production`). Ở `production`, hệ thống bắt buộc bật cookie `Secure` và loại bỏ các origin loopback khỏi CORS. |
| `ENABLE_API_DOCS` | `false` | Bật/tắt tài liệu OpenAPI tại `/api/docs` (chỉ có hiệu lực khi `ENVIRONMENT` khác `production`). |
| `SESSION_COOKIE_SECURE` | `true` | Đặt cờ `Secure` cho cookie phiên `qrg_sid` (chỉ đặt `false` khi chạy thử qua HTTP nội bộ với `docker-compose.dev.yml`). |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173,...` | Danh sách origin được phép gọi API / WebSocket, phân tách bằng dấu phẩy. |
| `REDIS_URL` | `redis://localhost:6379/0` | Chuỗi kết nối Redis (trong Docker Compose được nạp tự động qua tệp bí mật `REDIS_URL_FILE`). |
| `STORAGE_PATH` | `/app/storage` | Thư mục lưu tệp tải lên tạm thời trước khi worker xử lý. |
| `MAX_FILE_SIZE_MB` | `50` | Dung lượng tệp tải lên tối đa (MB). |
| `MAX_PDF_PAGES` | `10` | Số trang tối đa được phép xử lý trong một tệp PDF. |
| `MAX_ACTIVE_JOBS_PER_SESSION` | `3` | Số tác vụ đang chờ hoặc đang xử lý tối đa trên mỗi phiên người dùng. |
| `MAX_ACTIVE_JOBS_PER_CLIENT` | `8` | Số tác vụ đồng thời tối đa trên mỗi mạng máy khách (IPv4 hoặc IPv6 `/64`), độc lập với cookie phiên. |
| `MAX_GLOBAL_ACTIVE_JOBS` | `40` | Tổng số tác vụ đang chờ hoặc đang xử lý tối đa trên toàn hệ thống. |
| `TRUST_PROXY_HEADERS` | `true` | Tin cậy header `X-Real-IP` từ Nginx reverse proxy nội bộ để tính hạn ngạch theo mạng máy khách. |
| `MAX_STREAMS_PER_SESSION` | `6` | Số kết nối SSE/WebSocket đồng thời tối đa trên mỗi phiên. |
| `WS_MAX_INBOUND_MESSAGES` | `10` | Số tin nhắn chiều lên tối đa cho phép trên mỗi kết nối WebSocket trong cửa sổ `WS_INBOUND_WINDOW_SECONDS` (`10s`). |
| `JOB_QUEUE_MAX_WAIT_SECONDS` | `300` | Thời gian tối đa (giây) một tác vụ được phép nằm chờ trong hàng đợi trước khi bị từ chối. |
| `RESULT_CACHE_TTL` | `3600` | Thời gian lưu kết quả và trạng thái tác vụ trong Redis (giây). |
| `FILE_RESULT_CACHE_TTL` | `1800` | Thời gian lưu đệm kết quả theo mã băm tệp + mã băm Local IOC feed + chế độ giải mã (giây). |
| `ORPHAN_FILE_MAX_AGE_SECONDS` | `900` | Ngưỡng tuổi tệp tạm mồ côi để tác vụ dọn dẹp định kỳ xóa bỏ (giây). |
| `QR_DECODE_MODE` | `fast` | Chế độ giải mã QR: `fast` (ưu tiên tốc độ) hoặc `complete` (quét đa tầng pyzbar + WeChatQR). |
| `URL_LENGTH_LIMIT` | `4096` | Độ dài ký tự tối đa của chuỗi URL được phân tích. |
| `TI_LOCAL_FEED_PATH` | `/app/ti_feed/ioc_feed.jsonl` | Đường dẫn tệp dữ liệu chỉ báo Local IOC cục bộ. |
| `TI_LOCAL_FEED_SHA256` | `""` | Mã băm SHA-256 dùng để xác minh tính toàn vẹn của tệp Local IOC khi nạp. |
| `TI_IOC_MAX_AGE_DAYS` | `90` | Số ngày tối đa tính từ lần ghi nhận cuối trước khi chỉ báo IOC bị xem là cũ (`stale`). |
| `URL_MODEL_HIGH_THRESHOLD` | `0.597483` | Ngưỡng xác suất mô hình mức cao (`ML_HIGH_RISK`, tối đa hóa Recall tại `FPR_val <= 5%`). |
| `URL_MODEL_MEDIUM_THRESHOLD` | `0.50` | Ngưỡng xác suất mô hình mức trung bình (`ML_MODERATE_RISK`). |

---

## 7. Hướng dẫn cài đặt và vận hành

### 7.1. Chuẩn bị cấu hình và khóa bí mật
```bash
# 1. Tạo tệp .env từ mẫu cấu hình
cp .env.example .env

# 2. Sinh mật khẩu Redis ngẫu nhiên (tạo secrets/redis_url và redis/users.acl)
python scripts/generate_secrets.py

# 3. (Tùy chọn) Tải và xây dựng tệp dữ liệu Local IOC kèm ghi mã băm SHA-256 vào .env
python scripts/build_ioc_feed.py --write-env
```

### 7.2. Đóng gói giao diện Frontend và khởi chạy Docker Compose
Container `qr_guard_pwa` phục vụ trực tiếp thư mục `frontend/dist`, do đó cần đóng gói giao diện trước khi khởi động cụm container:

```bash
# 1. Cài đặt phụ thuộc và build giao diện React PWA
npm --prefix frontend install
npm --prefix frontend run build

# 2. Khởi chạy toàn bộ dịch vụ (chế độ phát triển nội bộ qua HTTP port 80)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

# Xem trạng thái và nhật ký hoạt động
docker compose ps
docker compose logs -f
```

Khi triển khai thực tế sau lớp TLS/HTTPS reverse proxy, chạy trực tiếp `docker compose up -d --build` (không kèm `docker-compose.dev.yml`) để giữ nguyên cờ bảo mật `SESSION_COOKIE_SECURE=true`.

Sau khi khởi động thành công:
- **Giao diện ứng dụng**: `http://localhost` (hoặc kéo-thả trực tiếp các mẫu trong thư mục `demo_samples/` để trải nghiệm)
- **Điểm kiểm tra trạng thái dịch vụ (Health Check)**: `http://localhost/api/health`
- **Kiểm tra tính toàn vẹn gói mô hình XGBoost 81 đặc trưng**:
  ```bash
  python backend/scripts/verify_url_model.py
  ```

### 7.3. Kiểm thử
```bash
# Kiểm thử frontend (định dạng cảnh báo, giải thích theo ngữ cảnh, TreeSHAP dễ hiểu, các ràng buộc ngôn từ/bảo mật giao diện)
npm --prefix frontend test

# Kiểm thử backend
cd backend && python -m pytest -q
```

Bộ ảnh `demo_samples/tinh_huong_thuc_te/` có bảng kết quả mong đợi trong `HUONG_DAN_DEMO_THUC_TE.md`, gồm cả các trường hợp hệ thống còn bỏ sót (dùng cho phần hạn chế và hướng phát triển).
