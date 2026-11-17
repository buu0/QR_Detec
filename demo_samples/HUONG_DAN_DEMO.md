# BỘ 21 MẪU KIỂM THỬ & TRÌNH DIỄN TRỰC TIẾP (LIVE DEMO 01–21) — QRDETEC

Thư mục `demo_samples` chứa trọn bộ **21 tệp kịch bản mẫu (`01` đến `21`, định dạng `.png` và `.pdf`)** được sắp xếp **theo đúng thứ tự số hiệu liên tục từ `01` đến `21`**, kèm kịch bản kiểm thử tự động `CHAY_KIEM_THU_8_LOP_BAO_VE.bat`. Toàn bộ 21 tệp đã được kiểm chứng trực tiếp trên hệ thống `QRDetec` (`http://127.0.0.1`).

---

## Danh mục 21 Tệp Mẫu theo Thứ tự Liên tục (`01` – `21`)

### 01. `01_quishing_local_ioc_danger.png` — Quishing khớp Danh sách đen cục bộ (Tier 1/2 Local IOC Match)
- **Payload:** `https://0046.paypal-merchant.ru/login/verify-account`
- **Kết quả & Ý nghĩa (`Table 4.9`):** Cả Local IOC (`593.049` mẫu, khớp trực tiếp `< 1 ms`) và mô hình `XGBoost 81 đặc trưng` (`> 98%`, vượt ngưỡng $t^* = 0.597483$) đồng loạt phát hiện mà không cần truy cập đích $\rightarrow$ **`Malicious (DANGER)`**.

### 02. `02_quishing_vietcombank_otp.png` — Quishing giả mạo Ngân hàng Việt Nam (Tên miền mới chưa có trong IOC)
- **Payload:** `http://vietcombank-xacthuc-otp.top/login`
- **Kết quả & Ý nghĩa (`Table 3.7`, Nhóm E & F):** Local IOC báo `No Match`, nhưng mô hình `XGBoost 81 đặc trưng` chấm **`99.7%`** nhờ nhóm đặc trưng thương hiệu và từ khóa ngân hàng/OTP tiếng Việt, kèm giải thích `TreeSHAP` $\rightarrow$ **`Malicious (DANGER)`**.

### 03. `03_quishing_idn_homograph_paypal.png` — Tấn công Ký tự đồng dạng Quốc tế hóa (IDN Homograph Quốc tế)
- **Payload:** `https://xn--pypal-4ve.com/login/verify` (`https://päypal.com/login/verify`)
- **Kết quả & Ý nghĩa (`Table 3.7`, Nhóm G):** Bộ chuẩn hóa giải mã Punycode (`xn--`), phát hiện `IDN_BRAND_HOMOGRAPH` & `BRAND_LOOKALIKE_DOMAIN` $\rightarrow$ **`Malicious (DANGER)`**.

### 04. `04_vietqr_dan_de_sai_stk_va_tien_danger.png` — Dán đè Mã VietQR trên Standee (Tráo STK & Tăng 10 lần Số tiền)
- **Ngữ cảnh in:** `VIETCOMBANK` | `NGUYEN VAN AN` | `STK: 0123456789` | `50.000 VND`.
- **Payload QR (CRC-16 hợp lệ):** `VIETCOMBANK` (`970436`) | `TRAN VAN GIAN LAN` | `STK: 999988887777` | `500.000 VND`.
- **Kết quả & Ý nghĩa (`Table 4.13` Row 3):** Dù CRC-16 và TLV hợp lệ, Giai đoạn 2 đối soát không gian 2D phát hiện lệch số tài khoản và tên người nhận $\rightarrow$ **`Critical Mismatch (DANGER)`**.

### 05. `05_vietqr_hop_le_khop_ngu_canh.png` — Standee Thanh toán VietQR Hợp lệ & Khớp Ngữ cảnh 100%
- **Ngữ cảnh in & Payload QR:** `VIETCOMBANK` (`970436`) | `NGUYEN VAN AN` | `STK: 0123456789` | `150.000 VND` | `THANH TOAN HOA DON`.
- **Kết quả & Ý nghĩa (`Table 4.13` Row 2):** Khớp hoàn toàn các trường thông tin $\rightarrow$ **`Context Consistent (No Known Risk)`**.

### 06. `06_url_chinh_thuc_vietcombank.png` — Liên kết Trang chủ Chính thức (Đối chứng âm `No Known Risk`)
- **Payload:** `https://vietcombank.com.vn/`
- **Kết quả & Ý nghĩa (`Table 4.9` Case 7):** Local IOC = `No Match`, điểm mô hình = `0.0114` (`< 0.500000`) $\rightarrow$ **`No Known Risk`** (nhấn mạnh: *"Chưa phát hiện dấu hiệu rủi ro đã biết"*, không khẳng định *"An toàn tuyệt đối"* khi không tải trang đích).

### 07. `07_lop1_gia_mao_magic_bytes.png` — Kiểm thử Biên Bảo mật 1: Giả mạo Chữ ký Nhị phân (`Magic-Bytes Verification`)
- **Bản chất tệp (`Table 3.2`):** Mang đuôi `.png` nhưng nội dung là văn bản không có header `\x89PNG\r\n\x1a\n` $\rightarrow$ bị chặn ngay tại cổng tiếp nhận (**`HTTP 415`**).

### 08. `08_lop2_bom_giai_nen_9000x5000px.png` — Kiểm thử Biên Bảo mật 2: Bom Giải nén Ảnh (`Image Decompression Bomb`)
- **Bản chất tệp (`Table 3.2`):** Nặng `~52 KB` nhưng khai báo kích thước `9.000 × 5.000 = 45 MP` (vượt trần `36 MP` và cạnh `8.000 px`) $\rightarrow$ bị từ chối trước khi cấp phát bộ nhớ điểm ảnh (**`Fail-Closed`**).

### 09. `09_lop3_pdf_khoa_mat_khau.pdf` — Kiểm thử Biên Bảo mật 3: Tệp PDF Mã hóa Mật khẩu (`Encrypted PDF Guard`)
- **Bản chất tệp (`Table 3.2`):** Tệp PDF khóa mật khẩu `AES-256` $\rightarrow$ bị từ chối xử lý ngay lập tức (**`Fail-Closed`**).

### 10. `10_lop4_pdf_vietqr_chu_trang_nen_trang.pdf` — Kiểm thử Biên Bảo mật 4: Lọc Văn bản PDF Ẩn (`Hidden PDF Text Filter`)
- **Bản chất tệp (`Section 3.4`):** Hóa đơn PDF bị tráo mã QR sang tài khoản kẻ gian `999988887777`, đồng thời chèn chữ trắng trên nền trắng (`render_mode=3`, cỡ `1.0 pt`) chứa số tài khoản kẻ gian để đánh lừa trình đọc PDF $\rightarrow$ hệ thống loại bỏ các span chữ ẩn, bật cờ `PDF_HIDDEN_TEXT` và báo **`Critical Mismatch (DANGER)`**.

### 11. `11_lop5_qr_chua_bay_ssrf_internal_ip.png` — Kiểm thử Biên Bảo mật 5: Chống SSRF Mạng Nội bộ (`Zero-Egress SSRF Guard`)
- **Payload (`Table 3.3`):** `http://127.0.0.1:6379/admin/flushall?token=internal_test` $\rightarrow$ hệ thống không gửi bất kỳ gói tin nào tới `127.0.0.1`, phát hiện host loopback/private tĩnh và cảnh báo ngay lập tức.

### 12. `12_quishing_idn_homograph_vietcombank.png` — Kịch bản Live Demo 1: IDN Homograph Cyrillic Giả mạo Vietcombank
- **Payload (`Table 4.11` Case 3):** `https://xn--vetcombank-x2i.com.vn` (`https://vіetcombank.com.vn` với chữ `і` Cyrillic `U+0456`).
- **Kết quả & Ý nghĩa (`Table B.1` Nhóm G):** Điểm hiệu chuẩn tăng vọt từ `0.0039` lên `0.9857` (trên chuỗi chuẩn hóa `0.9885`), kích hoạt cờ `IDN Brand Homograph` $\rightarrow$ **`Malicious (DANGER)`**.

### 13. `13_quishing_embedded_redirect_ioc.png` — Chuyển hướng Mở Ẩn trong Tham số (Tier 3 Embedded-Redirect IOC Match)
- **Payload (`Table 4.9` Case 2):** `https://vietcombank.com.vn/personal?redirect=https://aaaalimos.com/login`
- **Kết quả & Ý nghĩa:** Tầng Tier 3 bóc tách tham số `redirect`, khớp tên miền độc hại `aaaalimos.com` trong Local IOC $\rightarrow$ **`Malicious (DANGER — Embedded Indicator Match)`**.

### 14. `14_vietqr_gia_mao_cau_truc_duplicate_tag38.png` — Kịch bản Live Demo 2: Chèn 2 Khối Tag 38 Trùng lặp có CRC-16 Tính lại
- **Payload (`Table 4.12` Case 3):** Chứa 2 khối `Tag 38` liên tiếp (`0123456789` rồi `9999888877`) với trailer `CRC-16` đã tính lại hợp lệ.
- **Kết quả & Ý nghĩa:** Bộ chỉ kiểm CRC sẽ bị qua mặt, nhưng `vietqr_parser.py` phát hiện thẻ TLV trùng lặp và chặn ngay ở Giai đoạn 1 $\rightarrow$ **`Invalid Payload (Duplicate TLV Tag 38)`**.

### 15. `15_pdf_thong_bao_quishing_ngan_hang.pdf` — Thông báo PDF Ngân hàng Giả mạo Đính kèm QR Quishing
- **Bản chất tệp:** Công văn PDF giả mạo yêu cầu cập nhật sinh trắc học qua mã QR `http://vietcombank-xacthuc-otp.top/login` $\rightarrow$ kết xuất PDF 200 DPI, giải mã QR và báo **`Malicious (DANGER, 99.7%)`**.

### 16. `16_pdf_hoa_don_vietqr_hop_le.pdf` — Hóa đơn PDF Hợp lệ Có Bảng Đơn giá Gây nhiễu
- **Bản chất tệp (`Figure 3.7`):** Hóa đơn PDF có dòng `Đơn giá: 50.000 VND` và `Tổng cộng: 150.000 VND` đi kèm mã VietQR `150.000 VND` $\rightarrow$ thuật toán gắn kết khối không gian ưu tiên dòng `Tổng cộng` và xác nhận **`Context Consistent`**.

### 17. `17_pdf_hoa_don_vietqr_bi_trao_stk_va_tien.pdf` — Kịch bản Live Demo 3: Hóa đơn PDF Bị Tráo Mã VietQR
- **Bản chất tệp (`Table 4.13` Row 3):** Chữ in trên hóa đơn là `VIETCOMBANK - STK 0123456789 - NGUYEN VAN AN - 50.000 VND`, nhưng mã QR nhúng trỏ tới `999988887777` (`TRAN VAN GIAN LAN`, `500.000 VND`) $\rightarrow$ **`Critical Mismatch (DANGER)`**.

### 18. `18_vietqr_qr_in_qr_dan_de_tam.png` — Tấn công QR-in-QR Dán đè Nhỏ ở Tâm (Giải mã Đồng thời Cả 2 Mã QR)
- **Bản chất tệp (`Section 3.4`):** Sticker VietQR nhỏ (`60×60 px`, tài khoản kẻ gian `999988887777`) dán vào tâm mã VietQR gốc (`362×362 px`, tài khoản thật `0123456789`) trong ngưỡng sửa lỗi Reed–Solomon.
- **Kết quả:** Khử trùng lặp IoU (`IoU ≈ 0.023 < 0.70`) giữ lại cả 2 mã: mã trong báo **`Critical Mismatch`**, mã ngoài báo **`Context Consistent`**.

### 19. `19_vietqr_qr_in_qr_dan_de_co_lon.png` — Tấn công QR-in-QR Dán đè Cỡ lớn (Phá vỡ Reed–Solomon của Mã Ngoài)
- **Bản chất tệp (`Section 3.4`):** Sticker VietQR lớn (`160×160 px`) dán đè làm hỏng mã ngoài; hệ thống giải mã mã trong và đối soát với chữ in trên biển $\rightarrow$ **`Critical Mismatch (DANGER)`**.

### 20. `20_vietqr_chi_co_ma_qr_khong_ngu_canh.png` — Kịch bản Live Demo 4: Mã VietQR Đứng Một Mình Không Có Chữ In
- **Bản chất tệp (`Table 4.13` Row 1):** Ảnh chỉ chứa mã VietQR hợp lệ (cắt từ tệp `05`), không có bất kỳ dòng chữ in nào xung quanh.
- **Kết quả:** Dù CRC-16 và TLV hợp lệ 100%, hệ thống không gắn kết được trường văn bản nào nên trả về **`Insufficient Context (Unverifiable)`**, tuyệt đối không hiển thị là đã xác minh an toàn.

### 21. `21_vietqr_cung_stk_khac_ngan_hang.png` — Kịch bản Live Demo 5: Cùng Số Tài Khoản Có Nhãn Nhưng Khác Ngân Hàng (Quy tắc BIN)
- **Bản chất tệp (`Table 4.13` Row 4):** Mã QR mang BIN `970407` (`Techcombank`), `STK: 0123456789`, `NGUYEN VAN A`; nhưng chữ in trên biển là `Ngân hàng: Vietcombank`, `STK: 0123456789` (có nhãn tường minh), `Chủ TK: NGUYỄN VĂN A`.
- **Kết quả:** Vì số tài khoản nội địa gắn liền với từng ngân hàng (cùng dãy số ở Techcombank là tài khoản khác với ở Vietcombank), hệ thống nâng cảnh báo lên **`Critical Mismatch (DANGER)`**.
