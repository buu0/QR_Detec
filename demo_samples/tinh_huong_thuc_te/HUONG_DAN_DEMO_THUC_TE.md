# ẢNH QR TÌNH HUỐNG THỰC TẾ (22–33) — MINH CHỨNG TRƯỚC HỘI ĐỒNG

Mở http://127.0.0.1 → **Chọn ảnh hoặc PDF** (hoặc in ảnh ra rồi dùng **Quét bằng camera**) → đối chiếu với bảng dưới.

> Tên người, số tài khoản, tên miền lừa đảo trong ảnh đều là **giả định**. Không quét bằng app ngân hàng thật.

Khi kết quả hiện ra, chỉ cho hội đồng xem **khung "Tình huống: …"** ngay dưới tiêu đề. Câu chữ trong khung được ghép từ dữ liệu thật của lần quét đó (tên miền, STK, tên, số tiền, nguồn IOC, điểm AI…), nên mỗi ảnh ra một nội dung khác nhau, không phải đoạn văn gán cứng.

| Ảnh | Tình huống | Kết quả mong đợi | Chỉ cho hội đồng thấy |
|---|---|---|---|
| `22_bai_giu_xe_ktx_ve_thang_bi_dan_de.png` | Sticker VietQR dán đè lên mã thu vé tháng bãi giữ xe | 🔴 **Nguy hiểm** – `CRITICAL_MISMATCH` | Biển ghi STK **0987654321**, mã QR chuyển tới **0356789123**; tên khác nhau |
| `23_quan_ca_phe_standee_hop_le.png` | Standee quầy cà phê đúng thông tin | 🟢 Chưa thấy rủi ro – `CONTEXT_CONSISTENT` | STK trùng nhưng vẫn nhắc: chữ in khớp ≠ đã xác minh chủ tài khoản |
| `24_thong_bao_tien_dien_gia_mao.png` | Thông báo tiền điện giả dán cửa nhà | 🔴 **Nguy hiểm** – AI ≈ 99.4% | Mượn tên EVN, đuôi `.top`, chưa có trong IOC → AI là lớp bắt được; gợi ý app EVNCSKH |
| `25_thu_ngan_hang_gia_cap_nhat_sinh_trac_hoc.png` | Thư "BIDV" đòi cập nhật sinh trắc học | 🔴 **Nguy hiểm** – AI ≈ 98.9% | Từ khóa "sinh trắc học", gợi ý app BIDV SmartBanking (khác với ảnh 24) |
| `26_giay_bao_phat_nguoi_gia_mao.png` | Giấy phạt nguội giả | 🟢 Chưa thấy rủi ro – AI ≈ 33.3% | **Hạn chế:** AI bỏ sót; khung vẫn cảnh báo "có chữ csgt nhưng không phải csgt.vn", http, "nộp phạt" |
| `27_keu_goi_tu_thien_ma_qr_tai_khoan_ca_nhan.png` | Kêu gọi từ thiện, mã QR là tài khoản cá nhân | 🔴 **Nguy hiểm** – `CRITICAL_MISMATCH` | Ngữ cảnh nhận ra là *quyên góp* → thêm bước tra tài khoản trên kênh chính thức |
| `28_bien_wifi_mien_phi_mang_mo.png` | Biển "Wi-Fi miễn phí" | ⚪ Chưa kiểm tra đầy đủ | Nhận ra mã Wi-Fi mở `Free_Wifi_CaPhe_Moc`, cảnh báo nghe lén |
| `29_thuc_don_quan_an_link_dat_mon.png` | Menu quán ăn → shopeefood.vn | 🟢 Chưa thấy rủi ro | Đối chứng âm: tên miền chính thức |
| `30_to_roi_nhan_qua_gui_tin_nhan_dau_so_ngan.png` | Tờ rơi "nhận quà 500K" soạn SMS | ⚪ Chưa kiểm tra đầy đủ | Đầu số ngắn 8077, nội dung chứa "OTP" |
| `31_phieu_thu_hoc_phi_hop_le.png` | Phiếu thu học phí đúng (ảnh chụp) | 🟢 Chưa thấy rủi ro – `CONTEXT_CONSISTENT` | Khớp đủ 4 trường: ngân hàng, STK, tên, số tiền 3.500.000 đ |
| `31_phieu_thu_hoc_phi_pdf_hop_le.pdf` | Cùng phiếu, dạng PDF | 🟢 Chưa thấy rủi ro – `CONTEXT_CONSISTENT` | Khớp đủ 4 trường (kể cả khi OCR làm dính nhãn `Chủ TK` và `Số tiền`) |
| `32_phieu_thu_hoc_phi_bi_sua_so_tien_x10.png` | Phiếu thu bị sửa số tiền ×10 trong QR (ảnh chụp) | 🟠 **Đáng ngờ** – `PARTIAL_MATCH` | STK, tên đúng nhưng mã QR đòi **35.000.000 đ** trong khi phiếu in **3.500.000 đ** (gấp 10 lần) |
| `32_phieu_thu_hoc_phi_pdf_bi_sua_so_tien_x10.pdf` | Cùng phiếu, dạng PDF | 🟠 **Đáng ngờ** – `PARTIAL_MATCH` | Bắt được lệch số tiền ×10 (**35.000.000 đ** vs **3.500.000 đ**) và khớp đúng tên `TRUNG TAM ANH NGU BINH MINH` trên cả bản PDF |
| `33_bai_dang_voucher_link_rut_gon.png` | Bài đăng voucher dùng bit.ly | 🟢 Chưa thấy rủi ro – AI ≈ 26.5% | **Hạn chế:** không mở link rút gọn (zero-egress chống SSRF); khung nói rõ trang đích bị giấu |

## Thứ tự trình diễn gợi ý (~6 phút)

1. **22 → 23:** cặp đối chứng VietQR (bị dán đè / đúng).
2. **24 → 25:** URL mạo danh mới, IOC chưa có nhưng AI bắt được; hai ảnh ra hai lời khuyên khác nhau.
3. **27:** cùng mã lỗi với ảnh 22 nhưng ngữ cảnh *từ thiện* nên lời khuyên khác.
4. **28 → 30:** mã không phải link web (Wi-Fi, SMS).
5. **31 → 32 (PNG & PDF):** cùng phiếu thu học phí, bản sửa số tiền ×10 bị bắt ở cả định dạng ảnh chụp và PDF.
6. **26, 33:** trung thực về hạn chế (tên miền mới cấu trúc giống trang thật, link rút gọn zero-egress) → dùng khi hội đồng hỏi "hệ thống có bỏ sót không?".

Các ảnh 01–21 ở thư mục cha (`demo_samples`) vẫn dùng được như cũ, xem `HUONG_DAN_DEMO.md`.
