## Cách chạy

Yêu cầu: Windows, .NET SDK (phiên bản khớp với TargetFramework trong file .csproj).

dotnet run --project ATBM_App -c Release

Nên chạy bản Release để số liệu đo tốc độ chính xác.

## Bài 1: Mã hoá AES (đối xứng)

1. Sinh khoá, mã hoá và giải mã văn bản

<img width="1920" height="1080" alt="Screenshot 2026-10-23 111137" src="https://github.com/user-attachments/assets/9ceb90c9-49ff-4f09-8bb4-f0c4d167fcce" />


AES văn bản

Sinh khoá AES-256 (hiển thị dạng base64), mã hoá một đoạn văn bản ra chuỗi base64 (IV + ciphertext) rồi giải mã lại ra đúng bản rõ. Ảnh cũng cho thấy chương trình báo lỗi "Chưa có khoá AES" khi bấm mã hoá mà chưa sinh hoặc import khoá.


2. Lưu khoá ra file và import khoá từ file
<img width="1920" height="1080" alt="Screenshot 2026-10-23 114925" src="https://github.com/user-attachments/assets/11ae0b4e-36a7-45f0-967a-c5f246cda9a3" />

AES lưu và import khoá

Khoá được lưu ra file aes.key (một dòng base64), sau đó import lại từ file (báo "Đã import khoá 256 bit"). Dùng khoá vừa import để mã hoá và giải mã văn bản vẫn cho kết quả đúng, chứng tỏ việc lưu và import khoá hoạt động chính xác.

3. Thử nghiệm file 1 GB: thời gian mã hoá, giải mã và so sánh byte

<img width="680" height="205" alt="Screenshot 2026-10-23 120140" src="https://github.com/user-attachments/assets/5b049be7-a5af-4664-86e1-4c2765285f3e" />

AES benchmark 1 GB

Tạo file test 1024 MB (1.073.741.824 byte), sau đó chạy benchmark trọn gói gồm mã hoá, giải mã và so sánh byte giữa file nguồn với file sau giải mã.

| Chỉ số	Kết quả |
| --- |
| Mã hoá	1,127 s (908,7 MB/s) |
| Giải mã	0,687 s (1489,8 MB/s) |
| So sánh byte	0,655 s, giống nhau 100% (cả hai file đều 1.073.741.824 byte) |

Nhận xét: thuật toán đúng (file giải mã trùng khớp từng byte với file gốc). Tốc độ đạt hàng trăm đến hàng nghìn MB/s nhờ AES phần cứng, giải mã nhanh hơn mã hoá vì CBC giải mã có thể song song hoá.

## Bài 2: Mã hoá RSA (bất đối xứng)


4. Sinh cặp khoá, xuất PEM và xem cấu trúc PEM

<img width="1920" height="1080" alt="Screenshot 2026-10-23 121013" src="https://github.com/user-attachments/assets/e4047e8c-61f7-4e79-8e7d-e7e4ec1ebd06" />


 RSA xem PEM

Sinh cặp khoá RSA-2048, xuất ra public.pem và private.pem. Chức năng Xem PEM hiển thị nội dung PEM và giải thích cấu trúc byte theo ASN.1 DER (Tag-Length-Value): khoá công khai dài 294 byte gồm SEQUENCE > OID rsaEncryption, NULL, BIT STRING > SEQUENCE{ n (257 byte), e = 010001 }. Khoá riêng dài 1190 byte, bắt đầu bằng SEQUENCE với version, n, e...

5. Nhập PEM, đọc các thành phần của khoá





RSA nhập PEM

Phần cuối cấu trúc khoá riêng PKCS#1 (d, p, q, dP, dQ, qInv) và kết quả nhập PEM: file public cho ra n (2048 bit) và e = 65537; file private cho ra thêm d, p, q, dP, dQ, qInv.

Các khoá trong ảnh chỉ là khoá thử nghiệm, không dùng cho mục đích thật.

6. Mã hoá khoá 32 byte bằng public key, giải mã bằng private key

RSA mã hoá giải mã




Mã hoá chuỗi base64 của một khoá 32 byte bằng public.pem, lưu bản mã ra file (base64), rồi giải mã bằng private.pem. Kết quả giải mã trùng khớp với dữ liệu gốc.

7. Kiểm tra giới hạn dữ liệu 190 byte

RSA giới hạn 190 byte

<img width="1920" height="1080" alt="Screenshot 2026-10-24 100036" src="https://github.com/user-attachments/assets/33c07d86-f13b-4e48-a2d1-2a7dc985b6c2" />

Với dữ liệu 191 byte, chương trình báo lỗi "Dữ liệu 191 byte > tối đa 190 byte (OAEP-SHA256)". Đây là giới hạn của RSA-2048 với OAEP-SHA256: 256 - 2×32 - 2 = 190 byte.

8. Xuất cặp khoá ra thư mục riêng và mã hoá, giải mã lại

RSA khoá trong thư mục riêng
<img width="1920" height="1080" alt="Screenshot 2026-10-24 101143" src="https://github.com/user-attachments/assets/05b4c2b7-5fc0-40bc-8417-09f3260cb1bb" />


Cặp khoá được xuất vào thư mục riêng khóa A. Mã hoá 32 byte bằng public key trong thư mục này rồi giải mã bằng private key cùng cặp, cho kết quả trùng khớp với dữ liệu gốc.

9. Đánh giá tốc độ: public key (e nhỏ) so với private key (d lớn)

RSA tốc độ

<img width="1920" height="1080" alt="Screenshot 2026-10-24 101430" src="https://github.com/user-attachments/assets/b082178e-6efa-4e0b-8d2d-97dc275cfe01" />

| Độ dài khoá	Mã hoá (public)	Giải mã (private)	Private chậm hơn |
| --- |
| 1024 bit	0,0060 ms	0,1081 ms	18,1 lần |
| 2048 bit	0,0208 ms	0,6262 ms	30,1 lần |
| 3072 bit	0,0413 ms	1,9257 ms	46,6 lần |
| 4096 bit	0,0684 ms	4,2478 ms	62,1 lần |

Nhận xét: mã hoá bằng public key (e = 65537 chỉ khoảng 17 bit) nhanh hơn giải mã bằng private key (d dài cỡ bằng n) hàng chục lần, và khoảng cách càng tăng khi khoá dài hơn. Vì vậy RSA chỉ dùng cho dữ liệu nhỏ (khoá AES, giá trị băm), còn dữ liệu lớn được mã hoá bằng AES.

SHA-256
10. Hiệu ứng thác đổ của hàm băm

SHA-256




Nhập hai chuỗi chỉ khác nhau rất ít (Hello world và Hello worle), chương trình tự tính SHA-256 của cả hai và đếm số bit băm khác nhau: 142/256 bit (55,5%). Lý thuyết là khoảng 50%, tức chỉ cần đổi đầu vào rất ít thì băm đổi gần như hoàn toàn (hiệu ứng thác đổ).

Chữ ký số

Chữ ký số là RSA dùng khoá bí mật trên giá trị băm của dữ liệu.

11. Cùng dữ liệu, cùng khoá nhưng chữ ký khác nhau

Chữ ký số




Ký 3 lần cùng dữ liệu hợp đồng 001 bằng cùng một private key:

Kiểu đệm	Kết quả	Xác thực
PKCS#1 v1.5 (tất định)	3 chữ ký giống hệt nhau (1/3 chữ ký khác nhau)	True cả 3 lần
RSASSA-PSS (salt ngẫu nhiên)	3 chữ ký khác nhau (3/3)	True cả 3 lần

Phương pháp đề xuất: dùng RSASSA-PSS. Mỗi lần ký sinh một salt ngẫu nhiên đưa vào giá trị được ký, nên cùng dữ liệu, cùng người ký vẫn cho chữ ký khác nhau, nhưng khi xác thực vẫn đúng vì salt được nhúng sẵn trong chữ ký.
