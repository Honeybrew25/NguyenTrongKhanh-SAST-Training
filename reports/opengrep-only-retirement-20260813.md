# Báo cáo bàn giao: dừng baseline CodeQL, tiếp tục với OpenGrep

- Ngày quyết định: **13/08/2026**
- Người thực hiện: **Nguyễn Trọng Khánh**
- Phạm vi project: **VulnGym SAST Training**
- Trạng thái sau bàn giao: **chỉ dùng kết quả OpenGrep cho baseline SAST và đánh giá**

## Kết luận

Phương án đối chiếu CodeQL (`baseline`) không hoàn tất đủ số job cần quét
(`coverage`) trong ngân sách thời gian và tài
nguyên của máy thử nghiệm. Cùng job OpenClaw commit
`041c47419f5a821fd4adcd46dfc7d85a7eda340e`, ngôn ngữ
JavaScript/TypeScript, đã timeout hai lần dù lần hai tái sử dụng database và
tăng đáng kể tài nguyên. Vì kết quả full scan không hoàn chỉnh, project **không
sử dụng bất kỳ finding, SARIF hoặc metrics CodeQL nào**.

Toàn bộ service/process đã được dừng. Runner, profile, test, tài liệu vận hành,
database, SARIF, normalized output, cache scanner và runtime Go cài riêng cho
baseline này đã được loại bỏ. Từ thời điểm bàn giao, OpenGrep r1 là nguồn kết
quả SAST duy nhất của project.

## Bằng chứng hai lần timeout

### Attempt 1

- Trạng thái: `TIMEOUT`.
- Database create: thành công trong `112,857` giây.
- Analyze: `14.400,002` giây, đúng giới hạn 4 giờ.
- Return code: `-9` do runner kết thúc process khi timeout.
- Tài nguyên: 3 thread, RAM 5.632 MiB, disk cache 2.048 MiB.
- SHA-256 của `attempts/0001/status.json` trước khi xóa:
  `5e37484e999ece9ff5cad2fe0bf590914ae145caac85f412a89f408b5baedda0`.

### Attempt 2

- Bắt đầu: `2026-08-13T02:10:02.213700+00:00`.
- Kết thúc: `2026-08-13T04:10:02.246191+00:00`.
- Trạng thái: `TIMEOUT`.
- Analyze: `7.200,025` giây, đúng giới hạn 2 giờ.
- Database cũ được tái sử dụng; không mất thời gian tạo lại database.
- Tài nguyên đã tăng lên 6 thread, RAM 10.240 MiB và disk cache 8.192 MiB.
- Return code: `-9`; lỗi được runner ghi là `TimeoutError: CodeQL database
  analysis timed out`.
- SHA-256 của `attempts/0002/status.json` trước khi xóa:
  `31e638663bb54ce90c5e55fb006854bf0a4cebf3b533a3affabc240096f6d76d`.

Sau attempt 2, bộ điều phối tự chuyển sang OpenClaw commit `04e103d10ef7...`.
Job này đang chạy khoảng 6 phút thì bị dừng chủ động cùng toàn bộ baseline; nó
không phải kết quả scan và không được đưa vào thống kê.

## Phân tích nguyên nhân

Nguyên nhân tính toán gốc là sự mở rộng rất lớn của quan hệ trung gian trong các
truy vấn theo dõi đường đi của dữ liệu không tin cậy qua nhiều hàm
(`taint/data-flow` liên thủ tục), nổi bật là `CommandInjection`,
`IndirectCommandInjection` và `ShellCommandInjectionFromEnvironment`. Log
evaluator cho thấy fixed-point đã tới khoảng 205–334 vòng lặp nhưng mỗi delta
vẫn sinh khoảng 1,0–2,6 triệu dòng.

Giới hạn disk cache 2 GiB ở attempt 1 là yếu tố khuếch đại nghiêm trọng:

- khoảng 6,49–6,50 GiB dữ liệu được evaluator đánh dấu là thiết yếu;
- 46.391 lần trim cache thất bại;
- 322.655 chu kỳ pause/evict/unpause;
- chỉ 23/104 query hoàn tất trước timeout 4 giờ.

Attempt 2 nâng cache lên 8 GiB nên không còn lỗi trim xuống dưới giới hạn và
tiến triển nhanh hơn, nhưng các fixed-point nặng vẫn chưa hội tụ trước timeout 2
giờ. Không có bằng chứng OOM, Java heap error, hết dung lượng đĩa hoặc CPU quota.
Do đó, thiếu cache giải thích sự chậm bất thường của attempt 1 nhưng không phải
nguyên nhân duy nhất; chi phí data-flow trên graph OpenClaw là nguyên nhân sâu.

## Baseline OpenGrep được giữ nguyên

Release được tiếp tục sử dụng:
`opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812`.

- Coverage: **166/166 job `SUCCESS`**.
- Raw/normalized observations: **113.756**.
- Canonical clusters: **112.739**.
- Finding có dataflow trace: **16.886**.
- Mẫu đại diện phục vụ review: **400 finding trên 141 snapshot**.
- Validator gói hybrid review sau khi dọn: **`VALID`**, đủ 400 record/141
  snapshot. Gói này vẫn ở chế độ `DEVELOPMENT` và
  `official_corpus_verified=false`, nên chưa được trình bày như gold label hoặc
  metrics chính thức.
