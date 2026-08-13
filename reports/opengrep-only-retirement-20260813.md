# Báo cáo bàn giao: dừng baseline CodeQL, tiếp tục với OpenGrep

- Ngày quyết định: **13/08/2026**
- Người thực hiện: **Nguyễn Trọng Khánh**
- Phạm vi project: **VulnGym SAST Training**
- Trạng thái sau bàn giao: **chỉ dùng kết quả OpenGrep cho baseline SAST và đánh giá**

## Kết luận cho mentor

Baseline CodeQL không đạt coverage hoàn chỉnh trong ngân sách thời gian và tài
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
query taint/data-flow liên thủ tục, nổi bật là `CommandInjection`,
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

## Bằng chứng dừng hoạt động

Trước khi xóa dữ liệu, hai service sau đều được kiểm tra ở trạng thái
`inactive/dead`, `ExecMainPID=0`:

- `vulngym-codeql-wsl-resume-20260813.service`;
- `vulngym-codeql-go-followup-20260813.service`.

Không còn process scanner, Java evaluator, runner Python, script điều phối,
monitor hoặc tail log liên quan. Unit cũ
`vulngym-codeql-wsl-batch.service` cũng được gỡ khỏi user systemd và daemon được
reload.

## Phạm vi loại bỏ và dung lượng

Inventory trước xóa ghi nhận `106.332.653.706` byte cho database/artifact,
scan status/log, normalized pilot, cache scanner, cache runtime Go và các file
artifact mang tên CodeQL. Con số dung lượng thực tế giải phóng sau khi hoàn tất
được ghi ở mục kiểm tra cuối báo cáo.

Các nhóm đã loại bỏ:

- `artifacts/codeql/` — database và evaluator cache;
- `artifacts/scans/codeql-*` và `artifacts/normalized/codeql-*`;
- log, manifest, selection plan và quarantine chỉ thuộc baseline này;
- `cache/codeql/`, `cache/tools/codeql/` và `cache/tools/go/` được cài riêng;
- runner/pipeline Python, Bash workflow, profile, test và tài liệu vận hành;
- report tiến độ cũ chỉ nói về baseline dở dang.

Việc xóa database/cache/artifact là **vĩnh viễn trong workspace**, không chuyển
vào thùng rác vì kích thước hơn 100 GB. Báo cáo này là bằng chứng văn bản được
giữ lại; raw artifact không còn khả năng phục hồi từ workspace.

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

Checksum kiểm tra trước khi dọn:

| Artifact OpenGrep | SHA-256 |
|---|---|
| `security-normalized.jsonl` | `077955a6964a90a31573f040fea641547f43a2a0d45bdeeab2ea8c345ce5fda1` |
| `security-deduplicated.jsonl` | `a432411e9ea289575b49efeccccd02dafe3d5d132908dfcf2ff76c354c215ed9` |
| `security-dedup-summary.json` | `fc7c2228504cf8b9f718212b2c027785c839239201a16d93f25ef36d9880b250` |
| `scanner-errors.jsonl` | `a266febabf43ec6ede82757244cc710bbbe8a0161c12fd94fec55b638fc4d769` |

Các checksum này phải giữ nguyên sau khi dọn. `SUCCESS` chỉ xác nhận job hoàn
tất và output hợp lệ; các chẩn đoán partial parsing/timeout nội bộ của OpenGrep
vẫn được công bố riêng trong `scanner-errors.jsonl` và không bị che giấu.

## Kiểm tra cuối

- Dung lượng filesystem trước xóa: `145.986.633.728` byte đã dùng,
  `880.122.187.776` byte khả dụng.
- Dung lượng filesystem sau xóa: `38.105.665.536` byte đã dùng,
  `988.003.155.968` byte khả dụng.
- Dung lượng filesystem giải phóng thực tế: **107.880.968.192 byte
  (100,47 GiB)** theo chênh lệch block filesystem trước/sau.
- Process/service liên quan sau xóa: **không còn**; user systemd không còn unit
  đã load hoặc unit file liên quan.
- Coverage và checksum OpenGrep sau xóa: **166/166 `SUCCESS`; cả bốn checksum
  khớp tuyệt đối với giá trị trước xóa**.
- Test suite và `git diff --check`: **164/164 test pass; không có lỗi
  whitespace**.

Một số chuỗi tên scanner vẫn xuất hiện trong URL tham khảo của ruleset
Semgrep/OpenGrep, fixture kiểm thử GitHub Actions và lexer Pygments đi kèm môi
trường Python. Chúng được giữ nguyên vì là dữ liệu rule/dependency chung, không
phải scanner executable, runner, service hay kết quả baseline; sửa chúng sẽ làm
thay đổi ruleset đã ghim và checksum OpenGrep.
