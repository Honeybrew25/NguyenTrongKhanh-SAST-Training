# Làm giàu dữ liệu VulnGym và xác minh phát hiện

Kho lưu trữ này mở rộng Tencent VulnGym bằng các phát hiện của trình quét đã được thẩm định, đặc biệt là các kết quả dương tính giả đã được xác nhận, đồng thời cung cấp một bộ benchmark có thể tái lập dành cho các tác nhân xác minh phát hiện.

## Các đầu vào được cố định

- VulnGym: `v0.1.4` at `cd69f7e163e08485ab5496115ae03439cda6e27e`
- Semgrep: `1.171.0`
- OpenGrep: `1.26.0`
- Rules: `semgrep/semgrep-rules` at `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`

Bộ benchmark và các quy tắc là những Git submodule. Khởi tạo chúng bằng lệnh:

```bash
git submodule update --init --recursive
```

## Thiết lập môi trường phát triển

```bash
uv sync --extra dev
uv run vulngym-audit --benchmark benchmark/VulnGym --output artifacts/manifests/vulngym-v0.1.4.json
uv run pytest
```

Trên Windows, đặt `PYTHONUTF8=1` trước khi chạy scanner để đầu ra Unicode ổn định. File thực thi của scanner phải đúng phiên bản và SHA-256 trong `config/scanners.lock.json`; runner sẽ dừng nếu pin không khớp.

## Pipeline quét và làm giàu

Ví dụ dưới đây tái lập pilot ngày 2 trên đúng snapshot NLTK:

```powershell
$env:PYTHONUTF8 = "1"
$scanId = "day2-pilot-nltk-final-20260803"
$repo = "https://github.com/nltk/nltk"
$commit = "40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e"

uv run vulngym-scan `
  --manifest artifacts/manifests/vulngym-v0.1.4.json `
  --scan-id $scanId `
  --repo-url $repo `
  --commit $commit
```

Mỗi lần chạy tạo một thư mục attempt bất biến chứa bản sao manifest/lock/profile, JSON, SARIF, log, checksum và status. `run.json` tại gốc scan-id khóa checksum đầu vào, ruleset, phiên bản/hash binary và timeout chung cho toàn batch. Chạy lại cùng `scan-id` sẽ bỏ qua attempt đã thành công; runner từ chối trộn cấu hình khác kể cả khi có `--force`.

Full batch ngày 2 dùng cùng các input đã cố định và không đặt filter snapshot/scanner:

```powershell
$env:PYTHONUTF8 = "1"
$env:GIT_CONFIG_COUNT = "1"
$env:GIT_CONFIG_KEY_0 = "core.longpaths"
$env:GIT_CONFIG_VALUE_0 = "true"
$scanId = "day2-full-v4-20260804"

uv run vulngym-scan `
  --manifest artifacts/manifests/vulngym-v0.1.4.json `
  --scan-id $scanId `
  --job-timeout-seconds 7200
```

Full batch có thể chia thành bốn partition không giao nhau bằng script đã kiểm tra đúng 166 snapshot:

```powershell
.\scripts\run_day2_partitions.ps1 `
  -ScanId $scanId `
  -JobTimeoutSeconds 7200

.\scripts\start_day2_finalizer.ps1 `
  -ScanId $scanId `
  -JobTimeoutSeconds 7200
```

Mỗi partition prefetch toàn bộ commit đã chọn theo từng repository trước khi tạo attempt. Mirror dùng ref `refs/vulngym/<sha>` và fetch nông đúng các SHA benchmark, tránh tải lịch sử ngoài phạm vi nhưng vẫn checkout/kiểm tra chính xác từng commit.

Finalizer chạy nền, đợi các partition kết thúc rồi resume toàn batch tối đa ba pass. Chỉ khi scanner trả thành công, nó mới gọi full pipeline không có `--allow-incomplete`; trạng thái nằm trong `finalizer-status.json` tại gốc scan-id.

Nếu bốn partition đang đồng thời bị chặn ở các job OpenGrep và máy còn ít nhất 10 GiB RAM trống, có thể thêm đúng một worker Semgrep ưu tiên thấp mà không đổi profile/provenance:

```powershell
.\scripts\start_day2_semgrep_accelerator.ps1 -ScanId $scanId
```

Worker này dùng khóa job chung và mặc định resume, nên chỉ xử lý Semgrep chưa thành công. Không khởi chạy nhiều accelerator trên máy 32 GiB RAM.

Profile cố định `max_memory_mb=8192` cho cả hai engine; giá trị này được truyền thành `--max-memory` để một file/rule không chiếm hết RAM hệ thống. Chạy lại đúng timeout trên để resume; không thêm `--force` hoặc `--refresh`. Attempt `SUCCESS` và snapshot không có rule phù hợp được tái sử dụng, còn `FAILED`/`TIMEOUT` được tạo attempt retry mới. Job được khóa liên tiến trình nên các partition không thể tạo trùng attempt. Khi timeout, runner kết thúc cả process tree của scanner. Scanner mặc định vẫn dùng `.gitignore`; nếu phiên bản scanner đã ghim không parse được ignore file, profile cho phép retry đúng clean snapshot bằng `--no-git-ignore`. Status lưu cả hai argv, output/log lỗi ban đầu và cờ `git_ignore_fallback_used`, nên ngoại lệ này không bị che giấu.

Chuẩn hóa riêng finding bảo mật, gộp quan sát của hai engine rồi đối sánh theo canonical cluster:

```powershell
$scanBase = "artifacts/scans/$scanId/nltk__nltk/$commit"
$queue = "artifacts/annotation-queue/$scanId"

uv run vulngym-normalize `
  --status "$scanBase/semgrep/attempts/0001/status.json" `
  --category security `
  --output "$queue/semgrep-security.jsonl" `
  --summary "$queue/semgrep-security-summary.json"

uv run vulngym-normalize `
  --status "$scanBase/opengrep/attempts/0001/status.json" `
  --category security `
  --output "$queue/opengrep-security.jsonl" `
  --summary "$queue/opengrep-security-summary.json"

uv run vulngym-dedup `
  --input "$queue/semgrep-security.jsonl" `
  --input "$queue/opengrep-security.jsonl" `
  --output "$queue/security-deduplicated.jsonl" `
  --summary "$queue/security-dedup-summary.json"

uv run vulngym-match `
  --findings "$queue/security-deduplicated.jsonl" `
  --canonical `
  --output "$queue/canonical-security-matches.jsonl" `
  --summary "$queue/canonical-security-match-summary.json"
```

Sau khi full batch kết thúc và mọi job đã có trạng thái cuối, chạy hậu xử lý toàn corpus:

```powershell
uv run vulngym-full-pipeline `
  --scan-root "artifacts/scans/$scanId" `
  --output-dir "artifacts/normalized/$scanId"
```

Lệnh này mặc định từ chối chốt output nếu chưa đủ ma trận 166 snapshot × 2 scanner hoặc còn job `RUNNING`, `FAILED`, `TIMEOUT`. Nó còn đối chiếu provenance của từng attempt với `run.json`, xác minh checksum raw input, normalize security finding, dedup, match canonical cluster và báo số parser warning; `unresolved_partial_files` đếm file partial mà không có engine còn lại scan sạch. `--allow-incomplete` chỉ dành cho kết quả tạm thời và không được dùng để tuyên bố Ngày 2 hoàn thành.

Ở chế độ `--status`, normalizer xác minh checksum của raw output và ưu tiên các bản sao input bất biến trong attempt, đồng thời không đọc lại source mutable. Dữ liệu đã duyệt của pilot nằm tại `data/enriched/*.jsonl` và được kiểm tra trực tiếp bằng JSON Schema trong test suite.

## Khi nào dùng CodeQL

CodeQL là nhánh escalation cho finding thiếu hoặc có exploitation path không đầy đủ sau Semgrep/OpenGrep, đặc biệt với dataflow liên tệp. Trước khi bật phải cố định phiên bản CodeQL CLI và commit/query-pack, tạo database từ cùng snapshot rồi lưu SARIF có `codeFlows`. Normalizer hiện đã đọc được `codeFlows` CodeQL bằng `--format sarif --scanner codeql`.

Không trộn số liệu CodeQL vào phép so sánh engine Semgrep/OpenGrep dùng chung rule: CodeQL dùng query semantics khác và phải được báo cáo như một baseline riêng. Xem `docs/day2-pilot-methodology.md`.

## Cấu trúc kho lưu trữ

- `benchmark/VulnGym/`: bộ benchmark thượng nguồn đã được ghim phiên bản.
- `rules/semgrep-rules/`: bộ quy tắc của trình quét đã được ghim phiên bản.
- `config/scanners.lock.json`: tệp khóa phục vụ khả năng tái lập.
- `schemas/`: các schema dành cho phát hiện đã chuẩn hóa và thẩm định.
- `data/enriched/`: các finding đã được thẩm định cùng bằng chứng và nguồn gốc.
- `src/vulngym_enrich/`: các công cụ kiểm tra, checkout, đối sánh và đánh giá.
- `tests/`: các kiểm thử hồi quy.
- `docs/`: tài liệu về chú thích và phương pháp luận.
- `artifacts/`: các manifest và kết quả quét được tạo ra; bị Git bỏ qua.

## Chính sách gán nhãn

Một phát hiện của Semgrep/OpenGrep không khớp với dữ liệu VulnGym không mặc nhiên là kết quả dương tính giả. Các phát hiện không khớp có thể là lỗ hổng mới hoặc biểu hiện khác của những lỗ hổng đã biết. Xem `docs/annotation-guideline.md`.

## An toàn và phạm vi

Chỉ chạy trình quét trên các kho lưu trữ và commit thuộc bộ benchmark VulnGym công khai hoặc trên mã nguồn mà bạn được phép phân tích. Theo mặc định, quá trình xác minh của tác nhân chỉ được phép đọc và không được nhận nhãn cảnh báo bảo mật hoặc bản vá đã sửa lỗi trong quá trình đánh giá.
