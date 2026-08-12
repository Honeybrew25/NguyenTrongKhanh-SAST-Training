# OpenGrep trên Ubuntu WSL2

Workflow này chạy OpenGrep `1.22.0` trên đúng 166 snapshot VulnGym. Mặc định nó
dùng ruleset security-only được dẫn xuất byte-preserving từ ruleset Semgrep đã
ghim. OpenGrep có scanner lock, scan profile, scan-id, raw output và thư mục
normalized riêng; release Semgrep v5 không bị thay đổi.

## Cấu hình đã ghim

- OpenGrep: `1.22.0`, Linux x86_64 standalone asset.
- SHA-256: `45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319`.
- Source ruleset commit: `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`.
- Security ruleset commit: `0c8a62c126651c4640e7c634912acc16de878282`.
- Mỗi scanner: `6144` MiB, `3` worker nội bộ.
- Batch: `2` snapshot song song; prefetch: `4` repository song song.
- Output: JSON và SARIF có checksum, log và frozen input cho mỗi attempt.

Binary được cài vào `cache/tools/`, không cần `sudo` và không được commit.
Profile vẫn lưu `metrics: off` để giữ cấu trúc provenance giống Semgrep, nhưng
runner không truyền `--metrics` vì OpenGrep đã bỏ cờ này. Runner tắt version
check và chuyển text output vào `/dev/null`; JSON và SARIF vẫn được giữ nguyên.

## Thiết lập trong Ubuntu WSL

Mở Ubuntu WSL2 rồi chuyển vào project:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
cd ~/projects/NguyenTrongKhanh-SAST-Training-opengrep
bash scripts/opengrep_scan_wsl.sh setup
bash scripts/opengrep_scan_wsl.sh doctor
```

Các lệnh giả định `uv` đã có trong `PATH`. `setup` khởi tạo submodule, tạo
`.venv-wsl`, tải đúng release asset, kiểm tra SHA-256 và dựng ruleset
security-only. `setup` đặt `core.autocrlf=false` ở repo/submodule local; mọi Git
subprocess tạo snapshot cũng ép LF. `doctor` kiểm tra filesystem, EOL, version,
checksum, ruleset pin, CPU, RAM và trạng thái runner.

Project không được đặt dưới `/mnt/*`. Mirror nằm tại `cache/wsl-opengrep/`; các
snapshot LF mới nằm tại `worktrees/opengrep-linux-lf/`. Thư mục pilot cũ
`worktrees/wsl-opengrep/` được giữ nguyên để đối chứng và không được tái sử dụng.

## Smoke test một snapshot

```bash
bash scripts/opengrep_scan_wsl.sh smoke
```

Mặc định smoke dùng snapshot duy nhất của `czlonkowski/n8n-mcp` để phản hồi
nhanh hơn snapshot đầu tiên trong manifest. Kết quả nằm dưới scan-id có hậu tố
`-smoke`. Chỉ chạy full batch sau khi smoke test trả `SUCCESS`. Official run
fail-closed nếu runner/config còn chưa commit; pilot tạm thời có thể đặt
`OPENGREP_REQUIRE_CLEAN_RUNNER=0`.

## Benchmark worker nội bộ

```bash
bash scripts/opengrep_scan_wsl.sh benchmark
```

Benchmark chạy cùng một snapshot Flowise lần lượt với `jobs=4`, `6`, `8`, mỗi
lần chỉ có một scanner. Kết quả in duration, finding, scanner error và số file
partial parsing. Dùng `OPENGREP_BENCHMARK_ID` mới nếu muốn đo lại thay vì resume
kết quả đã có.

Benchmark ngày 2026-08-12 trên máy 8 vCPU hiện tại cho kết quả: `jobs=4` mất
24,82 giây, `jobs=6` mất 23,54 giây và `jobs=8` mất 29,81 giây. Coverage cả ba
lần giống nhau: 268 finding, 1 scanner warning và 1 partial-parsing file. Vì
`jobs=8` đã thoái hóa, cấu hình full batch ưu tiên throughput bằng 2 snapshot ×
3 worker thay vì dành cả 8 CPU cho một snapshot.

Đối chứng hai snapshot Flowise trên cache ấm: chạy tuần tự `1×3` mất 50,78 giây,
trong khi `2×3` mất 30,14 giây, nhanh hơn khoảng 40,6% mà finding/scanner warning
không đổi.

## Chạy hoặc resume full batch

```bash
export OPENGREP_SCAN_ID="opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812"
bash scripts/opengrep_scan_wsl.sh run
```

`run` mặc định prefetch 4 repository song song, sau đó chạy 2 snapshot song song
với 3 worker OpenGrep mỗi snapshot. Máy hiện tại dùng tối đa 6/8 logical CPU và
giữ ít nhất khoảng 3 GiB RAM ngoài ngân sách scanner. Có thể override bằng
`OPENGREP_PREFETCH_WORKERS` và `OPENGREP_BATCH_WORKERS`; `doctor` từ chối cấu
hình vượt CPU hoặc chừa dưới 2048 MiB RAM.

Gọi lại đúng lệnh `run` để resume. Attempt `SUCCESS` với cùng frozen input được
tái sử dụng; job lỗi hoặc bị gián đoạn tạo attempt mới, không ghi đè attempt cũ.

Để chạy thử N snapshot trong cùng batch trước khi mở rộng:

```bash
OPENGREP_LIMIT=5 bash scripts/opengrep_scan_wsl.sh run
```

Để chọn đúng một snapshot:

```bash
OPENGREP_REPO_URL="https://github.com/openclaw/openclaw" \
OPENGREP_COMMIT="a78ec81ae6016bbe2bd1d8824cbffb7518a47c10" \
bash scripts/opengrep_scan_wsl.sh run
```

Không đổi profile hoặc scanner lock trong cùng một scan-id. Nếu cần thay đổi
version, rule hoặc giới hạn ảnh hưởng provenance, dùng scan-id mới.

Để chạy full ruleset tương đương lượt Semgrep cũ thay vì security-only:

```bash
OPENGREP_SCANNER_LOCK="$PWD/config/scanners.opengrep-wsl.lock.json" \
OPENGREP_SCAN_PROFILE="$PWD/config/scan-profile.opengrep-wsl-fast.json" \
OPENGREP_BATCH_WORKERS=1 \
OPENGREP_SCAN_ID="opengrep-full-rules-ext4-r1-20260812" \
bash scripts/opengrep_scan_wsl.sh run
```

## Xem trạng thái và chuẩn hóa

```bash
bash scripts/opengrep_scan_wsl.sh status
bash scripts/opengrep_scan_wsl.sh monitor
bash scripts/opengrep_scan_wsl.sh normalize
```

`monitor` hiển thị dashboard gọn và tự cập nhật mỗi 5 giây. Có thể đổi chu kỳ,
ví dụ `OPENGREP_MONITOR_INTERVAL=10 bash scripts/opengrep_scan_wsl.sh monitor`.
Nhấn `Ctrl+C` chỉ đóng dashboard, không dừng tiến trình scan ở terminal khác.
Dashboard báo riêng scanner errors và partial-parsing files. `PartialParsing`
không tự đổi job thành `FAILED`; chi tiết vẫn được lưu trong raw JSON và được
tổng hợp ở bước normalize.

`normalize` chỉ hoàn tất khi đủ 166/166 job. Khi điều tra batch chưa hoàn tất,
có thể tạo output tạm thời nhưng không dùng để báo metric chính thức:

```bash
OPENGREP_ALLOW_INCOMPLETE=1 bash scripts/opengrep_scan_wsl.sh normalize
```

Output normalized mặc định:

```text
artifacts/normalized/<scan-id>-opengrep-only/
```

Finding OpenGrep phải được giữ trong corpus thử nghiệm riêng. Dataset active
hiện vẫn là Semgrep-only; không nhập finding OpenGrep vào dataset FP hiện tại
nếu chưa tạo version/policy mới và chưa có human adjudication.

## Release r1 đã hoàn thành

Lượt chính thức ngày 2026-08-12 dùng scan-id:

```text
opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812
```

Kết quả: 166/166 job `SUCCESS`, 113.756 finding, 112.739 canonical cluster,
14 `CANDIDATE_REVIEW` và 112.725 `UNMATCHED`. Có 8.459 scanner diagnostic,
gồm 8.438 `PartialParsing`, 12 timeout ở mức rule/scanner, 8 `Syntax error` và
1 `Other syntax error`. Đây không phải job timeout: không job nào thất bại hoặc
hết hạn 7.200 giây.

Tạo lại annotation queue và frozen verifier corpus:

```bash
uv run vulngym-opengrep-release \
  --normalized-dir artifacts/normalized/opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812-opengrep-only \
  --queue-dir artifacts/annotation-queue/opengrep-v1.22.0-security-r1-20260812 \
  --corpus-dir artifacts/verifier-corpora/opengrep-security-r1-20260812 \
  --corpus-id opengrep-security-r1-20260812 \
  --created-at 2026-08-12T13:22:57+07:00
```

Queue chứa finding đầy đủ, metadata match chỉ dành cho human review, template
gold label và input verifier mù. Input mù loại canonical ID, VulnGym entry/report
ID, match, patch và adjudication label. Corpus được giữ riêng ở
`artifacts/verifier-corpora/opengrep-security-r1-20260812/`; validator runtime
và JSON Schema Semgrep đã được đóng băng nên không bị sửa. Ở đúng ranh giới
input, builder ánh xạ `{name: opengrep, version: 1.22.0}` thành định danh tương
thích `{name: other, version: "opengrep 1.22.0"}`; queue và release manifest
vẫn giữ scanner gốc là OpenGrep.

Release r1 chưa công bố precision/recall/F1 của OpenGrep verifier. Muốn có các
metric đó phải chạy agent trên corpus mù, khóa prediction, human review độc lập
rồi mới evaluate theo đúng gate của Semgrep. Kết quả so với human review cũ chỉ
là kiểm tra retention và nằm trong
`data/releases/opengrep-security-r1-20260812.json`.
