# Quét CodeQL trên Ubuntu WSL2/ext4

Workflow này tách biệt hoàn toàn với release Semgrep và OpenGrep. CodeQL không
được thêm vào `vulngym-scan`; nó dùng runner riêng để giữ đúng database,
build-mode, query-pack và provenance của CodeQL.

## Trạng thái đã kiểm tra

- Máy: WSL2 x86_64, 8 logical CPU, 15.6 GiB RAM, 8 GiB swap, project trên ext4.
- Corpus: 166 snapshot đã materialize, không thiếu worktree.
- Kế hoạch: 169 job gồm 131 JavaScript/TypeScript, 30 Python, 7 Go và 1 GitHub
  Actions. Một snapshot có thể cần nhiều extractor.
- Pin đang dùng: CodeQL bundle `2.25.5`; query pack Actions `0.6.28`, Go `1.6.3`,
  JavaScript `2.3.10`, Python `1.8.3`; Go runtime vận hành `1.24.11`.
- Build mode: Actions, JavaScript/TypeScript và Python dùng `none`; Go dùng
  `autobuild`. CodeQL 2.25.5 không hỗ trợ `none` cho Go.
- Pilot cold-cache ngày 2026-08-12: 3/3 `SUCCESS` trong 205.26 giây wall-clock,
  peak RSS 3,929,704 KiB, không swap. Resume 3/3 mất 0.10 giây.

Không đổi bundle/query pack giữa một scan-id. Khi nâng lên bundle mới, tạo
profile và scan-id mới để kết quả còn so sánh và tái lập được.

Go 1.24.11 và timeout analyze 7.200 giây được truyền dưới dạng runtime override
có ghi provenance. Profile gốc không bị sửa nên 66 job `SUCCESS` không phải Go
vẫn được reuse. Năm job Go đã thành công sẽ được tạo lại cùng hai job Go lỗi,
vì toolchain là một phần của extraction identity.

## Hai profile

| Profile | Suite | Mục tiêu | Disk cache/job |
|---|---|---|---:|
| `config/codeql-profile-wsl-fast.json` | `code-scanning` | tốc độ và precision tốt, phù hợp vòng đầu | 1 GiB |
| `config/codeql-profile-wsl-full.json` | `security-extended` | độ phủ rộng hơn, dùng cho baseline full | 2 GiB |

`code-scanning` không phải bản thay thế tương đương cho `security-extended`.
Trong pilot nhanh, CodeQL sinh 45 finding (36 có dataflow): JS/TS 15, Python 0,
Go 30. Khi tái sử dụng database, pilot `security-extended` mất 25.32 giây và
sinh 84 finding (70 có dataflow): JS/TS 52, Python 2, Go 30. Vì vậy baseline
chính nên dùng `security-extended`; profile nhanh phù hợp smoke/triage.

## Thiết lập và doctor

```bash
cd ~/projects/NguyenTrongKhanh-SAST-Training-opengrep
bash scripts/codeql_scan_wsl.sh setup
bash scripts/codeql_scan_wsl.sh doctor
bash scripts/codeql_scan_wsl.sh plan
```

`setup` tải có resume và kiểm SHA-256 trước khi giải nén. `doctor` fail-closed
nếu sai kiến trúc/filesystem, binary hoặc query-pack sai pin, thiếu snapshot,
hay cấu hình CPU/RAM vượt máy hiện tại.

## Cấu hình nhanh nhất phù hợp máy hiện tại

Mức cân bằng đã đo và đặt mặc định:

- 2 snapshot đồng thời;
- 3 evaluator thread/job (tổng 6/8 CPU);
- 5,632 MiB analyze RAM/job (tổng 11,264 MiB, còn hơn 3 GiB cho WSL/runner);
- `--max-paths=1` để giảm chi phí SARIF/dataflow;
- database và BQRS được giữ để resume/re-analyze;
- timeout analyze mỗi attempt là 2 giờ;
- query pack có sẵn trong bundle và `--no-download` trong lúc analyze;
- nguồn, database, cache và artifact đều ở ext4, không dùng `/mnt/c` hay
  `/mnt/d`.

Không tăng lên 3 worker trên máy này: 3 × 3 thread vượt 8 CPU và 3 × 5.5 GiB
vượt ngân sách RAM. `run-heavy` mặc định dành riêng tài nguyên cho OpenClaw:
1 worker, 6 thread, 10.240 MiB RAM và 8.192 MiB disk cache. Cách này xử lý nút
thắt cache 2 GiB đã quan sát và tránh hai evaluator nặng tranh CPU/RAM:

```bash
CODEQL_PROFILE=config/codeql-profile-wsl-full.json \
bash scripts/codeql_scan_wsl.sh run-heavy
```

Go chạy một worker vì `autobuild` và tải dependency là nút thắt. Module/build
cache dùng chung tại `cache/codeql/go-1.24.11`; lần cold-cache của Ollama mất
171.17 giây để create nhưng chỉ 11.41 giây để analyze. Tăng nhiều Go worker
thường chỉ tranh network, disk và RAM.

Giới hạn 2 giờ ngắn hơn attempt OpenClaw trước đó. Tăng thread/cache có thể giảm
đáng kể thời gian nhưng không bảo đảm dưới 2 giờ. Nếu retry vẫn timeout, giữ
nguyên pinned pack và chia 104 query `security-extended` thành các lane rời nhau;
mỗi lane dùng lại cùng database rồi hợp nhất SARIF. Không tăng worker hoặc chạy
lại 66 job không phải Go đã thành công.

## Pilot và full scan

Vòng nhanh:

```bash
bash scripts/codeql_scan_wsl.sh pilot
bash scripts/codeql_scan_wsl.sh run
```

Baseline full `security-extended`:

```bash
export CODEQL_PROFILE=config/codeql-profile-wsl-full.json
bash scripts/codeql_scan_wsl.sh doctor
bash scripts/codeql_scan_wsl.sh plan
/usr/bin/time -v bash scripts/codeql_scan_wsl.sh run \
  |& tee artifacts/codeql-security-extended-wsl-20260812.log
```

`run` chủ động chia ba queue: main interpreted, Go, rồi OpenClaw heavy. Có thể
chạy/resume từng queue bằng `run-main`, `run-go`, `run-heavy`. Job `SUCCESS` có
đúng profile/query identity được tái sử dụng; job lỗi được retry khi
`CODEQL_RETRY_FAILED=1` (mặc định).

## Theo dõi liên tục và thời gian thực hiện

Mở terminal WSL thứ hai:

```bash
export CODEQL_PROFILE=config/codeql-profile-wsl-full.json
bash scripts/codeql_scan_wsl.sh monitor
```

Hoặc xem một lần:

```bash
bash scripts/codeql_scan_wsl.sh status
```

Monitor hiển thị tổng tiến độ, trạng thái process và elapsed time của từng job
đang chạy. `Ctrl+C` chỉ dừng monitor, không dừng scanner.

Phiên resume ngày 13/08/2026 chạy trong user service. Có thể theo dõi log và
service mà không ảnh hưởng scanner:

```bash
tail -F artifacts/codeql-security-extended-wsl-resume-20260813.log
systemctl --user status \
  vulngym-codeql-wsl-resume-20260813.service \
  vulngym-codeql-go-followup-20260813.service
```

## Chuẩn hóa

Chỉ chạy khi full plan 169 job đều thành công:

```bash
export CODEQL_PROFILE=config/codeql-profile-wsl-full.json
bash scripts/codeql_scan_wsl.sh normalize
```

Output nằm tại `artifacts/normalized/<scan-id>/`. Pipeline không trộn CodeQL
vào precision/recall/F1 của Semgrep hay OpenGrep; finding chưa human-review vẫn
chỉ là candidate, không mặc định là false positive.

Tài liệu tham chiếu chính thức: [CodeQL CLI database create](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-manual/database-create),
[database analyze](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-manual/database-analyze)
và [CodeQL query suites](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/codeql-query-suites).
