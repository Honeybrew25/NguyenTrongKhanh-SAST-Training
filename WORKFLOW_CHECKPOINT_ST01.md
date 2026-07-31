# WORKFLOW CHECKPOINT ST01

Ngày cập nhật: 2026-07-30  
Project root: `D:\AI Vinsoc\NguyenTrongKhanh-SAST-Training`  
Trạng thái: hoàn thành nền tảng Ngày 1; chưa bắt đầu batch scan Ngày 2.

## 1. Mục tiêu tổng thể

Project mở rộng benchmark Tencent/VulnGym để đánh giá khả năng xác minh findings của security agent theo hai tầng:

1. **Enrich dataset** bằng findings thực tế sinh ra từ Semgrep/OpenGrep, đặc biệt là các false positive đã được kiểm chứng.
2. **Xây finding-verification agent** nhận repository snapshot và một scanner finding rồi trả về:
   - `TRUE_POSITIVE`
   - `FALSE_POSITIVE`
   - `ABSTAIN`
3. **Đánh giá verifier-only và end-to-end pipeline** bằng precision, recall, F1, TP retention, false-positive removal rate, advisory-level recall, entry-level recall, abstention và chi phí chạy agent.

Nguyên tắc quan trọng:

- Finding không match VulnGym **không tự động là false positive** vì VulnGym không đảm bảo liệt kê toàn bộ vulnerability trong mỗi repository.
- Verifier không được nhìn thấy CVE/GHSA ID, advisory title, VulnGym trace, fixed commit, patch hoặc nhãn trong lúc đánh giá.
- Finding-level classification phải được tách khỏi advisory/entry-level coverage.
- Test split sau này phải group theo repository/advisory để hạn chế data leakage.

## 2. Trạng thái benchmark đã freeze

### VulnGym

- Upstream: `Tencent/VulnGym`
- Tag: `v0.1.4`
- Commit: `cd69f7e163e08485ab5496115ae03439cda6e27e`
- Được lưu dưới dạng Git submodule tại `benchmark/VulnGym`.

Audit hiện tại:

- 184 advisories/reports.
- 408 entries.
- 393 human-verified entries.
- 15 unverified entries.
- 23 repositories.
- 38 project names.
- 166 cặp `(repo_url, vulnerable commit)` khác nhau.
- 44 entries có line range ở entry point hoặc critical operation.

Checksums:

- `entries.jsonl`: `2158b6bfef0be1812e7a6a77b32ad32b65964c2546c83018ff20a9a6f706c7b1`
- `reports.jsonl`: `5d29ce523441eb1739bddca3e4550514171b1b2b1f9d38bd922933408d25fbb9`

Manifest đã sinh:

- `artifacts/manifests/vulngym-v0.1.4.json`
- Chứa thống kê, checksum và danh sách đầy đủ 166 snapshots.
- `artifacts/` được Git-ignore vì đây là generated output.

### Scanner/ruleset

- Python: `3.11.9`, pin qua `.python-version`.
- uv: `0.11.18`.
- Semgrep: `1.171.0`, đã chạy local thành công.
- OpenGrep: `1.26.0`, đã tải và chạy local thành công.
- OpenGrep Windows executable SHA-256:
  `4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3`
- Semgrep-compatible rule corpus:
  `semgrep/semgrep-rules@40b8c63f75dc7c22c8a77482d73bfb864b146f7e`
- Rules được lưu dưới dạng Git submodule tại `rules/semgrep-rules`.
- Hai engine dự kiến sử dụng cùng ruleset để tách ảnh hưởng của engine khỏi ảnh hưởng của rule.

## 3. Workflow hiện đã triển khai

### 3.1. Dataset audit và manifest

Module: `src/vulngym_enrich/audit.py`

Chức năng:

- Đọc `reports.jsonl` và `entries.jsonl`.
- Validate JSONL, entry/report IDs, commit SHA, GitHub URL và `verify` flag.
- Validate `entry_point`, `critical_operation`, `trace` và one-based line/range.
- Kiểm tra quan hệ join giữa reports và entries.
- Nhóm entries thành 166 exact snapshots.
- Tính checksum và thống kê.
- Sinh reproducibility manifest.

CLI:

```bash
uv run vulngym-audit \
  --benchmark benchmark/VulnGym \
  --output artifacts/manifests/vulngym-v0.1.4.json
```

### 3.2. Exact snapshot cache/checkout

Module: `src/vulngym_enrich/checkout.py`

Chức năng:

- Chỉ chấp nhận public GitHub HTTPS repository URL hợp lệ.
- Cache một bare Git mirror cho mỗi repository.
- Materialize exact vulnerable commit dưới `worktrees/`.
- Không overwrite destination không có marker hợp lệ.
- Kiểm tra `git rev-parse HEAD` sau checkout.
- Hỗ trợ refresh mirror.

Prefetch các repository trong manifest:

```bash
uv run vulngym-checkout prefetch \
  --manifest artifacts/manifests/vulngym-v0.1.4.json \
  --cache-root cache
```

Checkout một snapshot:

```bash
uv run vulngym-checkout checkout \
  --repo-url <github-url> \
  --commit <40-character-sha> \
  --cache-root cache \
  --work-root worktrees
```

Smoke test đã thực hiện với:

- Repository: `https://github.com/nltk/nltk`
- Commit: `40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e`
- Kết quả: `checkout-smoke=OK`.

### 3.3. Range-aware matcher

Module: `src/vulngym_enrich/matcher.py`

Chức năng:

- Parse line dạng integer hoặc range string, ví dụ `100-105`.
- Dùng inclusive interval distance.
- Normalize slash và leading `./` trong paths.
- Match đúng repository, commit, entry point và critical operation.
- Hỗ trợ configurable line tolerance.

Lý do cần module mới:

- Upstream VulnGym schema cho phép line range.
- Upstream evaluator dùng `int(line)`, nên không xử lý đúng range string.
- Dataset hiện có 44/408 entries bị ảnh hưởng bởi vấn đề này.

### 3.4. Evaluator

Module: `src/vulngym_enrich/evaluator.py`

Có hai chế độ:

1. Coverage:
   - Entry-level recall.
   - Advisory-level recall.
   - Inclusive line-range matching.
2. Finding verifier classification:
   - TP/FP/TN/FN.
   - Precision.
   - Recall/TP retention.
   - F1.
   - Specificity.
   - False-positive removal rate.
   - Accuracy trên decided cases.
   - Abstention và selective coverage.

CLI dự kiến:

```bash
uv run vulngym-evaluate coverage \
  --entries benchmark/VulnGym/data/entries.jsonl \
  --findings <findings.jsonl>
```

```bash
uv run vulngym-evaluate classify \
  --labels <labels.jsonl> \
  --predictions <predictions.jsonl>
```

### 3.5. Enriched finding schema và annotation

Files:

- `schemas/enriched-finding.schema.json`
- `docs/annotation-guideline.md`

Nhãn đã định nghĩa:

- `TP_KNOWN`
- `TP_NOVEL`
- `FP_CONFIRMED`
- `UNCERTAIN`
- `DUPLICATE`
- `OUT_OF_SCOPE`

Primary confusion matrix chỉ dùng:

- Positive: `TP_KNOWN`, `TP_NOVEL`.
- Negative: `FP_CONFIRMED`.
- Các nhãn còn lại được report riêng.

Schema giữ các trường provenance quan trọng:

- Repository và exact commit.
- Scanner name/version.
- Ruleset commit và rule ID.
- CWE/category/severity.
- Finding location.
- Dataflow trace.
- Raw result reference và scan ID.
- Dedup canonical ID.
- Adjudication rationale, evidence, annotator và linked VulnGym IDs.

### 3.6. Scanner configuration

Files:

- `config/scanners.lock.json`
- `config/scan-profile.json`

Đã pin:

- Benchmark commit.
- Rule corpus commit.
- Scanner versions.
- OpenGrep download URL và checksum.
- Common excludes.
- Timeout, target-size và output policy.
- Raw JSON/SARIF preservation policy.

Scanner smoke fixture:

- Rule: `tests/fixtures/rules/python-eval.yml`
- Target: `smoke/unsafe.py`

Kết quả smoke test:

- Semgrep: 1 finding.
- OpenGrep: 1 finding.

## 4. Files đã tạo/sửa

### Project và dependency management

- `.gitignore` — ignore virtualenv, caches, worktrees và generated scanner artifacts.
- `.gitmodules` — khai báo VulnGym và semgrep-rules submodules.
- `.python-version` — pin Python 3.11.9.
- `pyproject.toml` — package metadata, CLI entry points và pytest config.
- `uv.lock` — dependency lock.
- `README.md` — mục tiêu, frozen inputs, setup và layout.

### Pinned external sources

- `benchmark/VulnGym` — submodule tại VulnGym v0.1.4.
- `rules/semgrep-rules` — submodule tại ruleset commit đã pin.

### Configuration và schema

- `config/scanners.lock.json`
- `config/scan-profile.json`
- `schemas/enriched-finding.schema.json`
- `docs/annotation-guideline.md`

### Python implementation

- `src/vulngym_enrich/__init__.py`
- `src/vulngym_enrich/audit.py`
- `src/vulngym_enrich/checkout.py`
- `src/vulngym_enrich/matcher.py`
- `src/vulngym_enrich/evaluator.py`

### Tests và fixtures

- `tests/test_day1.py`
- `tests/fixtures/rules/python-eval.yml`
- `smoke/unsafe.py`

### Reports

- `reports/day-1.md`
- `WORKFLOW_CHECKPOINT_ST01.md` — checkpoint hiện tại.

### Generated/Git-ignored artifacts

- `artifacts/manifests/vulngym-v0.1.4.json`
- `artifacts/smoke/semgrep.json`
- `artifacts/smoke/opengrep.json`
- `cache/tools/opengrep/1.26.0/opengrep.exe`
- `cache/mirrors/nltk__nltk.git`
- `worktrees/nltk__nltk/40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e`

## 5. Các lệnh chính đã chạy

### Toolchain discovery

```bash
git --version
python --version
uv --version
docker --version
semgrep --version
opengrep --version
pytest --version
```

Kết quả ban đầu:

- Git và Python hoạt động.
- Semgrep có sẵn.
- OpenGrep chưa có trong PATH.
- Docker CLI có sẵn.
- Docker Linux daemon không chạy.

### Git/project initialization

```bash
git init -b main
git submodule add https://github.com/Tencent/VulnGym.git benchmark/VulnGym
git -C benchmark/VulnGym checkout v0.1.4
git submodule add --depth 1 https://github.com/semgrep/semgrep-rules.git rules/semgrep-rules
```

### Python environment

```bash
uv sync --extra dev
uv venv --python 3.11.9 --clear
uv sync --extra dev
uv run python --version
```

Python cuối cùng: `3.11.9`.

### Dataset audit

```bash
uv run vulngym-audit \
  --benchmark benchmark/VulnGym \
  --output artifacts/manifests/vulngym-v0.1.4.json
```

### OpenGrep setup

```bash
curl -fL --retry 3 \
  -o cache/tools/opengrep/1.26.0/opengrep.exe \
  https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_windows_x86.exe

printf '4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3 *cache/tools/opengrep/1.26.0/opengrep.exe\n' \
  | sha256sum -c -

cache/tools/opengrep/1.26.0/opengrep.exe --version
```

### Scanner smoke test

Lần đầu scanner không scan fixture dưới `tests/fixtures/target` vì ignore policy và trả về 0 findings. Smoke target sau đó được chuyển sang `smoke/unsafe.py` và thêm `--no-git-ignore`:

```bash
semgrep scan \
  --no-git-ignore \
  --config tests/fixtures/rules/python-eval.yml \
  --json \
  --output artifacts/smoke/semgrep.json \
  smoke

cache/tools/opengrep/1.26.0/opengrep.exe scan \
  --no-git-ignore \
  -f tests/fixtures/rules/python-eval.yml \
  --json-output artifacts/smoke/opengrep.json \
  smoke
```

Kết quả cuối cùng: mỗi engine sinh đúng 1 finding.

### Checkout smoke test

```bash
uv run vulngym-checkout checkout \
  --repo-url https://github.com/nltk/nltk \
  --commit 40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e \
  --cache-root cache \
  --work-root worktrees
```

### Tests và static checks

```bash
uv run pytest
uv run python -m compileall -q src tests
python -m json.tool schemas/enriched-finding.schema.json
python -m json.tool config/scanners.lock.json
python -m json.tool config/scan-profile.json
git diff --check
```

Fresh test gần nhất:

```text
7 passed in 0.06s
```

Test suite bao gồm self-match toàn bộ 408 entries và 184 advisories, kể cả 44 range-bearing entries.

### Git commit

```bash
git add .
git diff --cached --check
git commit -m "feat: establish VulnGym enrichment benchmark foundation"
```

Commit hiện tại:

```text
6b74e44 feat: establish VulnGym enrichment benchmark foundation
```

Trước khi tạo checkpoint này, working tree sạch.

## 6. Lỗi/blocker và việc chưa hoàn thành

### 6.1. Docker daemon chưa chạy

Docker CLI đã cài, nhưng lệnh:

```bash
docker info --format '{{.ServerVersion}}'
```

hiện trả về:

```text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

Ảnh hưởng:

- Chưa thể verify hoặc dùng Docker-based scanner execution.
- Không block local Semgrep/OpenGrep vì cả hai đã chạy thành công bằng executable local.

Cách xử lý:

- Khởi động Docker Desktop trước khi cần containerized batch scans.
- Batch runner phải giữ local executable fallback.

### 6.2. Batch scanner Ngày 2 chưa được triển khai

Chưa có module thực hiện đầy đủ:

- Iterate 166 snapshots.
- Checkout tuần tự hoặc song song có kiểm soát.
- Chọn applicable rules theo language.
- Chạy cả Semgrep và OpenGrep.
- Lưu raw JSON và SARIF theo deterministic path.
- Resume/retry/timeout.
- Scan status journal.
- Normalize scanner outputs về enriched schema.
- Deduplicate exact và semantic findings.

### 6.3. Chưa chạy full scan

Hiện mới chạy smoke fixture, chưa scan 166 VulnGym snapshots. Vì vậy chưa có:

- Tổng số raw findings.
- Tỷ lệ findings/scanner/repository/rule.
- TP candidate matching statistics.
- False-positive dataset.
- Precision/recall/F1 thực tế.

### 6.4. Chưa xây verification agent

Chưa có agent implementation hoặc open-source baseline integration. Hiện mới có schema, annotation policy và evaluator foundation.

### 6.5. Chưa có adjudicated labels

Chưa có human-reviewed `TP_KNOWN`, `TP_NOVEL`, `FP_CONFIRMED` records. Không được báo precision/F1 trước khi có tập nhãn hợp lệ.

### 6.6. Một scanner smoke pitfall đã được xử lý

Fixture đặt dưới `tests/fixtures/target` ban đầu bị ignore và cả hai scanner trả về 0 findings. Đã khắc phục bằng:

- Chuyển target sang `smoke/unsafe.py`.
- Dùng `--no-git-ignore` trong smoke command.

Batch runner Ngày 2 cần quản lý ignore policy rõ ràng thay vì mặc định thêm `--no-git-ignore` cho mọi target. Scan chính nên respect target repository `.gitignore`, đồng thời ghi lại skipped files.

## 7. Bước tiếp theo đề xuất: Ngày 2

### Bước 1 — Batch-runner skeleton

Tạo module, ví dụ:

- `src/vulngym_enrich/scanner.py`
- CLI `vulngym-scan`

Input:

- Snapshot manifest.
- Scanner lock.
- Scan profile.
- Cache/worktree roots.
- Scanner selector.
- Snapshot/repository filter.

Output deterministic:

```text
artifacts/scans/<scan-id>/<repo-slug>/<commit>/<scanner>/raw.json
artifacts/scans/<scan-id>/<repo-slug>/<commit>/<scanner>/raw.sarif
artifacts/scans/<scan-id>/<repo-slug>/<commit>/<scanner>/status.json
```

### Bước 2 — Resume/retry và provenance

Mỗi snapshot-scanner job cần trạng thái:

- `PENDING`
- `RUNNING`
- `SUCCESS`
- `FAILED`
- `TIMEOUT`
- `SKIPPED`

Status phải lưu:

- Command arguments.
- Scanner version.
- Ruleset commit.
- Start/end timestamps.
- Exit code.
- stdout/stderr references.
- Raw output checksum.

### Bước 3 — Pilot trước full scan

Không chạy ngay cả 166 snapshots. Chọn pilot có kiểm soát, ví dụ:

- NLTK: Python, nhỏ.
- TypeScript/JavaScript repository nhỏ hoặc vừa.
- Go repository nhỏ hoặc vừa.
- Một large repository để đo timeout/disk behavior.

Acceptance criteria pilot:

- Cả Semgrep/OpenGrep chạy thành công.
- Raw JSON parse được.
- Provenance đầy đủ.
- Resume không chạy lại successful job.
- Failed job có thể retry.
- Không ghi đè raw evidence ngoài ý muốn.

### Bước 4 — Normalizer

Chuyển raw outputs sang `enriched-finding.schema.json`:

- Stable `finding_id`.
- Repo/commit.
- Scanner/version.
- Rule/ruleset commit.
- File/start/end line và columns.
- Message/severity/CWE.
- Dataflow trace khi có.
- Raw result reference.
- Fingerprint.

### Bước 5 — Deduplication

Hai mức:

1. Exact duplicate theo repo, commit, scanner, rule, normalized location.
2. Cross-tool semantic cluster theo repo, commit, file/range, CWE/category và snippet fingerprint.

Giữ toàn bộ `observed_by` provenance; không xóa evidence của tool nguồn.

### Bước 6 — Known-positive matcher

Phân tầng match:

- Strict source + sink match.
- Strong sink/category/dataflow match.
- Candidate match cần review.
- Unmatched vẫn để `UNLABELED`, không tự gán FP.

### Bước 7 — Full scan sau khi pilot pass

Sau pilot và resource estimate:

- Prefetch 23 repository mirrors.
- Scan 166 snapshots.
- Theo dõi disk usage, duration, failures và rule counts.
- Sinh Day 2 report và candidate dataset statistics.

## 8. Lệnh tiếp tục nhanh

Từ project root:

```bash
cd 'D:\AI Vinsoc\NguyenTrongKhanh-SAST-Training'
git submodule update --init --recursive
uv sync --extra dev
uv run pytest
uv run vulngym-audit \
  --benchmark benchmark/VulnGym \
  --output artifacts/manifests/vulngym-v0.1.4.json
```

Kiểm tra scanners:

```bash
semgrep --version
cache/tools/opengrep/1.26.0/opengrep.exe --version
```

Nếu muốn dùng Docker:

```bash
docker info
```

Nếu Docker vẫn lỗi, tiếp tục bằng local scanner mode.

## 9. Git state tại checkpoint

Base commit trước checkpoint:

```text
6b74e44 feat: establish VulnGym enrichment benchmark foundation
```

`WORKFLOW_CHECKPOINT_ST01.md` được tạo sau commit trên và cần được add/commit nếu muốn lưu checkpoint vào Git history.
