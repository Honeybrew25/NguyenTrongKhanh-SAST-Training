# VulnGym Semgrep Verifier và OpenGrep Baseline

Project quét 166 source snapshot của Tencent VulnGym, chuẩn hóa/deduplicate
finding và tạo corpus mù cho agent đọc source tại đúng commit. Release Semgrep
v5 đã hoàn tất agent + human review + metrics; release OpenGrep r1 đã hoàn tất
full scan + normalize + annotation queue + frozen verifier corpus.

Finding chưa được xác minh luôn là candidate, không mặc định là false positive.

## Kết quả Semgrep v5

Release v5 đã hoàn tất toàn bộ workflow: 16/16 prediction thành công, prediction
đã khóa, evaluator đã chấp nhận đủ 16 gold-label record và sinh metrics. Nhãn
tham chiếu gồm 14 `TP_KNOWN`, 1 `FP_CONFIRMED` và 1 `UNCERTAIN`.

Trên 9 case mà agent đưa ra quyết định và gold label đủ điều kiện, kết quả là
TP=3, FP=0, TN=1, FN=5: precision **1,0000**, recall **0,3750** và F1
**0,5455**. Agent abstain 6/15 case được đánh giá, nên selective coverage là
**0,6000**. Một case `UNCERTAIN` được báo cáo riêng và không đưa vào ma trận.

## Kết quả OpenGrep r1

Full scan OpenGrep `1.22.0` trên Ubuntu WSL2/ext4 đã hoàn thành **166/166 job
SUCCESS**. Pipeline ghi nhận 113.756 finding, 112.739 canonical cluster, 14
`CANDIDATE_REVIEW` và 112.725 `UNMATCHED`. Corpus mù 14 record đã được đóng băng
với SHA-256
`7abb5bd8064a00fe4da18f16f1c4a2b6e8fc2d31d7b886fea5c9c14e6cc5bc7a`.

14 candidate OpenGrep đều trùng khóa ngữ nghĩa với candidate đã review của
Semgrep: 12 `TP_KNOWN`, 1 `FP_CONFIRMED`, 1 `UNCERTAIN`. Đây chỉ là phép kiểm
tra retention trên corpus cũ, không phải gold label hay precision/recall/F1
của OpenGrep. Hai `TP_KNOWN` Semgrep thuộc rule `detect-child-process` không
xuất hiện trong queue OpenGrep và được ghi rõ trong release manifest.

## Yêu cầu

- Git, Python 3.11+, `uv` và Codex CLI đã đăng nhập.
- Agent workflow trên Windows dùng PowerShell 7. OpenGrep trên Ubuntu WSL2 dùng
  Bash và không cần `pwsh`.
- Lượt chính thức phải theo đúng thứ tự `Doctor → Validate → Run → Freeze →
  PrepareHumanReview → Evaluate`.

## 1. Cài đặt và kiểm thử

Windows — PowerShell:

```powershell
git submodule update --init --recursive
uv sync --extra dev
$env:PYTHONUTF8 = "1"
uv run pytest -q
```

OpenGrep trên Ubuntu WSL2 dùng workflow độc lập, không thay đổi release Semgrep
v5 hiện tại:

```bash
cd ~/projects/NguyenTrongKhanh-SAST-Training-opengrep
bash scripts/opengrep_scan_wsl.sh setup
bash scripts/opengrep_scan_wsl.sh doctor
bash scripts/opengrep_scan_wsl.sh smoke
```

Project và toàn bộ cache/worktree OpenGrep phải nằm trên filesystem Linux của
WSL (ext4), không đặt dưới `/mnt/c` hoặc `/mnt/d`. Full run mặc định dùng ruleset
security-only, prefetch 4 repository song song và quét 2 snapshot song song × 3
worker OpenGrep. Chạy `bash scripts/opengrep_scan_wsl.sh benchmark` nếu muốn đo
lại mức `jobs=4/6/8` trên máy hiện tại.

Xem [hướng dẫn OpenGrep WSL](docs/opengrep-wsl.md) trước khi chạy full batch.

CodeQL dùng runner và database riêng. Hai profile WSL đã được thiết lập cho
`code-scanning` (nhanh) và `security-extended` (độ phủ rộng):

```bash
bash scripts/codeql_scan_wsl.sh setup
bash scripts/codeql_scan_wsl.sh doctor
bash scripts/codeql_scan_wsl.sh plan
bash scripts/codeql_scan_wsl.sh pilot
```

Xem [hướng dẫn CodeQL WSL](docs/codeql-wsl.md) để chọn profile, chạy ba queue
main/Go/OpenClaw, theo dõi elapsed time và normalize kết quả.

Để tái tạo queue và corpus OpenGrep từ normalized output đã hoàn chỉnh:

```bash
uv run vulngym-opengrep-release \
  --normalized-dir artifacts/normalized/opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812-opengrep-only \
  --queue-dir artifacts/annotation-queue/opengrep-v1.22.0-security-r1-20260812 \
  --corpus-dir artifacts/verifier-corpora/opengrep-security-r1-20260812 \
  --corpus-id opengrep-security-r1-20260812 \
  --created-at 2026-08-12T13:22:57+07:00
```

Lệnh fail-closed nếu coverage không đủ, có job khác `SUCCESS`, input không phải
OpenGrep-only, candidate count lệch hoặc policy vô tình gán `UNMATCHED` thành
false positive.

## 2. Chạy agent chính thức v5

Windows — PowerShell:

```powershell
.\scripts\semgrep_verifier_agent_v5.ps1 -Action Doctor
.\scripts\semgrep_verifier_agent_v5.ps1 -Action Validate
.\scripts\semgrep_verifier_agent_v5.ps1 -Action Status
.\scripts\semgrep_verifier_agent_v5.ps1 -Action Run
.\scripts\semgrep_verifier_agent_v5.ps1 -Action Freeze
.\scripts\semgrep_verifier_agent_v5.ps1 -Action PrepareHumanReview
.\scripts\semgrep_verifier_agent_v5.ps1 -Action Evaluate
```

Chỉ chạy `Run` khi `Doctor` báo `ProviderIdentityMatches=True` và `Validate` báo
`VALID`. Nếu bị gián đoạn, gọi lại `Run`; runner tái sử dụng case `SUCCESS` có
identity đúng và chỉ retry case lỗi.

Sau `PrepareHumanReview`, giao gói source-only cho một người thẩm định không xem
prediction. Người đó điền đủ 16 nhãn có lý do và bằng chứng `file:dòng` vào
`human-gold-labels.jsonl`. `Evaluate` sẽ dừng nếu thiếu prediction đã khóa, thiếu
nhãn, reviewer không phải người thật hoặc evidence không hợp lệ.

## 3. Dữ liệu chính

- Corpus mù: `artifacts/verifier-corpora/semgrep-day2-v1-20260806/`
- Run v5: `artifacts/verifier-runs/semgrep-agent-v5-20260807/`
- Gói thẩm định: `artifacts/human-review/semgrep-agent-v5-20260807/`
- Metrics: `artifacts/human-review/semgrep-agent-v5-20260807/metrics.json`
- Dataset FP làm giàu: `data/enriched/day2-semgrep-reviewed.jsonl`
- Source snapshot: `worktrees/`
- Release ghim: `config/semgrep-verifier-agent-v5.json`
- OpenGrep normalized: `artifacts/normalized/opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812-opengrep-only/`
- OpenGrep queue: `artifacts/annotation-queue/opengrep-v1.22.0-security-r1-20260812/`
- OpenGrep verifier corpus: `artifacts/verifier-corpora/opengrep-security-r1-20260812/`
- OpenGrep release manifest: `data/releases/opengrep-security-r1-20260812.json`

Xem [quickstart v5](docs/semgrep-verifier-agent-v5.md), [thiết kế
agent](docs/verifier-agent.md), [quy tắc gán nhãn](docs/annotation-guideline.md)
và hai báo cáo tổng kết [Semgrep](reports/final-semgrep-project-20260807.md),
[OpenGrep](reports/final-opengrep-project-20260812.md).
