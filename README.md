# VulnGym Semgrep Finding Verifier

Project dùng Semgrep để tạo finding từ Tencent VulnGym, chuẩn hóa dữ liệu và dùng
agent đọc source tại đúng commit để đề xuất `TRUE_POSITIVE`, `FALSE_POSITIVE`
hoặc `ABSTAIN`. Người thẩm định độc lập gán nhãn sau khi prediction được khóa;
chỉ khi đó project mới tính precision, recall và F1.

Phạm vi hiện tại: **16 Semgrep finding trên 9 source snapshot**. Finding chưa
được xác minh luôn là candidate, không mặc định là false positive.

## Kết quả cuối

Release v5 đã hoàn tất toàn bộ workflow: 16/16 prediction thành công, prediction
đã khóa, evaluator đã chấp nhận đủ 16 gold-label record và sinh metrics. Nhãn
tham chiếu gồm 14 `TP_KNOWN`, 1 `FP_CONFIRMED` và 1 `UNCERTAIN`.

Trên 9 case mà agent đưa ra quyết định và gold label đủ điều kiện, kết quả là
TP=3, FP=0, TN=1, FN=5: precision **1,0000**, recall **0,3750** và F1
**0,5455**. Agent abstain 6/15 case được đánh giá, nên selective coverage là
**0,6000**. Một case `UNCERTAIN` được báo cáo riêng và không đưa vào ma trận.

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

Xem [quickstart v5](docs/semgrep-verifier-agent-v5.md), [thiết kế
agent](docs/verifier-agent.md), [quy tắc gán nhãn](docs/annotation-guideline.md)
và [báo cáo tổng kết](reports/final-semgrep-project-20260807.md).
