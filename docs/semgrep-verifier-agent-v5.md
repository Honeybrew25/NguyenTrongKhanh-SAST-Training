# Semgrep Verifier Agent v5

Release v5 xác minh corpus cố định gồm 16 finding trên 9 snapshot. Scanner được
ghim ở Semgrep `1.171.0`, model là `gpt-5.6-sol`, và output chính thức nằm tại
`artifacts/verifier-runs/semgrep-agent-v5-20260807/`.

Controller v5 giữ nguyên citation của agent nhưng tự chia một phạm vi dài thành
các đoạn liên tiếp tối đa 25 dòng. Không dòng source nào bị thêm hoặc bỏ. Các
lỗi nội dung khác, như trường kết luận bị để trống, vẫn bị từ chối.

## Các gate bắt buộc

1. `Doctor` kiểm tra `uv`, Codex CLI, version và checksum binary.
2. `Validate` kiểm tra blind input, checksum và source đúng commit.
3. `Run` xử lý đủ 16 case. Chạy lại action này để resume case lỗi.
4. `Freeze` khóa checksum của 16 prediction hoàn chỉnh.
5. `PrepareHumanReview` tạo gói source-only, không chứa prediction.
6. Người thẩm định độc lập điền đủ nhãn có lý do và evidence `file:dòng`.
7. `Evaluate` kiểm tra toàn bộ gate rồi mới tính metric.

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

Linux — Bash:

```bash
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action Doctor
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action Validate
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action Status
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action Run
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action Freeze
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action PrepareHumanReview
pwsh -File ./scripts/semgrep_verifier_agent_v5.ps1 -Action Evaluate
```

Chỉ `Freeze` khi trạng thái là `COMPLETE` với 16/16 `SUCCESS`. Nếu có `FAILED`,
gọi lại `Run`; runner giữ case thành công và retry case lỗi. Không chạy subset,
development mode, `--force` hoặc bỏ qua incomplete gold trong lượt chính thức.

Precision, recall và F1 chỉ được công bố sau khi prediction đã khóa và một người
thật hoàn tất đủ 16 gold label độc lập có bằng chứng.

## Trạng thái release ngày 07/08/2026

Workflow hiện ở trạng thái `DONE`: 16/16 case thành công, prediction đã khóa,
gold-label gate và bước `Evaluate` đều hoàn tất. Gold labels gồm 14
`TP_KNOWN`, 1 `FP_CONFIRMED` và 1 `UNCERTAIN`.

Evaluator tính trên 15 nhãn đủ điều kiện; agent quyết định 9 và abstain 6. Ma
trận cho các case đã quyết định là TP=3, FP=0, TN=1, FN=5. Precision là 1,0000,
recall là 0,3750, F1 là 0,5455 và selective coverage là 0,6000. Case
`UNCERTAIN` không được đưa vào các chỉ số chính.

Kết quả máy đọc nằm tại
`artifacts/human-review/semgrep-agent-v5-20260807/metrics.json`.
