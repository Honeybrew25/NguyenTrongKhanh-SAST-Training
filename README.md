# VulnGym SAST Enrichment

Kho này dùng để:

1. chạy công cụ SAST trên các source snapshot của Tencent VulnGym;
2. chuẩn hóa và loại finding trùng;
3. dùng agent đọc source để xác minh finding;
4. để người thẩm định độc lập gán nhãn có bằng chứng;
5. tính precision, recall và F1 sau khi đủ nhãn.

Phiên bản đầu tiên hiện tập trung vào **Semgrep-only**: 16 finding trên 9
snapshot. OpenGrep đã bị loại khỏi workflow. CodeQL là baseline riêng và không
được trộn với kết quả Semgrep.

## Quy tắc quan trọng

- Finding không khớp VulnGym **không có nghĩa** là false positive.
- Agent không được xem nhãn, bản vá hoặc kết quả thẩm định trước đó.
- Thứ tự bắt buộc là: `Run → Freeze → Human review → Evaluate`.
- Chỉ công bố metric khi đủ prediction đã khóa và nhãn người thật có bằng chứng.
- Không dùng `--force`, `--development-run`, `--finding-id` hoặc
  `--allow-incomplete-gold` cho lượt đánh giá chính thức.

Các phiên bản được ghim trong [config/scanners.lock.json](config/scanners.lock.json)
và [config/semgrep-verifier-agent-v1.json](config/semgrep-verifier-agent-v1.json).

## 1. Chuẩn bị và kiểm tra

Cần có Git, Python 3.11+, `uv` và các Git submodule. Action `Run` của agent còn
cần Codex CLI đã đăng nhập và có quota.

Chạy từ thư mục gốc của repository.

### Windows — PowerShell

```powershell
git submodule update --init --recursive
uv sync --extra dev
$env:PYTHONUTF8 = "1"
uv run vulngym-audit `
  --benchmark benchmark/VulnGym `
  --output artifacts/manifests/vulngym-v0.1.4.json
uv run pytest
```

### Linux — Bash

```bash
git submodule update --init --recursive
uv sync --extra dev
export PYTHONUTF8=1
uv run vulngym-audit \
  --benchmark benchmark/VulnGym \
  --output artifacts/manifests/vulngym-v0.1.4.json
uv run pytest
```

Agent v1 dùng wrapper PowerShell. Trên Linux cần cài PowerShell 7 để có lệnh
`pwsh`. Chỉ chạy `Run` khi `Doctor` trả về
`ProviderIdentityMatches=True`; nếu sai, không bỏ qua gate mà phải dùng môi
trường đúng bản đã ghim hoặc tạo một release Linux riêng.

## 2. Chạy agent Semgrep v1

Wrapper dùng cố định corpus, model, prompt, schema và thư mục output của release
v1. Chỉ action `Run` gọi provider. Chạy từng action theo thứ tự dưới đây và chỉ
đi tiếp khi action trước thành công.

| Action | Mục đích | Điều kiện để đi tiếp |
| --- | --- | --- |
| `Doctor` | Kiểm tra công cụ và bản đã ghim | `LocalComponentsReady=True` |
| `Validate` | Kiểm tra blind input và source | đủ 16 finding, 9 snapshot |
| `Status` | Xem checkpoint hiện tại | không có lượt chạy trùng |
| `Run` | Chạy/resume agent | `COMPLETE`, 16/16 `SUCCESS` |
| `Freeze` | Khóa checksum prediction | tạo `prediction-freeze.json` |
| `PrepareHumanReview` | Tạo gói cho người thẩm định | không chứa prediction |
| `Evaluate` | Tính metric | đủ 16 human gold label hợp lệ |

### Windows — PowerShell

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Doctor
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Validate
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Status
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Run
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Freeze
.\scripts\semgrep_verifier_agent_v1.ps1 -Action PrepareHumanReview
$gold = "artifacts/human-review/semgrep-agent-v1-20260806/human-gold-labels.jsonl"
if (-not (Test-Path -LiteralPath $gold)) {
  Copy-Item `
    artifacts/human-review/semgrep-agent-v1-20260806/human-gold-labels.template.jsonl `
    $gold
}
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Evaluate
```

### Linux — Bash

```bash
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 -Action Doctor
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 -Action Validate
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 -Action Status
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 -Action Run
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 -Action Freeze
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 \
  -Action PrepareHumanReview
cp -n \
  artifacts/human-review/semgrep-agent-v1-20260806/human-gold-labels.template.jsonl \
  artifacts/human-review/semgrep-agent-v1-20260806/human-gold-labels.jsonl
pwsh -NoProfile -File ./scripts/semgrep_verifier_agent_v1.ps1 -Action Evaluate
```

Sau `PrepareHumanReview`, người thẩm định phải điền đủ 16 nhãn trong
`human-gold-labels.jsonl`, kèm lý do và bằng chứng `file:dòng`, rồi mới chạy
`Evaluate`. Người này không được mở prediction của agent trước khi khóa nhãn.

Nếu `Run` bị gián đoạn, chạy lại `Status`, xử lý lỗi provider rồi gọi lại `Run`;
không xóa case đã thành công. `Evaluate` sẽ tự dừng nếu một gate chưa hợp lệ.

## 3. Kết quả nằm ở đâu?

- Corpus mù: `artifacts/verifier-corpora/semgrep-day2-v1-20260806/`
- Trạng thái và prediction: `artifacts/verifier-runs/semgrep-agent-v1-20260806/`
- Gói thẩm định và metric: `artifacts/human-review/semgrep-agent-v1-20260806/`
- Source đúng commit: `worktrees/`

`artifacts/` là dữ liệu sinh ra trong lúc chạy và được Git bỏ qua.

## 4. Tài liệu chi tiết

- [Quickstart agent v1](docs/semgrep-verifier-agent-v1.md)
- [Thiết kế và ranh giới an toàn của agent](docs/verifier-agent.md)
- [Quy tắc gán nhãn](docs/annotation-guideline.md)
- [Báo cáo độc lập của Semgrep agent v1](reports/semgrep-agent-v1-20260806.md)
- [Tiến độ CodeQL/WSL](reports/day-4.md)
