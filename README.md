# VulnGym OpenGrep Machine-Reference Baseline

Project quét 166 source snapshot của Tencent VulnGym bằng OpenGrep, chuẩn hóa và
gộp trùng finding, tạo prevalence sample 400 record, review mù bằng nhiều LLM và
đánh giá ba baseline trên split theo repository.

Release active là OpenGrep machine-only. Reference do Gemini A/B và GPT-5.6
Luna C tạo, vì vậy kết quả là `LLM_ADJUDICATED_MACHINE_REFERENCE`, **không phải
human gold**. Theo policy hiện tại, các số đo được công bố là **project-approved
machine-reference metrics**: chính thức trong phạm vi project nhưng không phải
universal ground truth hay kết quả do người xác minh.

Người mới có thể xem [chú giải thuật ngữ](docs/thuat-ngu-bao-cao.md) trước khi
đọc bảng kết quả và các báo cáo theo ngày.

## Trạng thái hiện tại

- OpenGrep 1.22.0: 166/166 job thành công.
- 113.756 finding, 112.739 canonical cluster, 129 rule trên 23 repository.
- Prevalence sample: 400 record thuộc 16 repository.
- Machine reference r20: 400/400 gồm 7 TP máy, 367 FP máy, 26 UNCERTAIN.
- Enriched dataset: 400 OpenGrep-only record.
- Post-freeze linkage: 7/7 TP là `MACHINE_TP_UNLINKED`; không diễn giải là
  novelty.
- Balanced benchmark: train=6, validation=4, test=4; repository/finding
  overlap=0.
- Ba baseline: hoàn tất trên cùng test set, mỗi run 4/4 success.

## Kết quả baseline

| Baseline | TP/FP/TN/FN | Precision | TP retention | F1 | Coverage |
|---|---|---:|---:|---:|---:|
| Raw OpenGrep | 2/2/0/0 | 0,5000 | 1,0000 | 0,6667 | 1,0000 |
| GPT-5.6 Luna snippet-only | 0/0/2/0 + 2 abstain TP | N/A | 0,0000 | N/A | 0,5000 |
| GPT-5.6 Luna repository-context | 1/0/2/1 | 1,0000 | 0,5000 | 0,6667 | 1,0000 |

Test chỉ có 4 record của một repository và Luna cũng là adjudicator C, nên bảng
này dùng để kiểm tra workflow/so sánh hành vi, không đủ cho kết luận tổng quát
ngoài phạm vi machine reference r20. Chi tiết ở
[báo cáo 14/08/2026](reports/report-14-08-2026.md).

## Cài đặt và kiểm thử

Ubuntu WSL2, Python 3.11+ và `uv`:

```bash
git submodule update --init --recursive
UV_PROJECT_ENVIRONMENT=.venv-wsl uv sync --extra dev
.venv-wsl/bin/python -m pytest -q
```

## Artifact và cách tái lập

- Raw/normalized OpenGrep r2: `artifacts/scans/` và `artifacts/normalized/`.
- Machine reference r20: `artifacts/llm-review/opengrep-representative-openai-luna-r20-20260814/`;
  cần giữ lineage r7, r9 và r19 để validator kiểm chứng provenance.
- Dataset/manifest: `data/enriched/opengrep-machine-reviewed-r1.jsonl` và
  `data/releases/opengrep-machine-reviewed-r1-20260814.json`.
- Quyết định công bố:
  `data/releases/opengrep-machine-reference-publication-r1-20260814.json`.
- Split, prediction và frozen metrics:
  `data/splits/opengrep-machine-benchmark-r1-20260814/`; raw baseline run nằm
  trong `artifacts/baselines/`.

Các lệnh dưới đây kiểm tra và tái tạo artifact dẫn xuất mà không gọi API:

```bash
bash scripts/opengrep_scan_wsl.sh build-security-rules
bash scripts/opengrep_scan_wsl.sh doctor
bash scripts/opengrep_scan_wsl.sh status

unset MACHINE_DIR BASE_MACHINE_DIR R20_MACHINE_DIR R19_MACHINE_DIR R18_MACHINE_DIR
bash scripts/opengrep_machine_review.sh status
bash scripts/opengrep_machine_dataset.sh build
bash scripts/opengrep_machine_dataset.sh evaluate
bash scripts/opengrep_machine_dataset.sh status
```

Gate r20 phải có A/B=400/400, C=112/112 và
`MACHINE_REFERENCE_READY_WITH_UNCERTAINTY`. Muốn chạy lại baseline LLM, dùng
action `snippet` hoặc `context`; runner chỉ retry case failed. Không đổi model,
prompt, split hoặc reference trong cùng release. Chi tiết provenance nằm trong
[runbook machine review](docs/opengrep-machine-review.md); tiến độ nằm tại
[TODO active](docs/todo). Điều kiện công bố nằm trong
[machine-reference publication policy](docs/machine-reference-publication-policy.md).

Các scan, dataset, cấu hình và script thực thi Semgrep/CodeQL cũ đã được loại
khỏi workspace; mặc định CLI hiện là OpenGrep security-only. Parser tương thích
định dạng Semgrep vẫn được giữ vì OpenGrep xuất định dạng này. Submodule
`rules/semgrep-rules` cũng phải giữ vì nó là nguồn rule được pin để build
ruleset security-only cho OpenGrep; đây không phải scanner Semgrep hay nguồn
nhãn.
