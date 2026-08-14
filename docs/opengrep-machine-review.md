# OpenGrep machine reference r20

Cập nhật: 14/08/2026

## Phạm vi active

Release đang dùng:

```text
artifacts/llm-review/opengrep-representative-openai-luna-r20-20260814
```

Kết quả đã đóng băng:

- reviewer A `gemini-3.1-flash-lite`: 400/400, failed=0;
- reviewer B `gemini-3.5-flash-lite`: 400/400, failed=0;
- adjudicator C blind/final `gpt-5.6-luna`: 112/112, failed=0;
- machine reference: 400 record gồm 7 TP, 367 FP, 26 UNCERTAIN.

Đây là `LLM_ADJUDICATED_MACHINE_REFERENCE`, không phải human gold. Chỉ gọi
metric tạo từ artifact này là project-approved metrics against frozen
LLM-adjudicated reference labels. Chỉ số chính thức trong phạm vi project nhưng
không phải universal ground truth.

## Artifact tối thiểu được giữ

r20 vẫn cần ba ancestor để validator kiểm chứng toàn bộ lineage:

```text
artifacts/llm-review/
├── opengrep-representative-gemini-only-r7-20260814
├── opengrep-representative-openai-luna-r9-20260814
├── opengrep-representative-openai-luna-r19-20260814
└── opengrep-representative-openai-luna-r20-20260814
```

r7 giữ composite A/B, r9 giữ C blind composite và r19 giữ nguồn final được r20
phục hồi. Các release trung gian khác đã được loại sau khi thử cô lập và xác
nhận validator r20 không cần chúng.

Không xóa hoặc sửa ba ancestor này nếu chưa tạo release mới tự chứa đầy đủ
provenance.

## Kiểm tra trạng thái

Lệnh sau không gọi API:

```bash
unset MACHINE_DIR BASE_MACHINE_DIR R20_MACHINE_DIR R19_MACHINE_DIR R18_MACHINE_DIR
bash scripts/opengrep_machine_review.sh status
```

Kết quả quyết định hoàn tất là:

```text
reviewer_a: COMPLETE, success=400, failed=0
reviewer_b: COMPLETE, success=400, failed=0
adjudicator_blind: COMPLETE
adjudicator_final: COMPLETE
machine_reference: MACHINE_REFERENCE_READY_WITH_UNCERTAINTY
```

## Dataset và baseline

```bash
bash scripts/opengrep_machine_dataset.sh build
bash scripts/opengrep_machine_dataset.sh snippet
bash scripts/opengrep_machine_dataset.sh context
bash scripts/opengrep_machine_dataset.sh evaluate
bash scripts/opengrep_machine_dataset.sh status
```

`build`, `evaluate`, `status` không gọi LLM. `snippet` và `context` gọi exact
model mặc định `gpt-5.6-luna`; runner tái sử dụng case SUCCESS cùng identity và
chỉ retry failed.

Dataset active có 400 record. Benchmark cân bằng có train=6, validation=4,
test=4 và không overlap repository/finding. Không tune trên test=4 đã freeze.

## Quy tắc bắt buộc

- API key không được ghi vào source, config, artifact hoặc log.
- Không đổi tên machine reference thành human gold.
- UNCERTAIN không được tự chuyển thành FP.
- Link VulnGym chỉ sau khi verdict freeze; dùng `MACHINE_TP_LINKED` hoặc
  `MACHINE_TP_UNLINKED`, không tuyên bố `TP_NOVEL`.
- Human review là tùy chọn. Quyền công bố dựa trên các gate xác minh LLM độc lập
  tại [publication policy](machine-reference-publication-policy.md).
- Attestation áp dụng cho r20:
  `data/releases/opengrep-machine-reference-publication-r1-20260814.json`.
