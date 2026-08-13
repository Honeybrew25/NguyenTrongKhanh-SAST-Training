# Đánh giá độ phủ tập 400 finding OpenGrep

Cập nhật: **13/08/2026**

## Kết luận

Tập 400 finding **phù hợp để ước lượng tỷ lệ TP/FP chung của toàn bộ population
OpenGrep**, vì được chọn với xác suất đều, seed cố định và giữ phân bố rất gần
112.739 canonical cluster.

Tập này **chưa đủ nếu dùng một mình làm benchmark agent đa dạng hoặc để báo cáo
theo từng repository/rule/CWE**. Nó phản ánh đúng population đang bị OpenClaw và
một số rule JavaScript chi phối, nên nhiều nhóm hiếm không xuất hiện.

Hiện tập 400 **chưa thể dùng để công bố metrics chính thức** vì chưa có file nhãn
con người độc lập `human-gold-labels.jsonl`. Gói bằng chứng và quy trình hai LLM
kết hợp human audit đã được chuẩn bị; xem `docs/opengrep-hybrid-review.md`.

## Số liệu độ phủ

| Tiêu chí | Population | Mẫu 400 | Độ phủ |
|---|---:|---:|---:|
| Canonical clusters | 112.739 | 400 | 0,355% |
| Repository | 23 | 16 | 69,57% |
| Rule | 129 | 37 | 28,68% |
| Ngôn ngữ/phần mở rộng | 14 | 8 | 57,14% |
| CWE | 49 | 22 | 44,90% |
| Có dataflow trace | 15.869 — 14,08% | 59 — 14,75% | Gần population |

Các phân bố lớn được giữ sát:

- OpenClaw chiếm 327/400, tương đương **81,75%** mẫu; population khoảng 81,79%.
- Rule `javascript.jquery.security.audit.prohibit-jquery-html` chiếm 163/400,
  tương đương **40,75%** mẫu; population khoảng 40,72%.
- Severity gồm 76 `ERROR`, 313 `WARNING` và 11 `INFO`.
- 400 `finding_id` và 400 `canonical_finding_id` đều duy nhất; toàn bộ record là
  OpenGrep.

Phương pháp lấy mẫu là equal-probability systematic sampling với implicit
stratification. Xác suất một cluster được chọn là 0,003548; trọng số mỗi record
là 281,8475. Sai số lấy mẫu 95% xấu nhất cho một tỷ lệ nhị phân khoảng
**±4,89 điểm phần trăm**. Sai số này không bao gồm lỗi gán nhãn hoặc thiên lệch
của scanner/ruleset.

## Mức đáp ứng yêu cầu

| Mục tiêu | Đánh giá |
|---|---|
| Ước lượng precision/FP rate toàn cục của OpenGrep | **Đạt sau khi đủ 400 nhãn độc lập** |
| Phản ánh tỷ trọng noise thực tế | **Đạt** |
| Tái lập và kiểm toán mẫu | **Đạt** — có seed và SHA-256 |
| Đánh giá riêng mọi repository/rule/CWE | **Chưa đạt** |
| Tạo train/validation/test chống rò rỉ | **Chưa đạt** |
| Benchmark agent cân bằng TP/FP | **Chưa đạt** |
| Công bố Precision/Recall/F1 | **Chưa đạt** — nhãn còn trống |

## Cách sử dụng phù hợp

1. Giữ nguyên tập 400 làm **prevalence set** để đo tỷ lệ TP/FP thực tế của
   OpenGrep; không thay đổi mẫu hoặc chọn lại sau khi biết nhãn.
2. Trước mắt dùng hai LLM độc lập để chuẩn bị kết luận; con người xem mọi ca bất
   đồng/không chắc/TP và kiểm tra ngẫu nhiên 15% ca đồng thuận FP. Kết quả này chỉ
   là exploratory. Muốn công bố metrics chính thức cho toàn bộ prevalence set,
   con người vẫn phải xác nhận đủ 400 nhãn.
3. Để đánh giá agent, tạo thêm một **balanced verifier set** có chủ đích phủ các
   repository, rule, CWE, ngôn ngữ và dataflow hiếm; không dùng tập bổ sung này
   để ước lượng prevalence nếu không áp dụng trọng số lấy mẫu phù hợp.
4. Chia verifier set theo repository hoặc advisory, không chia ngẫu nhiên theo
   finding, rồi mới chạy các baseline và agent.

## Artifact nguồn

```text
artifacts/human-review/opengrep-representative-r1-20260812/
├── sample-manifest.json
├── sampled-findings.jsonl
├── sampling-index.jsonl
├── human-gold-labels.template.jsonl
└── human-gold-label.schema.json
```

Trạng thái manifest: `SAMPLED_AWAITING_HUMAN_LABELS`.

SHA-256 của `sampled-findings.jsonl`:
`ee9d76e58ec97f08759be250eb6817c9682ae8b7d2cdd058ef13a79bf8f96194`.
