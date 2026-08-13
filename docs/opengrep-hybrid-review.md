# Quy trình review kết hợp cho 400 finding OpenGrep

Cập nhật: **13/08/2026**

## Trạng thái hiện tại

Gói bằng chứng đã sẵn sàng tại:

```text
artifacts/hybrid-review/opengrep-representative-r1-20260812/
├── blind-verifier-input.jsonl          # 400 đầu vào không có nhãn
├── evidence-packets.jsonl              # 400 gói đoạn mã đúng commit
├── human-gold-label.schema.json
├── human-gold-labels.template.jsonl
├── hybrid-review-manifest.json
└── README.md
```

Checksum của đầu vào 400 record là
`8f0e7bc6442d45516003b37992a35c46738ac66747c28004993bc95d1272b69f`.
Checksum của gói bằng chứng là
`cb04e8fcf259718160f18262ac1d93944633dea289067c072741cd8d6db84751`.

Đây là kết quả OpenGrep đã quét; quy trình không chạy lại Semgrep hoặc OpenGrep.
Để không làm thay đổi các release Semgrep v1 đã khóa checksum, trường scanner
tổng quát trong blind input dùng giá trị tương thích `other`; provenance của mỗi
record vẫn ghi rõ nguồn thật là `opengrep`.

## Cách làm dễ hiểu

1. Reviewer máy A đọc 400 finding và mã nguồn, sau đó đưa ra kết luận.
2. Reviewer máy B làm lại độc lập, không được xem kết quả của A.
3. Công cụ so sánh hai kết quả.
4. Con người chỉ tập trung vào các ca khó: hai máy không đồng ý, máy không chắc,
   bất kỳ ca nào máy cho là lỗ hổng thật và một mẫu kiểm tra ngẫu nhiên từ các ca
   hai máy cùng cho là cảnh báo sai.

Hai máy cùng kết luận với độ tin cậy cao chỉ tạo nhãn
`SILVER_CONSENSUS`. Nó giúp giảm việc thủ công nhưng **không phải nhãn vàng của
con người**.

## Chọn hai reviewer

Ba model phải khác nhau:

- `REVIEWER_A_MODEL`: reviewer thứ nhất;
- `REVIEWER_B_MODEL`: reviewer thứ hai;
- `EVALUATED_AGENT_MODEL`: agent mà project muốn đo chất lượng.

Không dùng chính agent đang được đo để tự làm đáp án. Nên dùng hai họ model hoặc
hai nhà cung cấp khác nhau; nếu hiện chỉ có Codex CLI thì ít nhất phải dùng hai
model khác nhau và ghi rõ đây là giới hạn của thí nghiệm.

Thiết lập biến môi trường, ví dụ bằng tên model thực sự được cấp cho tài khoản:

```bash
export REVIEWER_A_MODEL='<model-review-a>'
export REVIEWER_B_MODEL='<model-review-b>'
export EVALUATED_AGENT_MODEL='<model-agent-under-test>'
```

Script sẽ dừng nếu A và B trùng nhau hoặc một reviewer trùng agent đang đo.

## Chạy từng bước

Kiểm tra lại 400 đầu vào và 141 snapshot mà chưa gọi model:

```bash
bash scripts/opengrep_hybrid_review.sh validate
```

Chạy hai reviewer trong hai terminal riêng:

```bash
bash scripts/opengrep_hybrid_review.sh reviewer-a
bash scripts/opengrep_hybrid_review.sh reviewer-b
```

Theo dõi trên một dòng, cập nhật mỗi 5 giây:

```bash
watch -n 5 -d 'bash scripts/opengrep_hybrid_review.sh status'
```

Khi cả hai đã đủ 400 kết quả:

```bash
bash scripts/opengrep_hybrid_review.sh reconcile
```

Kết quả được tách thành:

- `consensus-high.jsonl`: mọi ca hai máy cùng kết luận, cùng độ tin cậy cao;
- `silver-consensus.jsonl`: ca đồng thuận FP chưa cần con người xem ngay;
- `needs-human-review.jsonl`: hàng đợi con người cần xử lý;
- `uncertain-or-novel.jsonl`: ca có ít nhất một reviewer chọn TP hoặc không chắc;
- `human-adjudication.template.jsonl`: mẫu nhãn chỉ dành cho hàng đợi con người;
- `hybrid-review-summary.json`: số lượng và chính sách công bố.

Mặc định công cụ lấy 15% ca đồng thuận FP vào hàng đợi để con người kiểm tra ngẫu
nhiên. Có thể đổi tỷ lệ nhưng phải ghi lại trong báo cáo:

```bash
HUMAN_AUDIT_FRACTION=0.20 bash scripts/opengrep_hybrid_review.sh reconcile
```

## Quy tắc công bố metrics

- Có đủ 400 nhãn thực sự do con người xác nhận: được tính metrics chính thức trên
  prevalence set.
- Chỉ có nhãn máy đồng thuận cộng một phần con người xem: chỉ gọi là
  **exploratory hybrid metrics**.
- Không đổi tên `silver-consensus.jsonl` thành `human-gold-labels.jsonl`.
- Chỉ dùng finding và provenance OpenGrep trong quy trình này; không bổ sung kết
  quả từ scanner SAST khác vào population hoặc metrics.
