# Báo cáo độc lập: Semgrep Verifier Agent v5

## Phạm vi

Agent đọc 16 Semgrep finding trên 9 source snapshot tại đúng commit. Finding là
cảnh báo cần kiểm tra, chưa phải kết luận có hoặc không có lỗ hổng. Agent chỉ
được dùng source do controller cung cấp và trả một trong ba verdict:

- `TRUE_POSITIVE`: source chứng minh đường khai thác theo threat model;
- `FALSE_POSITIVE`: source chứng minh điều kiện cụ thể phủ định cảnh báo;
- `ABSTAIN`: chưa đủ bằng chứng để kết luận.

Agent không được xem nhãn tham chiếu, bản vá hay prediction cũ. Không khớp dữ
liệu tham chiếu không tự động trở thành false positive.

## Kết quả vận hành đã đo

- Release: `semgrep-verifier-agent-v5`.
- Scanner: Semgrep `1.171.0`.
- Model: `gpt-5.6-sol`.
- Official run: 16/16 `SUCCESS`, 0 failed, 0 running, 0 pending.
- Lượt đầu: 2.132,6 giây; retry một case: 192,3 giây; tổng thời gian hai lệnh:
  2.324,9 giây.
- Thời gian case thành công cuối cùng: nhỏ nhất 101,2 giây, lớn nhất 207,7 giây.
- Prediction đã được khóa; gói review chứa 16 record và không chứa nội dung
  prediction.
- Sau khi bỏ test của script batch đã loại khỏi project, bộ test còn 144 case:
  143 đạt và 1 skip do môi trường không hỗ trợ symlink;
  Ruff và `git diff --check` đều đạt.

Một case từng trả citation rộng hơn giới hạn. Controller v5 chia đúng phạm vi đó
thành các đoạn liên tiếp tối đa 25 dòng rồi kiểm tra từng đoạn đã được source
tool cung cấp. Một case khác cần attempt 2 vì citation đầu tiên chưa được expose.
Attempt lỗi được lưu riêng để kiểm toán và không tạo prediction hợp lệ.

## Kết quả đánh giá

Workflow đã đạt trạng thái **evaluation complete**. Evaluator chấp nhận 16
gold-label record: 14 `TP_KNOWN`, 1 `FP_CONFIRMED` và 1 `UNCERTAIN`. Case
`UNCERTAIN` được loại khỏi ma trận chính, nên còn 15 case có nhãn dùng đánh giá.

Agent đưa ra quyết định trên 9/15 case và abstain 6/15 case:

| Chỉ số | Kết quả |
|---|---:|
| TP / FP / TN / FN | 3 / 0 / 1 / 5 |
| Precision | 1,0000 |
| Recall | 0,3750 |
| F1 | 0,5455 |
| Specificity | 1,0000 |
| Accuracy trên case đã quyết định | 0,4444 |
| Selective coverage | 0,6000 |

Precision cao cho thấy các cảnh báo mà agent xác nhận là TP không tạo false
alarm trong tập nhỏ này. Recall thấp cho thấy agent bỏ sót 5 TP trong các case
đã quyết định; thêm 6 TP khác nhận `ABSTAIN`. Vì vậy kết quả quan trọng nhất của
v5 là tính thận trọng và khả năng loại đúng FP, chưa phải khả năng giữ lại đầy
đủ lỗ hổng.

Metrics máy đọc nằm tại
`artifacts/human-review/semgrep-agent-v5-20260807/metrics.json`. FP đã xác nhận
được lưu riêng trong `data/enriched/day2-semgrep-reviewed.jsonl`; case
`UNCERTAIN` không bị ép thành FP.
