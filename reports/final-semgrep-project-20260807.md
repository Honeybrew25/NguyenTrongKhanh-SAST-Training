# Báo cáo tổng kết project Semgrep Verifier

## 1. Phạm vi

Project dùng Semgrep `1.171.0` quét các source snapshot của Tencent VulnGym,
chuẩn hóa finding và đưa 16 candidate trên 9 snapshot vào một agent xác minh.
Mỗi candidate vẫn là cảnh báo cần thẩm định; việc không khớp VulnGym không tự
động biến nó thành false positive.

Release đánh giá là `semgrep-verifier-agent-v5`. Corpus, scanner, rule commit,
source commit, prompt, response schema và model đều được ghim trong release
manifest để có thể tái lập.

## 2. Dataset sau làm giàu

Gold labels của 16 candidate gồm:

- 14 `TP_KNOWN`;
- 1 `FP_CONFIRMED` có lý do và bằng chứng source;
- 1 `UNCERTAIN` do chưa đủ source để chứng minh hoặc phủ định khả năng khai thác.

Chỉ FP đã xác nhận được thêm vào
`data/enriched/day2-semgrep-reviewed.jsonl`. Case `UNCERTAIN` được giữ riêng,
không bị suy diễn thành FP. Dataset làm giàu hiện có 1 record Semgrep FP.

## 3. Agent và quy trình đánh giá

Agent đọc source đúng commit và trả `TRUE_POSITIVE`, `FALSE_POSITIVE` hoặc
`ABSTAIN`. Controller kiểm tra schema, citation và source exposure. Cả 16 case
đã chạy thành công; prediction sau đó được khóa trước khi evaluator ghép với
gold labels.

Gói review chứa candidate, source metadata và candidate matches nhưng không
chứa nội dung prediction. Evaluator từ chối nhãn thiếu reviewer, timestamp,
reasoning, evidence hoặc liên kết VulnGym bắt buộc.

## 4. Kết quả đã đo

Một nhãn `UNCERTAIN` bị loại khỏi ma trận chính. Trong 15 case còn lại, agent
đưa ra quyết định trên 9 case và abstain 6 case.

| Chỉ số | Giá trị |
|---|---:|
| TP | 3 |
| FP | 0 |
| TN | 1 |
| FN | 5 |
| Precision | 1,0000 |
| Recall | 0,3750 |
| F1 | 0,5455 |
| Specificity | 1,0000 |
| Accuracy trên case đã quyết định | 0,4444 |
| Selective coverage | 0,6000 |
| Abstain trên nhãn thật | 6 |

Precision 1,0000 nghĩa là trong tập này không có case agent xác nhận TP nhưng
gold label là FP. Recall 0,3750 nghĩa là agent chỉ giữ lại 3 trong 8 TP thuộc
nhóm đã đưa ra quyết định. Nếu tính cả abstain, agent chỉ xác nhận 3 trong tổng
14 TP; đây là nguyên nhân `tp_retention` end-to-end chỉ đạt 0,2143.

## 5. Kết luận và hạn chế

Project đã hoàn thành bốn yêu cầu: khảo sát VulnGym, làm giàu dataset bằng FP có
bằng chứng, xây dựng agent xác minh và đo precision/recall/F1. Release v5 hoạt
động ổn định, không còn job lỗi và loại đúng FP duy nhất trong corpus.

Kết quả chưa chứng minh khả năng tổng quát vì corpus chỉ có 16 finding và một
FP. Agent còn quá thận trọng: 6 abstain và 5 false negative. Release sau nên tập
trung phân tích các TP bị bỏ lỡ, nhưng phải dùng corpus/prediction freeze mới;
không sửa ngược kết quả v5.

Kết quả máy đọc nằm tại
`artifacts/human-review/semgrep-agent-v5-20260807/metrics.json`.
