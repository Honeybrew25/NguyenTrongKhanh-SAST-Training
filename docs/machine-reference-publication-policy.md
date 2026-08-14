# Chính sách công bố machine reference

Cập nhật: 14/08/2026

## Quyết định

Project không bắt buộc human review để công bố chỉ số. Nhãn do model tạo được
chấp nhận làm nhãn tham chiếu chính thức trong phạm vi project khi quy trình xác
minh độc lập bên dưới vượt qua đầy đủ các gate.

Tên công bố phải là **project-approved metrics against frozen LLM-adjudicated
reference labels**. Không được gọi kết quả là `human gold`, `human verified`,
universal ground truth hoặc bằng chứng rằng một finding là lỗ hổng mới.

## Gate bắt buộc

1. Scanner tạo candidate phải khác với model tạo nhãn.
2. Reviewer A và B dùng exact model ID khác nhau, chạy mù độc lập và không xem
   prediction của agent được đánh giá.
3. Adjudicator C tự đưa ra nhận định mù trước khi xem kết quả A/B; C xử lý mọi
   bất đồng, TP, ABSTAIN, bằng chứng không hợp lệ và mẫu audit FP đã xác định
   trước.
4. Mọi kết luận phải có bằng chứng source-backed; lỗi schema/evidence không được
   tự chuyển thành FP.
5. `UNCERTAIN` được giữ riêng và loại khỏi confusion matrix chính.
6. Verdict phải được khóa trước khi đối sánh với VulnGym; unmatched không được
   tự động coi là FP hoặc lỗ hổng mới.
7. Model, prompt, schema, checksum, raw response, retry và provenance phải được
   đóng băng; evaluator phải fail-closed khi checksum sai.
8. Train/validation/test phải chia theo repository hoặc advisory và không rò rỉ
   dữ liệu.
9. Báo cáo phải nêu rõ giới hạn về cỡ mẫu, sai số tương quan giữa model và phạm
   vi áp dụng của chỉ số.

Human review vẫn có thể dùng như một lớp audit bổ sung nhưng là tùy chọn, không
phải điều kiện xuất bản.

## Áp dụng cho r20

Release r20 đáp ứng gate vận hành với Gemini A/B 400/400, GPT-5.6 Luna C
112/112, 26 `MACHINE_UNCERTAIN`, provenance/checksum đã khóa và split theo
repository không overlap. Vì vậy r20 được phép công bố ở cấp
`PROJECT_APPROVED_MACHINE_REFERENCE` theo attestation:

`data/releases/opengrep-machine-reference-publication-r1-20260814.json`

Các trường `publish_as_official=false` nằm trong artifact r20 được giữ nguyên vì
đó là policy lịch sử đã đóng băng tại thời điểm tạo release. Attestation mới
thay đổi quyền công bố, không sửa ngược checksum hoặc nội dung artifact cũ.

