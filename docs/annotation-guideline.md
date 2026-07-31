# Hướng dẫn chú thích phát hiện

## Đơn vị chú thích

Một phát hiện đã chuẩn hóa của trình quét tại đúng một ảnh chụp `(repo_url, commit)`. Các kết quả trùng lặp do trình quét tạo ra được gom nhóm nhưng vẫn giữ lại đầy đủ thông tin nguồn gốc từ mọi công cụ.

## Các nhãn

- `TP_KNOWN`: lỗ hổng có thể bị khai thác và được liên kết với một cảnh báo bảo mật trong VulnGym.
- `TP_NOVEL`: lỗ hổng có thể bị khai thác nhưng chưa có trong VulnGym.
- `FP_CONFIRMED`: lỗ hổng được nêu không thể bị khai thác theo mô hình đe dọa đã công bố.
- `UNCERTAIN`: bằng chứng chưa đầy đủ hoặc những người đánh giá không đồng thuận.
- `DUPLICATE`: trùng lặp với một ứng viên chuẩn khác.
- `OUT_OF_SCOPE`: mã được sinh tự động, mã của nhà cung cấp, mã chỉ dùng cho kiểm thử hoặc một phát hiện không liên quan đến bảo mật bị loại theo chính sách.

Chỉ `TP_KNOWN`, `TP_NOVEL` và `FP_CONFIRMED` được đưa vào ma trận nhầm lẫn chính. Các trạng thái còn lại được báo cáo riêng.

## Lối tắt bị nghiêm cấm

Một phát hiện của trình quét không khớp với mục nào trong VulnGym **không mặc nhiên là kết quả dương tính giả**. VulnGym không tuyên bố bao phủ toàn bộ lỗ hổng của từng kho lưu trữ.

## Bằng chứng bắt buộc

Mỗi bản ghi đã được thẩm định phải bao gồm:

1. Kho lưu trữ và commit chính xác.
2. Trình quét, phiên bản trình quét, commit của bộ quy tắc và ID quy tắc.
3. Vị trí phát hiện và dấu vết nguồn/đích liên quan nếu có.
4. Lập luận ngắn gọn kèm tham chiếu đến tệp và dòng tương đối so với gốc kho lưu trữ.
5. Danh tính hoặc bí danh ổn định của người chú thích, cùng dấu thời gian.
6. Đối với `FP_CONFIRMED`, ít nhất một mã lý do.
7. Đối với `TP_KNOWN`, ID mục/báo cáo VulnGym được liên kết trong phần siêu dữ liệu chỉ chứa nhãn và được ẩn khỏi bộ xác minh.

## Mã lý do cho kết quả dương tính giả

- `UNREACHABLE_CODE`
- `NO_ATTACKER_CONTROL`
- `SANITIZED_BEFORE_SINK`
- `CONSTANT_VALUE`
- `AUTHZ_PRECONDITION_BLOCKS_ATTACK`
- `SAFE_API_USAGE`
- `TYPE_OR_SCHEMA_CONSTRAINT`
- `TEST_OR_FIXTURE_ONLY`
- `DEAD_OR_UNUSED_PATH`
- `FRAMEWORK_GUARANTEE`
- `SCANNER_MODELING_ERROR`
- `OTHER_EXPLAINED`

## Quy trình đánh giá

1. Chuẩn hóa và loại bỏ kết quả trùng lặp trong đầu ra của trình quét.
2. Thử đối sánh nghiêm ngặt hoặc có độ tin cậy cao với các mục VulnGym đã biết.
3. Thực hiện phân loại sơ bộ với sự hỗ trợ của tác nhân mà không cung cấp nhãn, nội dung cảnh báo bảo mật, quyền truy cập web hoặc bản vá đã sửa lỗi.
4. Yêu cầu con người đánh giá mọi lỗ hổng mới có khả năng tồn tại, các trường hợp chưa chắc chắn và tập kiểm thử được niêm phong.
5. Giải quyết bất đồng bằng một người thẩm định độc lập.
6. Không đưa `UNCERTAIN` vào các chỉ số precision/recall/F1 chính.

## Kiểm soát rò rỉ

Bộ xác minh chỉ nhận ảnh chụp kho lưu trữ có lỗ hổng và cảnh báo đã chuẩn hóa của trình quét. Bộ xác minh không được nhận ID CVE/GHSA, tiêu đề/dấu vết VulnGym, commit đã sửa lỗi, bản vá, nhãn hoặc quyền truy cập web.

## Mô hình đe dọa

Một kết quả dương tính thật đòi hỏi kẻ tấn công phải có năng lực cụ thể, có một điểm vào có thể tiếp cận, có thao tác gây ảnh hưởng đến bảo mật và không có biện pháp kiểm soát ngăn chặn hữu hiệu. Việc mã nguồn chỉ chứa một API nguy hiểm hoặc cú pháp đáng ngờ là chưa đủ.
