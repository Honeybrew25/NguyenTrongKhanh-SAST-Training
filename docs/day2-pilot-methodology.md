# Phương pháp pilot ngày 2

## Phạm vi cố định

- Dataset: Tencent VulnGym `v0.1.4`, commit `cd69f7e163e08485ab5496115ae03439cda6e27e`.
- Snapshot Python: `https://github.com/nltk/nltk` tại commit `40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e`.
- Snapshot TypeScript: `https://github.com/modelcontextprotocol/typescript-sdk` tại commit `50d9fa3cd12e807e7963bcb9e1548786d3d5d941`.
- Snapshot Go/JavaScript/TypeScript: `https://github.com/ollama/ollama` tại commit `7325791599409de52534429897481918717a9e85`.
- Semgrep `1.171.0`, OpenGrep `1.26.0`.
- Rule: `semgrep/semgrep-rules` tại commit `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`.
- Hai engine dùng cùng các thư mục rule được route theo ngôn ngữ. Semgrep chạy OSS, tắt metrics; OpenGrep bật taint intrafile. Cả hai xuất JSON và SARIF có yêu cầu dataflow trace.

Pilot này kiểm tra tính đúng đắn của pipeline trên ba snapshot, không phải phép đo đại diện cho toàn bộ 166 snapshot. Sáu job cuối đều lưu bản sao byte-for-byte của manifest, scanner lock và scan profile trong attempt.

Khi mở rộng sang full batch, target-list preflight trên LiteLLM phát hiện Semgrep 1.171.0 lỗi parser với exclude glob `**/dist/**`. Pattern tương đương `dist` chọn thành công cùng tập target cần loại và được cố định trong profile full batch. Profile vẫn ưu tiên `.gitignore`; chỉ khi scanner báo đúng lỗi parser ignore, runner mới retry trên clean snapshot bằng `--no-git-ignore` và lưu riêng argv/log của lần đầu cùng cờ fallback trong status.

## Kết quả đo của pilot

- Sáu job scanner đều `SUCCESS`, tổng thời gian job là 77,765 giây; raw output có 1.306 finding và 12 cảnh báo partial parsing.
- Lọc security còn 608 raw observation. Dedup tạo 308 canonical cluster: 296 cluster có quan sát từ cả hai engine, 11 singleton và 1 cluster exact-duplicate.
- Semgrep OSS không xuất security trace. OpenGrep xuất 46 security trace, gồm 165 node.
- Cả 308 cluster đều `UNMATCHED` khi đối chiếu với 393 entry VulnGym đã xác minh. Chính sách của pipeline giữ chúng ở trạng thái chưa có nhãn.
- Điều tra 12 cảnh báo cho thấy 11 cảnh báo Semgrep/Go đến từ cú pháp generics/type-set hợp lệ và một cảnh báo OpenGrep/TypeScript đến từ `unique symbol`. Cả 12 file đều được engine còn lại scan sạch; số parser gap đồng thời ở cả hai engine trong pilot là 0. Đây là backstop cú pháp, không phải bằng chứng hai engine có semantic coverage tương đương.

## Đơn vị và chính sách đối sánh

Mỗi raw observation được giữ nguyên. Các observation có cùng snapshot, file và bằng chứng ngữ nghĩa tương thích được gán chung một `canonical_finding_id`; thao tác này không xóa nguồn gốc từng scanner.

Đối sánh với VulnGym ưu tiên source và sink. `STRICT_SOURCE_SINK` yêu cầu vị trí source/sink chính xác; `STRONG_SOURCE_SINK` yêu cầu source và sink nằm trong dung sai dòng đã công bố, có trace source-to-sink và category/CWE tương thích. Sink-only hoặc source/category không đủ chỉ là ứng viên cần xem xét. Finding `UNMATCHED` luôn giữ trạng thái chưa có nhãn, không được suy ra là false positive.

## Mô hình đe dọa và cơ sở duyệt finding

Kẻ tấn công có thể điều khiển dữ liệu đi vào public library/API. Với hai finding NLTK, biến môi trường của tiến trình, binary cục bộ và filesystem cấu hình triển khai thuộc quyền kiểm soát của operator đáng tin cậy. Vì vậy, một đường dữ liệu chỉ bắt đầu từ biến môi trường chưa đủ chứng minh khả năng khai thác từ xa hoặc qua API.

Hai finding TypeScript được duyệt theo bằng chứng riêng: một regex chỉ nhận ba literal tại toàn bộ call site; finding còn lại đi vào thông điệp JSON-RPC chứ không có SQL/database sink. Nếu code hoặc bối cảnh triển khai thay đổi, các record phải được đánh giá lại; không được tái sử dụng nhãn một cách máy móc.

## Tiêu chí escalation sang CodeQL

Escalate một finding khi Semgrep và OpenGrep đều không cung cấp trace đủ để kiểm tra source-to-sink, hoặc khi việc xác minh cần dataflow liên tệp mà OpenGrep intrafile không thể biểu diễn. Quy trình CodeQL phải:

1. Cố định CodeQL CLI và query-pack bằng version/commit cùng checksum tương ứng.
2. Tạo database từ đúng repository và commit của finding.
3. Không đưa CVE/GHSA, entry VulnGym, fixed commit hoặc nhãn vào query hay verifier.
4. Lưu SARIF có `codeFlows` và đưa qua normalizer với scanner `codeql`.
5. Báo cáo CodeQL thành baseline riêng, vì query của CodeQL không tương đương bộ rule chung của Semgrep/OpenGrep.

Pilot chưa kích hoạt nhánh này: OpenGrep đã trả về 46 security trace và đủ bằng chứng cho bốn finding được duyệt. Vì CodeQL chưa được cài và chưa chạy, không có số liệu CodeQL nào được báo cáo.

## Giới hạn của số liệu ngày 2

Bốn finding được chọn vì có trace rõ và kết luận có thể kiểm chứng, nên đây là mẫu có chủ đích chứ không phải test set được lấy mẫu độc lập. Do đó chưa tính precision, recall hoặc F1 của verifier từ bốn nhãn này. Các chỉ số đó chỉ được tính sau khi khóa một tập đánh giá đại diện, ẩn nhãn khỏi verifier và xử lý đầy đủ prediction thiếu hoặc abstain.
