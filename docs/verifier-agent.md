# Agent xác minh finding

## Trách nhiệm

Agent chỉ trả lời finding có phải một lỗ hổng thực sự theo mô hình đe dọa đã công bố hay không:

- `TRUE_POSITIVE`: có attacker capability cụ thể, entry point reachable, tác động bảo mật và không có control hữu hiệu chặn khai thác.
- `FALSE_POSITIVE`: source chứng minh một điều kiện phủ định cụ thể; bắt buộc có reason code và bằng chứng.
- `ABSTAIN`: bằng chứng source còn thiếu, phụ thuộc implementation bên ngoài hoặc giả định quan trọng chưa thể giải quyết.

Agent không dự đoán `TP_KNOWN` hay `TP_NOVEL`; việc liên kết VulnGym chỉ thuộc pha human gold sau khi prediction đã đóng băng. Không tìm thấy exploitation path không đủ để kết luận false positive.

## Ranh giới chống rò nhãn

Runner từ chối input chứa label, adjudication, match tier, VulnGym match, entry/report ID, CVE/GHSA, fixed commit hoặc patch, kể cả khi khóa bị đổi sang camelCase/kebab-case hoặc nằm sâu trong metadata. Model chỉ nhận projection có giới hạn gồm `scanner`, `rule`, `message`, `location`, `dataflow_trace`, `snippet`; finding ID, repository, commit, fingerprint, member ID và provenance chỉ nằm ở controller. Context source do controller trích từ snapshot đã xác minh đúng commit. Model chạy trong session tạm, không có source filesystem; event log dùng allowlist fail-closed nên mọi shell/web/MCP tool call hoặc event lạ đều làm case thất bại.

Controller chỉ cho phép:

1. `read_file`: đọc khoảng dòng repo-relative với giới hạn.
2. `search_code`: tìm fixed string bằng `rg`, giới hạn kết quả và timeout.
3. `list_directory`: liệt kê một thư mục, không đi qua symlink.

Mọi đường dẫn tuyệt đối, `..`, `.git`, symlink hoặc đường dẫn thoát snapshot đều bị từ chối. CVE/GHSA tình cờ xuất hiện trong source context được redaction mà không đổi số dòng. Evidence cuối phải nằm hoàn toàn trong khoảng source model đã được xem; controller tự đọc lại và đóng băng code excerpt.

Source comment, scanner message và tên file được coi là dữ liệu không tin cậy, không phải instruction.

## Tính tái lập và resume

`config/verifier-profile-v1.json`, `config/verifier-prompt-v1.md`, blind input, response schema, prediction schema, controller và predictions đều được ghi SHA-256 trong `verifier-run.json`. Mỗi finding có thư mục case riêng chứa status, response và event log từng bước. Chỉ case `SUCCESS` có đủ identity, checksum và schema hợp lệ mới được resume. Prediction đã bị sửa làm resume dừng fail-closed để điều tra; chỉ dùng `--force` sau khi xác định rõ nguyên nhân. Lỗi provider, timeout, source mismatch hoặc protocol violation là `FAILED` và không sinh prediction.

Run chính thức bắt buộc ghim model bằng `--model`, cấm lọc subset bằng `--finding-id`, và bắt buộc `summary.json` tồn tại với `complete:true`, record count, tên input và SHA-256 khớp chính xác. Input thiếu proof hoặc còn partial chỉ được chạy với `--development-run`; prediction khi đó có `evaluation_eligible:false` và exclusion reason rõ ràng. Token usage do provider báo được cộng theo case và toàn run.

`evaluation_eligible` do runner đặt, model không được tự loại case khỏi metric. Chỉ một `ABSTAIN` do model chủ động sau khi xem bằng chứng mới được tính là abstention; lỗi hạ tầng được báo là missing prediction cho đến khi retry thành công.

## Trình tự đánh giá

1. Hoàn tất scanner/postprocess và đóng băng blind input.
2. Chạy agent trong run directory mới; yêu cầu `verifier-run.json` có `complete: true`.
3. Đóng băng predictions và checksum trước khi mở metadata matcher/gold.
4. Người thẩm định độc lập dùng cùng threat model, không xem prediction trước khi khóa label.
5. Chạy evaluator trên exact finding ID. `UNCERTAIN`, `DUPLICATE`, `OUT_OF_SCOPE` được báo riêng, không đổi thành false positive.

Queue CodeQL có `complete: false` chỉ dùng cho smoke/development. Không báo precision, recall hoặc F1 chính thức từ queue thay đổi trong lúc batch đang chạy.
