# Báo cáo độc lập: agent xác minh 16 finding Semgrep v1

Ngày ghi nhận: 06/08/2026  
Phạm vi: chỉ tập finding Semgrep đã đóng băng

## 1. Mục đích

Semgrep tạo ra **finding**, tức là cảnh báo về đoạn code có dấu hiệu nguy hiểm.
Finding chưa phải kết luận rằng ứng dụng chắc chắn có lỗ hổng. Agent v1 được xây
dựng để đọc finding cùng source code tại đúng commit rồi đưa ra một trong ba kết
luận:

- `TRUE_POSITIVE`: bằng chứng source cho thấy có đường khai thác thực tế.
- `FALSE_POSITIVE`: source chứng minh một điều kiện cụ thể làm cảnh báo không thể
  khai thác theo threat model.
- `ABSTAIN`: chưa đủ bằng chứng để kết luận đúng hoặc sai.

Agent không được xem nhãn tham chiếu, thông tin đối sánh VulnGym, bản vá hoặc kết
quả thẩm định trước đó. Việc không tìm thấy đường khai thác cũng không tự động
biến finding thành false positive.

## 2. Corpus Semgrep-only đã cố định

Corpus hiện có **16 finding trên 9 source snapshot**, thuộc 6 repository. Mỗi
snapshot là source code tại một commit cụ thể. Toàn bộ 16 finding đều thuộc hàng
đợi `CANDIDATE_REVIEW`, nghĩa là cần xác minh thêm; đây chưa phải nhãn TP hoặc FP.

Thông tin tái lập chính:

- Scanner: Semgrep `1.171.0`.
- Ruleset commit: `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`.
- Corpus: `artifacts/verifier-corpora/semgrep-day2-v1-20260806/`.
- Blind input: `blind-verifier-input.jsonl`.
- Số record: 16.
- SHA-256 blind input:
  `c1ab3287b77fc43355f329f0f2812daa592a8c663561966775b6b85a88d53490`.
- SHA-256 corpus summary:
  `2cdd755b7f371d403fb647778ca48177157d30388ed2cf28252340343427c17f`.

Lệnh kiểm tra không gọi model đã xác nhận cả 16 record hợp lệ và tìm thấy đủ 9
snapshot sạch tại đúng commit. Corpus riêng chỉ chứa blind input và proof; nó
không chứa prediction cũ, nhãn kỹ thuật, nhãn con người hoặc metric.

## 3. Kiến trúc agent v1

Luồng xử lý của agent gồm năm lớp:

1. **Corpus gate** đọc blind input, từ chối khóa có thể làm lộ nhãn và xác minh
   source snapshot đúng commit.
2. **Controller** chỉ gửi cho model sáu nhóm dữ liệu kỹ thuật: scanner, rule,
   message, location, data-flow trace và snippet. Identity cùng provenance được
   giữ ngoài model.
3. **Source tools có giới hạn** cho phép model yêu cầu đọc một khoảng dòng, tìm
   chuỗi cố định hoặc liệt kê một thư mục. Model không được tự dùng shell, Git,
   web hay đọc trực tiếp filesystem của repository.
4. **Provider session cô lập** tạo một session mới cho từng finding. Response và
   event của provider phải đúng schema; direct tool call ngoài controller làm
   case thất bại.
5. **Evidence gate** chỉ chấp nhận kết luận có trích dẫn file và dòng đã được
   controller cung cấp. Prediction được gắn identity của profile, prompt,
   controller, schema, provider và model.

Mỗi finding có status, event, response và prediction riêng. Một case `SUCCESS`
chỉ được tái sử dụng khi identity và mọi checksum còn khớp. Lỗi hạ tầng phải là
`FAILED` hoặc `INTERRUPTED`, không được đổi thành `ABSTAIN`.

## 4. Trạng thái official-mode prototype hiện tại

Lần chạy thử official mode hiện được giữ tại:

`artifacts/verifier-runs/semgrep-day2-official-v1-20260806/`

Run ghim model `gpt-5.6-sol`. Tại checkpoint đã kiểm tra:

- 16 case dự kiến;
- 1 case `SUCCESS`;
- 3 case `FAILED`;
- 1 marker `RUNNING` cũ do tiến trình bị ngắt;
- 11 case chưa bắt đầu;
- không còn verifier hoặc provider process đang chạy.

Case thành công duy nhất có checksum đúng, prediction đúng schema,
`evaluation_eligible:true` và identity model khớp. Tuy nhiên một prediction đơn
lẻ không đại diện cho cả corpus.

Provider gặp hai blocker độc lập:

1. tài khoản đã hết usage quota; provider báo thời điểm có thể thử lại là
   12/08/2026 lúc 19:55;
2. OAuth token bị thu hồi và request trả `401 token_revoked`, vì vậy cần đăng
   nhập lại.

`codex login status` có thể vẫn hiển thị đã đăng nhập dù request thực tế bị từ
chối. Do đó trạng thái đăng nhập cục bộ không đủ để chứng minh provider đã sẵn
sàng.

Run bị ngắt trước khi tạo `verifier-run.json` tổng hợp và
`verifier-predictions.jsonl` hoàn chỉnh. Vì vậy không được khóa prediction, không
được chuyển sang human review và không được dùng output này để đánh giá.

## 5. Không trộn prototype với release v1

Thư mục `semgrep-day2-official-v1-20260806` là **bằng chứng prototype bị gián
đoạn**. Phải giữ nguyên nó cho mục đích kiểm toán.

Agent đã được gia cố thêm lock, circuit breaker, run state, attempt history và
redaction. Vì checksum controller đã thay đổi, prototype trên được giữ nguyên và
**không resume**. Release sử dụng run directory sạch:

`artifacts/verifier-runs/semgrep-agent-v1-20260806/`

Không sao chép `cases/`, prediction, status, event log hoặc manifest của
prototype sang release v1. Corpus blind vẫn được dùng lại vì checksum không thay
đổi, nhưng toàn bộ prediction chính thức phải được tạo mới dưới identity v1.

Entry point và release identity:

- `scripts/semgrep_verifier_agent_v1.ps1`;
- `config/semgrep-verifier-agent-v1.json`;
- `docs/semgrep-verifier-agent-v1.md`.

## 6. Acceptance gates trước khi gọi agent là “usable”

### Gate A — Corpus hợp lệ

- Đúng 16 finding và 16 finding ID duy nhất.
- Đúng 9 snapshot, tất cả sạch và ở đúng commit.
- Blind input đúng schema và không chứa metadata làm lộ nhãn.
- Hash input, source pipeline và corpus summary khớp proof đã đóng băng.
- Corpus directory không chứa prediction hoặc nhãn.

Trạng thái hiện tại: **đạt**.

### Gate B — Provider sẵn sàng

- Codex CLI có version và binary identity cố định.
- Model được ghi rõ, không dùng model mặc định ẩn.
- Authentication thực sự hợp lệ.
- Tài khoản còn quota hoặc credit cho toàn bộ run.
- Preflight thất bại phải dừng trước khi tạo case mới.

Trạng thái hiện tại: **chưa đạt** do quota và OAuth.

### Gate C — Chạy an toàn và resume được

- Chỉ một process được ghi vào một run directory; process thứ hai phải nhận
  `BUSY`.
- Run state được ghi atomically trước case đầu tiên và sau mỗi thay đổi.
- Auth/quota terminal làm circuit breaker mở ngay, không tiếp tục làm hỏng các
  case kế tiếp.
- `Ctrl+C` hoặc timeout phải để lại `INTERRUPTED`, không để marker `RUNNING` mồ
  côi.
- Resume cùng identity được reuse `SUCCESS`; identity khác phải bị từ chối trước
  mọi thay đổi.
- Mỗi lần retry tạo attempt mới và giữ nguyên log/checksum attempt cũ.
- Status công bố chỉ chứa mã lỗi và thông báo đã redaction; không lưu token,
  cookie hoặc opaque credential data.

Trạng thái phần mềm hiện tại: **đạt**. Mười một kiểm thử lifecycle v1 bao phủ
classification/redaction lỗi provider, immutable run identity, atomic run state,
singleton lock, circuit breaker và lưu attempt cũ khi retry. Run chính thức vẫn
chưa bắt đầu vì Gate B đang bị chặn bên ngoài.

### Gate D — Output hoàn chỉnh

- Đúng 16/16 case `SUCCESS`.
- Không còn `FAILED`, `RUNNING`, `INTERRUPTED` hoặc case chưa bắt đầu.
- Có `verifier-run.json` hợp lệ và khai báo `complete:true`.
- Có đúng 16 prediction, finding ID khớp chính xác blind input.
- Mỗi prediction đúng schema và có `evaluation_eligible:true`.
- Checksum input, prediction, profile, prompt, schema, controller, provider và
  model đều khớp manifest.

Trạng thái hiện tại: **chưa đạt**.

### Gate E — Khóa prediction

- Chỉ khóa sau khi Gate D đạt.
- `prediction-freeze.json` phải cam kết checksum của manifest, input và toàn bộ
  prediction.
- Mọi thay đổi sau freeze phải bị phát hiện và làm pipeline dừng.

Trạng thái hiện tại: **chưa được phép thực hiện**.

### Gate F — Human review độc lập

- Chỉ tạo gói thẩm định sau khi prediction đã khóa.
- Người thẩm định không xem prediction trước khi hoàn tất nhãn.
- Mọi nhãn phải có reviewer thật, timestamp, lý do và evidence `file:dòng`.
- `FP_CONFIRMED` phải có reason code; không khớp VulnGym không phải bằng chứng
  false positive.
- Trường hợp thiếu bằng chứng phải dùng `UNCERTAIN`, không ép thành TP hoặc FP.

Trạng thái hiện tại: **chưa bắt đầu**; chưa có human gold label hợp lệ.

## 7. Điều kiện hoàn thành thực tế

Release hiện **sẵn sàng vận hành cục bộ**: `Doctor`, `Validate` và `Status` dùng
được; corpus và guard lifecycle đã đạt. Action `Run` chỉ sử dụng được sau khi
provider vượt Gate B. Kết quả chỉ được gọi là **evaluation-usable** khi tiếp tục
đạt Gate D, E và F.

Việc tiếp theo theo đúng thứ tự là:

1. khôi phục authentication và quota provider;
2. chạy `Run` trong run directory v1 sạch và hoàn tất 16/16 case;
3. xác minh output và khóa prediction;
4. giao gói source-only cho người thẩm định độc lập;
5. chỉ đánh giá sau khi human gold đã hoàn tất và được khóa.

## 8. Trạng thái metric

Hiện **không công bố precision, recall, F1 hoặc bất kỳ metric đánh giá agent
nào**. Lý do là official run chưa hoàn tất, prediction chưa được khóa và chưa có
human gold label độc lập. Mọi con số sinh từ prediction cũ, technical review hoặc
nhãn chưa hoàn tất đều không phải kết quả chính thức của agent v1.
