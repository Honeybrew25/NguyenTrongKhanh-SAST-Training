# Semgrep Verifier Agent v1 — Quickstart

Tài liệu này mô tả quy trình chính thức để agent xác minh corpus Semgrep đã đóng
băng. Phạm vi v1 là **16 finding trên 9 source snapshot**, model được ghim là
`gpt-5.6-sol`, và mọi lần chạy chính thức dùng run directory mới:

`artifacts/verifier-runs/semgrep-agent-v1-20260806`

Corpus đầu vào:

`artifacts/verifier-corpora/semgrep-day2-v1-20260806/blind-verifier-input.jsonl`

Không đưa nhãn, kết quả đối sánh hoặc prediction cũ vào input của agent. Một
finding chưa được xác minh không được mặc định là false positive.

## Trước khi bắt đầu

Chạy các lệnh từ thư mục gốc của repository bằng PowerShell. Máy cần có `uv`,
Codex CLI và source snapshot tương ứng trong `worktrees`. Action `Run` còn yêu
cầu Codex CLI đã đăng nhập và tài khoản có quota khả dụng.

Wrapper v1 dự kiến có giao diện duy nhất:

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action <Doctor|Validate|Status|Run|Freeze|PrepareHumanReview|Evaluate>
```

Các đường dẫn corpus, model và run directory ở trên là cấu hình cố định của v1;
không đổi chúng giữa các action trong cùng một lượt đánh giá.

## Quickstart theo đúng thứ tự

### 0. Kiểm tra công cụ cục bộ

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Doctor
```

`Doctor` xác minh `uv`, Codex CLI, version và checksum binary đã ghim. Trạng thái
đăng nhập/quota vẫn được ghi là `UNVERIFIED_UNTIL_RUN`; kiểm tra cục bộ không thể
thay thế một request provider thật.

### 1. Kiểm tra corpus và source

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Validate
```

`Validate` không gọi provider. Action này phải xác nhận corpus hợp lệ, có đúng
16 record, 16 `finding_id` duy nhất và resolve được đúng 9 snapshot. Chỉ tiếp tục
khi kết quả là `VALID`.

### 2. Xem trạng thái hiện tại

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Status
```

`Status` chỉ đọc artifact và tiến trình liên quan; nó không tự chạy hoặc resume
agent. Trước lần chạy đầu, trạng thái hợp lệ có thể là chưa có case nào. Khi
resume, kiểm tra tổng số case `SUCCESS`, `FAILED`, `RUNNING` và chưa bắt đầu.

### 3. Chạy hoặc resume verifier chính thức

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Run
```

`Run` là action duy nhất gọi provider. Nó phải dùng toàn bộ 16 record, model
`gpt-5.6-sol` và run directory
`artifacts/verifier-runs/semgrep-agent-v1-20260806`. Không chạy subset, không
dùng chế độ development và không dùng `-Force` cho lượt đánh giá chính thức.

Nếu bị gián đoạn, chạy `Status`, xử lý blocker rồi gọi lại chính action `Run`.
Runner chỉ được tái sử dụng case `SUCCESS` khi toàn bộ identity và checksum khớp;
case lỗi hoặc dở dang phải được chạy lại.

### 4. Khóa prediction

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Freeze
```

`Freeze` chỉ thành công khi official run đã hoàn tất đủ 16/16 case, không có case
failed, model đã được ghim, mọi prediction có `evaluation_eligible: true`, và
checksum khớp manifest. Kết quả bắt buộc là:

`artifacts/verifier-runs/semgrep-agent-v1-20260806/prediction-freeze.json`

Nếu thiếu `verifier-run.json`, thiếu prediction hoặc còn case lỗi, action phải
dừng mà không tạo freeze.

### 5. Chuẩn bị gói thẩm định độc lập

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action PrepareHumanReview
```

Action này chỉ được chạy sau `Freeze`. Gói review không được chứa prediction của
agent. Người thẩm định hoàn tất đủ 16 nhãn mà không xem prediction, đồng thời ghi:

- `reviewer.kind` là `HUMAN` và có reviewer ID;
- timestamp có múi giờ;
- reasoning và ít nhất một evidence `file:dòng`;
- reason code cho `FP_CONFIRMED`;
- cả entry ID và report ID cho `TP_KNOWN`;
- `UNCERTAIN` khi bằng chứng chưa đủ.

Không khớp với dữ liệu tham chiếu không phải là bằng chứng để gán
`FP_CONFIRMED`.

### 6. Tính metric chính thức

```powershell
.\scripts\semgrep_verifier_agent_v1.ps1 -Action Evaluate
```

`Evaluate` chỉ được chạy sau khi prediction đã khóa và file human gold labels đã
hoàn tất. Action phải kiểm tra lại checksum prediction, tập `finding_id` của gold
label và prediction giống hệt nhau, reviewer là người thật và evidence đầy đủ.
Không dùng tùy chọn bỏ qua incomplete gold trong báo cáo chính thức.

Precision, recall, F1 và các chỉ số liên quan chỉ là kết quả chính thức khi
`Evaluate` vượt qua toàn bộ gate trên. `UNCERTAIN`, `DUPLICATE` và `OUT_OF_SCOPE`
được báo riêng, không bị đổi ngầm thành false positive.

## Khi trạng thái là `BLOCKED_PROVIDER`

`BLOCKED_PROVIDER` nghĩa là provider không thể tiếp tục vì vấn đề như hết quota,
phiên đăng nhập hết hiệu lực hoặc dịch vụ không khả dụng. Đây là lỗi hạ tầng,
không phải verdict của finding và không được đổi thành `ABSTAIN` hoặc
`FALSE_POSITIVE`.

Xử lý theo thứ tự:

1. Không chạy `Freeze`, `PrepareHumanReview` hoặc `Evaluate`.
2. Bảo đảm không còn tiến trình verifier/provider cũ đang chạy.
3. Khôi phục đăng nhập hoặc quota.
4. Chạy `Status` để kiểm tra lại checkpoint.
5. Chạy lại `Run` với đúng run directory v1 để resume.
6. Chỉ tiếp tục khi run báo hoàn tất 16/16 case `SUCCESS`.

Không xóa case thành công, không ghép prediction từ run khác và không tạo metric
tạm như thể đó là kết quả chính thức.

## Thứ tự fail-closed

```text
Validate
   ↓ VALID: 16 record / 9 snapshot
Status
   ↓ không có tiến trình trùng hoặc blocker chưa xử lý
Run
   ↓ COMPLETE: 16/16 SUCCESS
Freeze
   ↓ prediction checksum đã khóa
PrepareHumanReview
   ↓ 16 human gold label độc lập, có evidence
Evaluate
   ↓ metric chính thức
```

Mỗi action chỉ mở khóa action kế tiếp khi artifact và checksum bắt buộc hợp lệ.
Nếu một gate thất bại, dừng tại đó, giữ nguyên bằng chứng và sửa nguyên nhân; không
bỏ qua gate để đi tiếp.

## Operational-ready và evaluation-ready

**Operational-ready** nghĩa là wrapper, corpus đóng băng, profile, schema và 9
snapshot đã sẵn sàng; `Validate` thành công và agent có thể bắt đầu khi provider
khả dụng. Trạng thái này chưa chứng minh agent đã xử lý đủ 16 finding và chưa cho
phép báo metric.

**Evaluation-ready** chỉ đạt được khi official run hoàn tất 16/16, prediction đã
được `Freeze`, và 16 human gold label độc lập đã hoàn tất với bằng chứng hợp lệ.
Chỉ ở trạng thái này mới được chạy `Evaluate` và công bố precision, recall hoặc
F1.
