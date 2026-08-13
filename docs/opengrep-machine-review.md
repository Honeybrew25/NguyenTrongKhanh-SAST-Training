# Quy trình machine reference Gemini-only cho 400 finding OpenGrep

Cập nhật: **13/08/2026**

## Phạm vi và giới hạn công bố

Đây là thay đổi methodology có chủ đích so với kế hoạch ban đầu yêu cầu một
người kiểm tra độc lập đủ 400 finding. Ba model Gemini khác nhau sẽ tạo một
`LLM_ADJUDICATED` machine reference; kết quả này **không phải human gold** và
không làm thỏa điều kiện công bố metrics chính thức của methodology cũ.

Nếu dùng machine reference để đánh giá, tên kết quả bắt buộc là:

> exploratory metrics against frozen LLM-adjudicated reference labels

Không được đổi tên `machine-reference-labels.jsonl` thành
`human-gold-labels.jsonl`, không dùng các từ `human verified`, `gold` hoặc
`official` cho các nhãn này. Nếu sau này cần metrics chính thức theo yêu cầu gốc,
vẫn phải thực hiện review độc lập bởi con người hoặc có phê duyệt thay đổi
methodology bằng văn bản.

Phạm vi dữ liệu vẫn là OpenGrep-only:

- 400 finding trong prevalence sample đã đóng băng;
- source tại đúng vulnerable commit;
- không import label, reasoning hoặc evidence từ Semgrep, CodeQL hay review
  Codex cũ;
- không cho reviewer xem prediction của agent đang được đánh giá, CVE/GHSA,
  patch hoặc ground truth VulnGym trước khi khóa verdict bảo mật.

Reviewer A/B và các case được route sang adjudicator C đều được gửi tới Gemini
API. Chỉ vận hành workflow bằng Google project đã được tổ chức phê duyệt cho
loại mã nguồn này.

## Thiết kế ba reviewer

Quy trình dùng ba model ID khác nhau:

- reviewer A và reviewer B review mù, độc lập toàn bộ 400 finding;
- adjudicator C tự review mù các finding được đưa vào hàng đợi và khóa verdict
  ban đầu;
- chỉ sau khi verdict mù của C đã được đóng băng, C mới được xem reasoning và
  evidence đã ẩn danh của A/B để chốt machine reference.

Cả ba model phải khác model của agent được đánh giá. A/B/C dùng Gemini API.
Script từ chối alias `latest`, model ID trùng hoặc seed trùng. Một Gemini
credential hợp lệ được yêu cầu cho mọi bước gọi model.

Hàng đợi cho C bao gồm:

- mọi bất đồng A/B;
- mọi finding có ít nhất một verdict `TRUE_POSITIVE` hoặc `ABSTAIN`;
- mọi confidence `LOW` hoặc `MEDIUM`;
- evidence không hợp lệ hoặc không đủ;
- một mẫu seed-fixed 20% từ nhóm A/B cùng `FALSE_POSITIVE` confidence `HIGH`.

Ngưỡng fail-closed được đăng ký trước là 10%: nếu hơn 10% mẫu FP đồng thuận bị C
đổi sang TP hoặc UNCERTAIN, workflow không phát hành machine reference. Khi đó
phải tạo release directory mới với `MACHINE_AUDIT_FRACTION=1` để C review toàn
bộ bucket FP đồng thuận; không sửa policy của release đã chạy.

Không ép model chọn TP hoặc FP. Thiếu bằng chứng phải giữ `UNCERTAIN` trong
machine reference. Một TP chỉ hợp lệ khi evidence chứng minh attacker control,
reachability, security effect và không có control hữu hiệu; một FP phải chỉ ra
điều kiện phủ định cụ thể.

## Chuẩn bị biến môi trường

Đồng bộ environment để có Google GenAI SDK cho C và JSON Schema validator:

```bash
uv sync --extra dev
uv pip install --python .venv-wsl/bin/python -r requirements-gemini.lock
```

Không cài runtime chính thức trực tiếp từ `requirements-gemini.in`; file lock là
nguồn phiên bản có thể tái lập và lệnh `uv pip install` thứ hai không gỡ các
dependency dev vừa đồng bộ. Checksum của chính file lock được ghi vào manifest
workflow.

## Cấu hình release Gemini-only

Release `r4` đã dừng do HTTP 429 sau 72 API call thành công ở A và 144 ở B.
Adapter cũ chỉ backoff 1/2 giây, đồng thời chưa retry hai lỗi ngữ nghĩa quan sát
được: citation nằm ngoài source đã expose và reason code FP đi cùng verdict
không phải FP. Hai lỗi này được sửa trong adapter mới; vì checksum implementation
đã đổi, không trộn output `r4` với release mới.

Tạo release `r5` với profile tối đa 5 controller step:

```bash
export MACHINE_DIR='artifacts/llm-review/opengrep-representative-gemini-only-r5-20260813'
export PROFILE='config/verifier-profile-v1.json'

export REVIEWER_A_PROVIDER='gemini-api'
export REVIEWER_A_MODEL='gemini-3.1-flash-lite'
export REVIEWER_A_THINKING='minimal'

export REVIEWER_B_PROVIDER='gemini-api'
export REVIEWER_B_MODEL='gemini-3.5-flash-lite'
export REVIEWER_B_THINKING='minimal'

export ADJUDICATOR_PROVIDER='gemini-api'
export ADJUDICATOR_MODEL='gemini-3.6-flash'
export ADJUDICATOR_THINKING='low'
export EVALUATED_AGENT_MODEL='gpt-5.6-sol'
export GEMINI_MIN_REQUEST_INTERVAL_SECONDS=4
export GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS=30
export GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS=90
```

Không tái sử dụng directory `r4`: manifest của nó khóa checksum adapter cũ.

Không truyền API key trên command line, không ghi key vào config và không bật
shell tracing (`set -x`). Nhập key trước khi chạy A/B/C mà không lưu vào history:

```bash
read -rsp 'Gemini API key: ' GEMINI_API_KEY
export GEMINI_API_KEY
printf '\n'
```

Các giá trị mặc định có thể tái lập là temperature `0` và ba
seed khác nhau. Chỉ override khi có lý do và phải giữ nguyên trong toàn bộ run:

```bash
export REVIEWER_A_SEED=17011
export REVIEWER_B_SEED=29023
export ADJUDICATOR_SEED=47017
export GEMINI_TEMPERATURE=0
export MACHINE_AUDIT_FRACTION=0.20
export MACHINE_AUDIT_FAILURE_THRESHOLD=0.10
```

Provider chấp nhận `GEMINI_API_KEY` hoặc `GOOGLE_API_KEY`. Chỉ đặt một trong hai
để tránh nhầm credential; script sẽ dừng nếu cả hai cùng tồn tại. Provider thấp
hơn ưu tiên `GOOGLE_API_KEY` khi được gọi trực tiếp với cả hai key, nhưng wrapper
không cho phép rơi vào trường hợp có hai nguồn credential này.

## Chạy tuần tự theo gate

Chạy từ root của repository. Lệnh đầu tiên tạo manifest machine-review, xáo thứ
tự riêng cho A/B theo seed cố định, xác minh đủ đúng 400 record và kiểm tra toàn
bộ snapshot mà chưa gọi model hoặc cần API key:

```bash
bash scripts/opengrep_machine_review.sh validate
```

Chỉ khi `validate` thành công mới chạy A và B. Chạy tuần tự nếu quota Free Tier
thấp; chạy song song chỉ khi AI Studio cho thấy quota của project đủ:

```bash
bash scripts/opengrep_machine_review.sh reviewer-a
```

Sau khi A đủ 400/400, chạy B:

```bash
bash scripts/opengrep_machine_review.sh reviewer-b
```

Theo dõi tiến độ mà không gọi API:

```bash
watch -n 5 -d 'bash scripts/opengrep_machine_review.sh status'
```

Chỉ khi A và B đều hoàn tất đúng 400 prediction mới tạo reconciliation và hàng
đợi adjudicator:

```bash
bash scripts/opengrep_machine_review.sh reconcile
```

Lượt đầu của C chỉ nhận finding và source đúng commit, chưa nhận verdict hay
reasoning A/B:

```bash
bash scripts/opengrep_machine_review.sh adjudicator-blind
```

Sau khi các verdict mù của C đã được đóng băng, lượt cuối mới đưa cho C các ý
kiến A/B đã ẩn danh để phân xử:

```bash
bash scripts/opengrep_machine_review.sh adjudicator-finalize
```

Mỗi command fail-closed nếu gate trước chưa hoàn tất. Run đã dở có thể chạy lại
cùng command để controller tiếp tục từ run state; không dùng `--force` và không
sửa trực tiếp prediction hoặc manifest. Muốn đổi model, seed, prompt hay policy
thì dùng một machine-review directory/release ID mới.

Adapter giữ nhịp tối đa 15 request/phút cho mỗi process và khi gặp 429 sẽ ưu
tiên `RetryInfo` của Google, nếu không có thì backoff 30/60 giây. Nếu API vẫn trả
`PROVIDER_RATE_LIMIT`, chờ quota hồi phục rồi chạy lại đúng command
`reviewer-a`, `reviewer-b`, `adjudicator-blind` hoặc `adjudicator-finalize` đang
dở. Các case `SUCCESS` được tái sử dụng theo checksum; case lỗi được ghi attempt
history và chạy lại. Nếu Google đổi `modelVersion` giữa hai phần của run, gate sẽ
từ chối trộn revision và yêu cầu một release directory mới.

## Artifact và provenance

Mặc định toàn bộ output mới nằm dưới release mới:

```text
artifacts/llm-review/opengrep-representative-gemini-only-r5-20260813/
├── machine-review-manifest.json
├── reviewer-a/
│   ├── blind-input.jsonl
│   └── run/
├── reviewer-b/
│   ├── blind-input.jsonl
│   └── run/
├── reconciliation/
├── adjudicator-c/
│   ├── blind/
│   └── final/
├── machine-reference-labels.jsonl
└── machine-review-summary.json
```

Manifest/final summary phải khóa checksum của sample, input, evidence packets,
prompt, response schema, controller và mọi prediction. Mỗi role phải lưu
provider, exact requested model ID, actual `modelVersion` do Gemini API trả về,
temperature, seed, token usage và raw response. Provenance cuối là
`LLM_ADJUDICATED`, `reviewer.kind = MODEL`.

Reconciliation summary cũng ghi raw agreement, Cohen's kappa, evidence-valid
coverage của A/B và tỷ lệ đưa sang C. Final summary ghi kết quả mẫu audit FP
đồng thuận, bao gồm tỷ lệ C không xác nhận lại là FP; đây là chỉ báo chất lượng
machine reference, không biến reference thành ground truth.

`validate` khóa exact requested model ID nhưng để `model_version` của prediction
rỗng trước run. Khi A/B/C chạy, provider ghi actual `modelVersion` do Gemini trả
về. Gate fail nếu giá trị này thiếu, thay đổi giữa run hoặc không nhất quán.

API key không được xuất hiện trong raw response, provider metadata, run state,
manifest hay log. Có thể kiểm tra sau run mà không in giá trị key:

```bash
rg -l 'AIza[0-9A-Za-z_-]{20,}' \
  artifacts/llm-review/opengrep-representative-gemini-only-r5-20260813 && \
  echo 'ERROR: possible credential in artifacts'
```

`rg` không in gì là kết quả mong đợi.

## Đối chiếu VulnGym và sử dụng kết quả

Chỉ sau khi `machine-reference-labels.jsonl` đã đóng băng mới được chạy bước
linkage tách biệt với VulnGym. Khi đó chỉ dùng tên `MACHINE_TP_LINKED` và
`MACHINE_TP_UNLINKED`; không gọi finding do LLM phát hiện là `TP_NOVEL` như một
sự thật đã được con người xác nhận.

`UNCERTAIN` phải báo riêng và không âm thầm quy đổi thành FP. Khi tính exploratory
metrics, phải công bố coverage/abstention cùng confusion matrix, precision,
recall và F1; đồng thời nêu rõ reference cũng do LLM tạo và có thể thiên lệch
cùng chiều với agent được đo.

Sau khi machine reference và prediction của một baseline đều đã đóng băng, chỉ
dùng evaluator mode dành riêng cho machine label:

```bash
.venv-wsl/bin/python -m vulngym_enrich.machine_evaluator classify \
  --labels artifacts/llm-review/opengrep-representative-gemini-only-r5-20260813/machine-reference-labels.jsonl \
  --reference-summary artifacts/llm-review/opengrep-representative-gemini-only-r5-20260813/machine-review-summary.json \
  --predictions '<frozen-baseline-predictions.jsonl>' \
  --output '<exploratory-machine-reference-metrics.json>'
```

Trước khi tính, evaluator dựng lại reconciliation và input phân xử từ các run
A/B/C đã đóng băng, đối chiếu decision với structured provider response và kiểm
tra checksum toàn package. Mode riêng này luôn ghi `publish_as_official=false`.
Không dùng evaluator human-gold hoặc đổi cờ này bằng cách sửa artifact; việc
tách module cũng bảo tồn checksum của evaluator official đã đóng băng.

## Trạng thái hiện tại và bước tiếp theo

Adapter Gemini đã có pacing, RetryInfo-aware backoff và bounded semantic retry.
Bước vận hành tiếp theo là tạo release `r5`, chạy `validate`, rồi chạy A và B.
Nếu quota trong AI Studio thấp, chạy tuần tự. Chỉ chạy `reconcile` sau khi cả hai
đạt đủ 400/400 và không còn failed.
