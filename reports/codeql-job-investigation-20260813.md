# Điều tra job CodeQL lỗi và thời gian chạy — 13/08/2026

## Phạm vi và trạng thái

Phân tích này chỉ đọc artifact của scan
`codeql-v2.25.5-security-extended-wsl-ext4-r1-20260812`. Không retry,
không sửa status và không thay đổi database.

Theo pointer mới nhất có 75 job đã bắt đầu: 71 `SUCCESS`, 2 `FAILED`, 1
`TIMEOUT` và 1 pointer `RUNNING` mồ côi. User service hiện `inactive`,
`ExecMainPID=0` và không còn process CodeQL/Java/runner; vì vậy batch không còn
quét tại thời điểm điều tra.

Từ “false” trong yêu cầu được hiểu là trạng thái `FAILED`. Đây là lỗi thực thi
scanner, không phải false positive/false negative của finding.

## Nguyên nhân hai job FAILED

Cả hai lỗi đều ở bước tạo database Go cho Milvus:

| Commit | Go mà source yêu cầu | Go đã ghim | Thời gian | Kết quả trực tiếp |
|---|---:|---:|---:|---|
| `2fad5b34f7d3` | 1.24.9 | 1.24.1 | 9,543 giây | `database create` exit 2 |
| `5519df6efc73` | 1.24.11 | 1.24.1 | 11,004 giây | `database create` exit 2 |

Cả bốn module `go.mod` trong mỗi snapshot đều yêu cầu đúng phiên bản nêu trên.
Profile khóa Go 1.24.1 và đặt `GOTOOLCHAIN=local`, nên Go không được tự tải
toolchain mới. Log cho thấy `go mod tidy`, `go get`, `packages.Load` và
extractor đều dừng với thông báo “go.mod requires go >= …”. Vì không module nào
extract được, CodeQL kết thúc bằng “Extraction failed for all discovered Go
projects”.

Log còn ghi `conan: command not found` khi autobuilder thử Makefile của Milvus.
Đây là lỗi phụ ở nhánh build C++/third-party fallback. Nguyên nhân chặn chắc chắn
và xuất hiện trước/lặp lại ở mọi Go module là Go 1.24.1 thấp hơn yêu cầu source.
Chỉ cài Conan mà không nâng Go sẽ không sửa được hai job này.

Nguồn bằng chứng:

- `artifacts/scans/.../milvus-io__milvus/2fad5b.../codeql/go/attempts/0001/create.stdout.log`
- `artifacts/scans/.../milvus-io__milvus/5519df.../codeql/go/attempts/0001/create.stdout.log`

Hướng sửa đã áp dụng ngày 13/08: cài và kiểm SHA-256 Go 1.24.11, giữ một Go
worker và truyền toolchain mới bằng runtime override có provenance. Năm job Go
đã thành công sẽ chạy lại cùng hai job lỗi để bảy job Go dùng chung toolchain;
66 job thành công không phải Go vẫn được reuse.

## Nguyên nhân job TIMEOUT

Job OpenClaw commit `041c47419f5a`, JavaScript/TypeScript:

- Tạo database: 112,857 giây — thành công.
- Analyze: 14.400,002 giây — chạm đúng giới hạn 4 giờ.
- Tổng attempt: 14.512,859 giây, tức 04:01:52,859.
- Process analyze bị runner kết thúc với return code -9 sau khi timeout.
- Không có bằng chứng OOM, Java heap error hoặc hết dung lượng đĩa.

Suite `security-extended` có 104 query. Log ghi 23 query hoàn tất; 13 query
nặng đã bắt đầu nhưng chưa hoàn tất, chủ yếu thuộc command injection, XSS, SQL
injection và code injection.

Nút thắt hiệu năng có bằng chứng là cache: evaluator giữ khoảng 6,49–6,50 GiB dữ
liệu thiết yếu trong khi `--max-disk-cache=2048` chỉ cho 2 GiB. CodeQL liên tục
báo không thể trim xuống 2 GiB và lặp nhiều lần pause/evict/unpause. Đây không
phải lỗi hết đĩa, nhưng làm analyze tiến triển quá chậm và cuối cùng chạm timeout.

Hướng sửa đã chọn: tái sử dụng database/BQRS hiện có, tăng disk cache riêng job
này lên 8 GiB, cấp 6 thread/10 GiB RAM cho một heavy worker và giới hạn mỗi
attempt ở 2 giờ. Vì attempt cũ vượt 4 giờ, nếu cấu hình mới vẫn timeout thì chia
cùng suite đã ghim thành các lane không chồng lặp rồi hợp nhất kết quả; không
tăng timeout hoặc chạy lại 66 job thành công không phải Go.

## Thống kê thời gian 71 job SUCCESS

- Tổng thời gian cộng dồn theo từng job: **08:12:55,813**.
- Trong đó create: **01:05:51,228**; analyze: **07:07:04,585**.
- Do từng giai đoạn từng chạy song song hoặc có khoảng dừng, tổng cộng dồn không
  phải wall-clock của batch.
- Khoảng thời gian quan sát từ lúc job thành công đầu tiên bắt đầu đến job thành
  công thứ 71 kết thúc: **11:02:16,298**.
- Nhanh nhất: **4,632 giây**; trung vị: **78,321 giây**; trung bình:
  **416,561 giây**; P90: **1.050,806 giây**; lâu nhất: **4.961,907 giây**.
- Theo ngôn ngữ: Actions 1 job/00:00:09,045; Go 5 job/00:09:04,050;
  JavaScript/TypeScript 35 job/06:58:23,200; Python 30 job/01:05:19,518.

Thời gian dưới đây là `create + analyze = total`; `00:00:00,000` ở create
nghĩa là database đã được tái sử dụng.

| # | Repository | Commit | Language | Create | Analyze | Total |
|---:|---|---|---|---:|---:|---:|
| 1 | modelcontextprotocol/typescript-sdk | `50d9fa3cd12e` | javascript-typescript | 00:00:00.000 | 00:00:12.196 | 00:00:12.196 |
| 2 | ollama/ollama | `732579159940` | go | 00:00:00.000 | 00:00:07.637 | 00:00:07.637 |
| 3 | nltk/nltk | `40d0bc1d484a` | python | 00:00:11.799 | 00:00:13.476 | 00:00:25.275 |
| 4 | FlowiseAI/Flowise | `1ae1638ed972` | javascript-typescript | 00:00:19.946 | 00:00:42.128 | 00:01:02.074 |
| 5 | FlowiseAI/Flowise | `4b1b8ba376db` | javascript-typescript | 00:00:20.298 | 00:00:42.567 | 00:01:02.865 |
| 6 | FlowiseAI/Flowise | `7c803f4e0bd9` | javascript-typescript | 00:00:17.875 | 00:00:35.712 | 00:00:53.587 |
| 7 | FlowiseAI/Flowise | `55b6913c03f0` | javascript-typescript | 00:00:20.598 | 00:00:42.319 | 00:01:02.917 |
| 8 | FlowiseAI/Flowise | `9d6a41677759` | javascript-typescript | 00:00:29.115 | 00:00:53.816 | 00:01:22.931 |
| 9 | FlowiseAI/Flowise | `af81d87063b6` | javascript-typescript | 00:00:27.755 | 00:00:50.547 | 00:01:18.302 |
| 10 | FlowiseAI/Flowise | `c045ceb872c0` | javascript-typescript | 00:00:26.417 | 00:00:51.904 | 00:01:18.321 |
| 11 | FlowiseAI/Flowise | `e135b2943362` | javascript-typescript | 00:00:25.980 | 00:00:52.121 | 00:01:18.101 |
| 12 | google/adk-python | `d1121317ef4e` | python | 00:00:18.291 | 00:00:24.240 | 00:00:42.531 |
| 13 | FlowiseAI/Flowise | `f0c1294173a5` | javascript-typescript | 00:00:30.051 | 00:01:14.403 | 00:01:44.454 |
| 14 | mlflow/mlflow | `83b9416cf1cf` | python | 00:00:40.594 | 00:00:32.779 | 00:01:13.373 |
| 15 | mlflow/mlflow | `083eac9cd0be` | python | 00:01:15.516 | 00:01:02.439 | 00:02:17.955 |
| 16 | mlflow/mlflow | `ba41980d604d` | python | 00:01:04.521 | 00:00:40.452 | 00:01:44.973 |
| 17 | mlflow/mlflow | `d1312edfca36` | python | 00:01:16.952 | 00:00:58.666 | 00:02:15.618 |
| 18 | NVIDIA/NeMo | `4d313cf5f097` | python | 00:00:40.159 | 00:01:04.484 | 00:01:44.643 |
| 19 | NVIDIA/NeMo | `d282d04322a8` | python | 00:00:42.958 | 00:01:07.159 | 00:01:50.117 |
| 20 | NVIDIA/NeMo | `ffee9a91f4b7` | python | 00:00:44.325 | 00:00:57.519 | 00:01:41.844 |
| 21 | paperclipai/paperclip | `50cd76d8a3f2` | javascript-typescript | 00:00:39.157 | 00:01:26.097 | 00:02:05.254 |
| 22 | paperclipai/paperclip | `549ef11c14b2` | javascript-typescript | 00:00:46.489 | 00:01:36.785 | 00:02:23.274 |
| 23 | paperclipai/paperclip | `a07237779bd5` | javascript-typescript | 00:00:33.222 | 00:01:21.520 | 00:01:54.742 |
| 24 | apache/airflow | `19c1a16dc8b4` | python | 00:01:44.128 | 00:01:51.792 | 00:03:35.920 |
| 25 | apache/airflow | `dba47277f309` | python | 00:01:41.397 | 00:02:14.065 | 00:03:55.462 |
| 26 | apache/airflow | `df4cb30b116c` | python | 00:01:45.506 | 00:01:30.781 | 00:03:16.287 |
| 27 | jlowin/fastmcp | `6bade1cbd973` | python | 00:00:09.586 | 00:00:12.879 | 00:00:22.465 |
| 28 | langchain-ai/langchain | `b7d1831f9d35` | python | 00:00:16.051 | 00:00:18.323 | 00:00:34.374 |
| 29 | langflow-ai/langflow | `198fab1dc7d4` | python | 00:00:24.323 | 00:00:24.792 | 00:00:49.115 |
| 30 | langflow-ai/langflow | `36eea7ee9db1` | python | 00:00:19.431 | 00:00:21.475 | 00:00:40.906 |
| 31 | langflow-ai/langflow | `73c1f203b020` | python | 00:00:11.646 | 00:00:14.290 | 00:00:25.936 |
| 32 | langflow-ai/langflow | `908c141d9721` | python | 00:00:07.334 | 00:00:10.962 | 00:00:18.296 |
| 33 | langflow-ai/langflow | `922a49acac14` | python | 00:00:23.443 | 00:00:23.024 | 00:00:46.467 |
| 34 | langflow-ai/langflow | `e8bbae8eeb87` | python | 00:00:24.447 | 00:00:22.765 | 00:00:47.212 |
| 35 | n8n-io/n8n | `3af9095245be` | python | 00:00:06.163 | 00:00:08.345 | 00:00:14.508 |
| 36 | n8n-io/n8n | `8e81f3e31398` | python | 00:00:06.010 | 00:00:08.302 | 00:00:14.312 |
| 37 | onnx/onnx | `bca0315ff3e5` | python | 00:00:09.093 | 00:00:10.865 | 00:00:19.958 |
| 38 | open-webui/open-webui | `1ac3dd4a893e` | python | 00:00:07.114 | 00:00:52.591 | 00:00:59.705 |
| 39 | open-webui/open-webui | `6cdb13d5cb26` | python | 00:00:06.107 | 00:00:17.513 | 00:00:23.620 |
| 40 | open-webui/open-webui | `9942de8011d4` | python | 00:00:05.576 | 00:00:17.368 | 00:00:22.944 |
| 41 | open-webui/open-webui | `e4e69a10ec08` | python | 00:00:07.254 | 00:00:52.741 | 00:00:59.995 |
| 42 | PrefectHQ/fastmcp | `c861862aeded` | python | 00:00:10.632 | 00:00:13.244 | 00:00:23.876 |
| 43 | Significant-Gravitas/AutoGPT | `f0c25036082a` | python | 00:00:15.759 | 00:00:15.259 | 00:00:31.018 |
| 44 | czlonkowski/n8n-mcp | `ff486ea04f0b` | javascript-typescript | 00:00:19.684 | 00:00:36.328 | 00:00:56.012 |
| 45 | n8n-io/n8n | `008cd8d08369` | javascript-typescript | 00:01:58.521 | 00:11:02.068 | 00:13:00.589 |
| 46 | BerriAI/litellm | `24f847b84c94` | python | 00:00:51.260 | 00:30:29.551 | 00:31:20.811 |
| 47 | n8n-io/n8n | `24af748fd3c8` | javascript-typescript | 00:02:09.871 | 00:19:54.870 | 00:22:04.741 |
| 48 | open-webui/open-webui | `9942de8011d4` | javascript-typescript | 00:00:16.108 | 00:00:24.685 | 00:00:40.793 |
| 49 | aquasecurity/trivy | `1885610c6a34` | actions | 00:00:03.027 | 00:00:06.018 | 00:00:09.045 |
| 50 | n8n-io/n8n | `09e2c2b5547b` | javascript-typescript | 00:00:00.000 | 00:00:04.632 | 00:00:04.632 |
| 51 | n8n-io/n8n | `3af9095245be` | javascript-typescript | 00:00:00.000 | 00:00:04.681 | 00:00:04.681 |
| 52 | n8n-io/n8n | `3cdfff7e6cbb` | javascript-typescript | 00:01:45.908 | 00:09:42.700 | 00:11:28.608 |
| 53 | n8n-io/n8n | `3f02194f6d17` | javascript-typescript | 00:02:25.066 | 00:52:35.610 | 00:55:00.676 |
| 54 | n8n-io/n8n | `4bb3552d8a0c` | javascript-typescript | 00:01:59.104 | 00:16:31.502 | 00:18:30.606 |
| 55 | n8n-io/n8n | `4c6b0180bd62` | javascript-typescript | 00:01:35.427 | 00:06:14.191 | 00:07:49.618 |
| 56 | n8n-io/n8n | `538181cbe32a` | javascript-typescript | 00:01:58.522 | 00:11:33.086 | 00:13:31.608 |
| 57 | n8n-io/n8n | `57d6015f2ea0` | javascript-typescript | 00:01:49.892 | 00:10:56.386 | 00:12:46.278 |
| 58 | n8n-io/n8n | `60670e1e40d3` | javascript-typescript | 00:01:28.515 | 00:05:46.623 | 00:07:15.138 |
| 59 | n8n-io/n8n | `6d2e489e54d1` | javascript-typescript | 00:02:12.857 | 00:25:22.649 | 00:27:35.506 |
| 60 | n8n-io/n8n | `732f2a3d3ddb` | javascript-typescript | 00:02:27.830 | 01:20:14.077 | 01:22:41.907 |
| 61 | n8n-io/n8n | `8a5d4d5746f5` | javascript-typescript | 00:01:50.088 | 00:11:05.351 | 00:12:55.439 |
| 62 | n8n-io/n8n | `8ab4492e8c0b` | javascript-typescript | 00:01:49.683 | 00:11:00.424 | 00:12:50.107 |
| 63 | n8n-io/n8n | `8e81f3e31398` | javascript-typescript | 00:02:20.567 | 00:51:55.858 | 00:54:16.425 |
| 64 | n8n-io/n8n | `911d3771ce23` | javascript-typescript | 00:01:50.037 | 00:10:54.396 | 00:12:44.433 |
| 65 | n8n-io/n8n | `e45a4b1073d8` | javascript-typescript | 00:01:46.170 | 00:09:35.148 | 00:11:21.318 |
| 66 | n8n-io/n8n | `e7d95055d1ab` | javascript-typescript | 00:01:51.342 | 00:11:39.643 | 00:13:30.985 |
| 67 | n8n-io/n8n | `ef9e32b27a78` | javascript-typescript | 00:01:42.470 | 00:07:51.614 | 00:09:34.084 |
| 68 | Tencent/WeKnora | `10b6c98078dc` | go | 00:05:21.192 | 00:00:13.040 | 00:05:34.232 |
| 69 | Tencent/WeKnora | `a20541cd9d0a` | go | 00:01:42.088 | 00:00:12.059 | 00:01:54.147 |
| 70 | Tencent/WeKnora | `a5d1233b969f` | go | 00:00:31.931 | 00:00:12.790 | 00:00:44.721 |
| 71 | Tencent/WeKnora | `de06bb24d319` | go | 00:00:31.050 | 00:00:12.263 | 00:00:43.313 |

## Trạng thái RUNNING mồ côi

Hai attempt đầu của n8n còn file `RUNNING`, nhưng pointer mới nhất của cùng job
đã trỏ đến attempt 2 `SUCCESS`; chúng không làm thiếu coverage của hai job đó.

Pointer OpenClaw mồ côi thực tế là commit `04e103d10ef7`, attempt 1; commit
`041c47419f5a` là job `TIMEOUT` riêng. Attempt `04e103d10ef7` bắt đầu ngay sau
job timeout rồi transient service/session biến mất. Ngày 13/08, attempt và
pointer này đã được reconcile thành `INTERRUPTED` tại thời điểm service bị đóng
băng, giữ nguyên log cũ làm audit trail. Runner sẽ tạo attempt mới khi đến hàng
đợi heavy; không coi attempt bị gián đoạn là `SUCCESS`.
