# Báo cáo Normalize và Deduplicate kết quả SAST

Cập nhật lần cuối: **13/08/2026**

Phạm vi hiện tại: **OpenGrep 1.22.0**. Đây là baseline SAST duy nhất được dùng
cho kết quả và đánh giá của project.

## 1. Tóm tắt kết quả

| Chỉ số | OpenGrep |
|---|---:|
| Trạng thái scan | 166/166 `SUCCESS` |
| Raw/normalized observations | 113.756 |
| Canonical clusters | 112.739 |
| Quan sát trùng được nhận diện | 1.017 |
| Cluster có nhiều quan sát | 677 |
| Singleton clusters | 112.062 |
| Finding có dataflow trace | 16.886 |
| Unique rules | 129 |
| Unique files | 2.082 |

Đơn vị dùng cho lấy mẫu và human review là **canonical cluster**, không phải số
dòng observation. Vì vậy population OpenGrep hiện tại là **112.739 nhóm cảnh
báo**, không phải 113.756 finding thô.

## 2. Định danh lần xử lý OpenGrep

- Scan ID:
  `opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812`.
- Scanner: OpenGrep `1.22.0`.
- Scanner executable SHA-256:
  `45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319`.
- Security ruleset commit:
  `0c8a62c126651c4640e7c634912acc16de878282`.
- VulnGym manifest SHA-256:
  `86dc0c249deb415ebffba5d54e81bd86dfb5d509745f4e97c7158a3d3c3cf9aa`.
- Entries SHA-256:
  `8a0385a987dbad8e573ad06aec1b6b05367dd783b28f3bbf1ce2464aef851bf2`.
- Coverage: 166 snapshot dự kiến, 166 job được ghi nhận, toàn bộ `SUCCESS`.

Thư mục kết quả:

```text
artifacts/normalized/
└── opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812-opengrep-only/
```

## 3. Normalize đã làm gì?

OpenGrep xuất JSON tương thích Semgrep nhưng mỗi raw result vẫn phải được đưa về
một schema ổn định trước khi so sánh hoặc review. Normalize thực hiện các việc
chính sau:

1. Gắn đúng `repo_url` và commit 40 ký tự của snapshot.
2. Chuẩn hóa đường dẫn thành repo-relative và dùng dấu `/`.
3. Chuẩn hóa rule ID, ruleset commit, CWE, category và severity.
4. Chuẩn hóa vị trí bắt đầu/kết thúc và snippet.
5. Giữ dataflow trace nếu scanner cung cấp.
6. Sinh `finding_id` ổn định từ repository, commit, scanner, rule, vị trí và
   ruleset.
7. Giữ provenance trỏ về raw result để có thể kiểm toán ngược.

Kết quả normalize:

| Chỉ số | Giá trị |
|---|---:|
| Findings | 113.756 |
| Unique rules | 129 |
| Unique files | 2.082 |
| Có dataflow trace | 16.886 — 14,84% |
| Trace nodes | 61.651 |
| Trace dài nhất | 11 nodes |
| `ERROR` | 22.049 |
| `WARNING` | 88.695 |
| `INFO` | 3.012 |

File chính:

```text
security-normalized.jsonl
```

SHA-256:
`077955a6964a90a31573f040fea641547f43a2a0d45bdeeab2ea8c345ce5fda1`.

## 4. Deduplicate đã làm gì?

Deduplicate trong project **không xóa observation gốc**. Nó giữ đủ 113.756 dòng
và gán cùng `canonical_finding_id` cho những observation thuộc một nhóm. Cách
này vừa cho phép làm việc với 112.739 nhóm duy nhất, vừa giữ đủ provenance của
mọi lần scanner quan sát thấy finding.

Khóa exact gồm:

```text
snapshot + scanner/version + rule/ruleset + normalized location
```

Chỉ xét semantic merge khi finding ở cùng snapshot và cùng file, trong phạm vi
5 dòng, đồng thời có bằng chứng chung như rule ID, snippet fingerprint hoặc
CWE/category giao nhau. Merge bị từ chối khi CWE tách biệt, snippet cụ thể khác
nhau hoặc cột trên cùng dòng không giao nhau.

Kết quả deduplicate:

| Chỉ số | Giá trị |
|---|---:|
| Input observations | 113.756 |
| Output observations được giữ | 113.756 |
| Canonical clusters | 112.739 |
| Duplicate observations | 1.017 — 0,89% |
| Exact-duplicate clusters | 677 |
| Singleton clusters | 112.062 |
| Cross-tool merges | 0 |
| Observation có canonical ID | 113.756/113.756 |

File dữ liệu và summary:

```text
security-deduplicated.jsonl
security-dedup-summary.json
```

SHA-256:

- `security-deduplicated.jsonl`:
  `a432411e9ea289575b49efeccccd02dafe3d5d132908dfcf2ff76c354c215ed9`.
- `security-dedup-summary.json`:
  `fc7c2228504cf8b9f718212b2c027785c839239201a16d93f25ef36d9880b250`.

## 5. Phân bố đáng chú ý sau normalize

### Repository có nhiều observations nhất

| Repository | Observations | Tỷ lệ |
|---|---:|---:|
| openclaw/openclaw | 92.424 | 81,25% |
| n8n-io/n8n | 12.958 | 11,39% |
| FlowiseAI/Flowise | 2.362 | 2,08% |
| mlflow/mlflow | 1.166 | 1,03% |
| apache/airflow | 1.038 | 0,91% |

### Rule có nhiều observations nhất

| Rule | Observations |
|---|---:|
| `javascript.jquery.security.audit.prohibit-jquery-html` | 45.906 |
| `javascript.lang.security.detect-insecure-websocket` | 18.403 |
| `javascript.lang.security.html-in-template-string` | 16.589 |
| `javascript.lang.security.audit.detect-non-literal-regexp` | 6.334 |
| `javascript.lang.security.audit.detect-non-literal-fs-filename` | 3.717 |
| `javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop` | 3.384 |
| `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal` | 2.841 |

Phân bố này giải thích vì sao một mẫu xác suất đều sẽ có nhiều OpenClaw và các
rule JavaScript nói trên. Đây không phải duplicate còn sót lại; nó phản ánh
population thực tế của scanner/ruleset.

## 6. Matching sau deduplicate

Canonical cluster được đối chiếu với 393 VulnGym entry đã human-verified, dùng
tolerance 5 dòng:

| Match tier | Clusters |
|---|---:|
| `STRICT_SOURCE_SINK` | 0 |
| `STRONG_SOURCE_SINK` | 0 |
| `CANDIDATE_REVIEW` | 14 |
| `UNMATCHED` | 112.725 |

`UNMATCHED` chỉ có nghĩa là chưa khớp ground truth VulnGym bằng policy hiện tại.
Nó **không phải nhãn false positive**. Chỉ human review mới được gán
`FP_CONFIRMED`.

Các file tra cứu:

```text
canonical-security-matches.jsonl
canonical-security-match-summary.json
full-pipeline-summary.json
```

## 7. Giới hạn và cảnh báo chất lượng

Mặc dù 166/166 job có trạng thái `SUCCESS`, scanner vẫn phát sinh 8.459 chẩn
đoán ở 149 job:

| Loại | Số lượng |
|---|---:|
| `PartialParsing` | 8.438 |
| `Timeout` | 12 |
| `Syntax error` | 8 |
| `Other syntax error` | 1 |

Vì release này chỉ chạy OpenGrep nên 8.438 file partial parsing chưa có scanner
thứ hai xác nhận đã quét sạch. Do đó `SUCCESS` nghĩa là job hoàn tất và output
hợp lệ, không có nghĩa mọi file đều được parse đầy đủ. Các chẩn đoán được giữ ở:

```text
scanner-errors.jsonl
```

SHA-256:
`a266febabf43ec6ede82757244cc710bbbe8a0161c12fd94fec55b638fc4d769`.

## 8. Lệnh tái tạo OpenGrep Normalize + Deduplicate

Chỉ chạy lại khi cần tái tạo artifact từ full scan đã hoàn tất:

```bash
cd ~/projects/NguyenTrongKhanh-SAST-Training-opengrep
bash scripts/opengrep_scan_wsl.sh normalize
```

Lệnh gọi `vulngym-full-pipeline` với scanner `opengrep`, kiểm tra coverage và
provenance trước khi normalize. Nếu batch không hoàn chỉnh, pipeline mặc định
dừng thay vì xuất báo cáo một phần.

## 9. Lịch sử cập nhật

| Ngày | Thay đổi |
|---|---|
| 13/08/2026 | Ghi kết quả Normalize + Deduplicate OpenGrep; xác nhận OpenGrep là baseline SAST duy nhất của project. |
