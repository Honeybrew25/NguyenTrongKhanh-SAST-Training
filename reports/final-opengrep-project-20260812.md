# Báo cáo tổng kết OpenGrep security baseline r1

## 1. Trạng thái release

Release `opengrep-security-r1-20260812` đã hoàn tất full scan, normalize,
deduplicate, match candidate, annotation queue và frozen verifier corpus trên
Ubuntu WSL2/ext4. Đây là baseline OpenGrep tương đương phần chuẩn bị corpus của
release Semgrep; agent prediction, human adjudication mới và metrics chưa chạy.

OpenGrep `1.22.0` quét đúng 166 snapshot VulnGym bằng ruleset security-only.
Binary, manifest, scanner lock, scan profile, source ruleset và derived security
ruleset đều có pin/checksum trong pipeline summary và release manifest.

## 2. Kết quả full scan

| Chỉ số | Giá trị |
|---|---:|
| Job SUCCESS | 166/166 |
| Finding chuẩn hóa | 113.756 |
| Rule duy nhất | 129 |
| File duy nhất | 2.082 |
| Finding có dataflow trace | 16.886 |
| Canonical cluster | 112.739 |
| Exact duplicate observation | 1.017 |
| `CANDIDATE_REVIEW` | 14 |
| `UNMATCHED` | 112.725 |
| Scanner diagnostic | 8.459 |

Các diagnostic gồm 8.438 `PartialParsing`, 12 timeout ở mức scanner/rule, 8
`Syntax error` và 1 `Other syntax error`. 149 job có ít nhất một diagnostic,
nhưng không có job `FAILED` hoặc job timeout. Coverage gate vì vậy hoàn chỉnh;
diagnostic vẫn được giữ để không che mất hạn chế parser/rule.

## 3. Corpus đánh giá OpenGrep

Pipeline tạo 14 candidate cluster/14 observation. Bộ tạo release kiểm tra
coverage fail-closed, nối candidate match với canonical finding theo quan hệ
một-một, rồi sinh:

- queue cho human review;
- template gold label chưa điền;
- input verifier mù không chứa canonical ID, VulnGym entry/report ID, match,
  patch hoặc adjudication label;
- corpus summary cùng SHA-256 của input.

Frozen input có 14 record, SHA-256
`7abb5bd8064a00fe4da18f16f1c4a2b6e8fc2d31d7b886fea5c9c14e6cc5bc7a`.
Policy vẫn là `UNLABELED_NOT_FALSE_POSITIVE`: 112.725 finding `UNMATCHED` không
được tính là false positive.

## 4. Đối chiếu với Semgrep

Theo khóa ngữ nghĩa `(repo, commit, file, start_line, rule_id)`, corpus Semgrep
có 110.437 khóa, OpenGrep có 110.130 khóa và giao nhau 108.644 khóa. Jaccard là
**0,9707**; Semgrep-only 1.793 và OpenGrep-only 1.486. So sánh cột/end-location
không dùng làm chỉ số chính vì hai engine định vị span khác nhau.

14 candidate OpenGrep đều trùng khóa ngữ nghĩa với 14 candidate đã được review
ở release Semgrep. Phân bố nhãn tham chiếu của phần giao là 12 `TP_KNOWN`, 1
`FP_CONFIRMED`, 1 `UNCERTAIN`. Message và snippet trùng 14/14; exact location
trùng 12/14 và dataflow trace trùng 13/14. Nhãn cũ không được nhập thành gold
label OpenGrep.

Hai candidate Semgrep `TP_KNOWN` không được OpenGrep giữ lại đều thuộc
`javascript.lang.security.detect-child-process`:

- `openclaw/openclaw`, commit `be37b397...`, `src/signal/daemon.ts:52`;
- `paperclipai/paperclip`, commit `50cd76d8...`,
  `server/src/services/workspace-runtime.ts:479`.

Toàn corpus, rule này giảm từ 1.878 finding Semgrep xuống 72 finding OpenGrep.
Đây là chênh lệch tương thích/taint semantics cần điều tra trước khi xem hai
engine là thay thế hoàn toàn cho nhau.

## 5. Kết luận và bước đánh giá tiếp theo

Project OpenGrep đã hoàn thiện baseline tái lập và corpus mù sẵn sàng cho agent.
Kết quả chưa đủ để công bố precision, recall hay F1 của verifier OpenGrep. Một
release đánh giá chính thức phải dùng corpus này, chạy agent không thấy metadata
match, khóa prediction trước human review, có người thẩm định độc lập điền đủ 14
gold label rồi mới chạy evaluator.

Kết quả máy đọc nằm tại
`data/releases/opengrep-security-r1-20260812.json`; artifact dung lượng lớn nằm
trong `artifacts/` và không được Git track.
