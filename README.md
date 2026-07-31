# Làm giàu dữ liệu VulnGym và xác minh phát hiện

Kho lưu trữ này mở rộng Tencent VulnGym bằng các phát hiện của trình quét đã được thẩm định, đặc biệt là các kết quả dương tính giả đã được xác nhận, đồng thời cung cấp một bộ benchmark có thể tái lập dành cho các tác nhân xác minh phát hiện.

## Các đầu vào được cố định

- VulnGym: `v0.1.4` at `cd69f7e163e08485ab5496115ae03439cda6e27e`
- Semgrep: `1.171.0`
- OpenGrep: `1.26.0`
- Rules: `semgrep/semgrep-rules` at `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`

Bộ benchmark và các quy tắc là những Git submodule. Khởi tạo chúng bằng lệnh:

```bash
git submodule update --init --recursive
```

## Thiết lập môi trường phát triển

```bash
uv sync --extra dev
uv run vulngym-audit --benchmark benchmark/VulnGym --output artifacts/manifests/vulngym-v0.1.4.json
uv run pytest
```

## Cấu trúc kho lưu trữ

- `benchmark/VulnGym/`: bộ benchmark thượng nguồn đã được ghim phiên bản.
- `rules/semgrep-rules/`: bộ quy tắc của trình quét đã được ghim phiên bản.
- `config/scanners.lock.json`: tệp khóa phục vụ khả năng tái lập.
- `schemas/`: các schema dành cho phát hiện đã chuẩn hóa và thẩm định.
- `src/vulngym_enrich/`: các công cụ kiểm tra, checkout, đối sánh và đánh giá.
- `tests/`: các kiểm thử hồi quy.
- `docs/`: tài liệu về chú thích và phương pháp luận.
- `artifacts/`: các manifest và kết quả quét được tạo ra; bị Git bỏ qua.

## Chính sách gán nhãn

Một phát hiện của Semgrep/OpenGrep không khớp với dữ liệu VulnGym không mặc nhiên là kết quả dương tính giả. Các phát hiện không khớp có thể là lỗ hổng mới hoặc biểu hiện khác của những lỗ hổng đã biết. Xem `docs/annotation-guideline.md`.

## An toàn và phạm vi

Chỉ chạy trình quét trên các kho lưu trữ và commit thuộc bộ benchmark VulnGym công khai hoặc trên mã nguồn mà bạn được phép phân tích. Theo mặc định, quá trình xác minh của tác nhân chỉ được phép đọc và không được nhận nhãn cảnh báo bảo mật hoặc bản vá đã sửa lỗi trong quá trình đánh giá.
