# brblocked-filters

Bộ lọc quảng cáo cho app Android BRBlocked. App tải các file ở đây để cập nhật rule mà không cần cài bản mới.

- `index.txt`: mục lục, mỗi dòng là `sha256  tên file` (định dạng của `sha256sum`). App chỉ tải file có mã khác bản đã có và bỏ qua file không khớp mã.
- `common.txt`: mạng quảng cáo và tracker phổ biến.
- `nettruyen.txt`: rule riêng cho nettruyen.

Cú pháp là tập con của Adblock Plus:

| Rule | Ý nghĩa |
|---|---|
| `\|\|ads.com^` | Chặn domain và mọi subdomain |
| `\|\|site.com/ads/` | Chặn theo đường dẫn |
| `@@\|\|cdn.com^` | Luôn cho phép domain |
| `site.com##.banner` | Ẩn phần tử trên site |
| `$strict=site.com` | Trên site này chặn mọi bên thứ ba ngoài allowlist |
| `$nav-allow=site.com` | Luôn cho phép điều hướng tới domain |

Repo này được cập nhật tự động từ mã nguồn của app, không sửa trực tiếp.
