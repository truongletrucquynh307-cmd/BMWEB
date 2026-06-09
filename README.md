# HỆ THỐNG ĐẶT VÉ XEM PHIM TRỰC TUYẾN

## Giới thiệu

Đây là ứng dụng web đặt vé xem phim trực tuyến được xây dựng bằng Flask và SQLite. Hệ thống cho phép người dùng đăng ký tài khoản, đăng nhập, xem danh sách phim, đặt vé và quản lý lịch sử giao dịch.

Bên cạnh các chức năng nghiệp vụ, ứng dụng còn triển khai nhiều cơ chế bảo mật theo nguyên tắc Privacy by Design nhằm bảo vệ dữ liệu người dùng và giảm thiểu các nguy cơ tấn công phổ biến trên môi trường web.

---

## Công nghệ sử dụng

### Backend

* Python 3.x
* Flask
* SQLite

### Frontend

* HTML5
* CSS3
* Bootstrap 5
* JavaScript

### Thư viện bảo mật

* Flask-WTF
* Flask-Limiter
* Bcrypt
* Itsdangerous

---

## Chức năng người dùng

### Tài khoản

* Đăng ký tài khoản
* Đăng nhập
* Đăng xuất
* Quên mật khẩu
* Đổi mật khẩu
* Cập nhật thông tin cá nhân
* Xóa tài khoản

### Đặt vé

* Xem danh sách phim
* Xem thông tin chi tiết phim
* Xem suất chiếu
* Đặt vé xem phim
* Xem lịch sử đặt vé

---

## Chức năng quản trị

### Admin System

* Quản lý người dùng
* Khóa/Mở khóa tài khoản
* Đặt lại mật khẩu người dùng
* Phân quyền tài khoản
* Xem lịch sử đặt vé
* Xem Security Logs
* Quản lý phim
* Quản lý suất chiếu

### Admin Content

* Quản lý phim
* Quản lý suất chiếu
* Xem danh sách vé đã đặt

---

## Các cơ chế bảo mật đã triển khai

### SQL Injection Protection

Sử dụng Parameterized Query:

```python
user = conn.execute(
    "SELECT * FROM users WHERE email=?",
    (email,)
).fetchone()
```

Ngăn chặn payload SQL Injection như:

```sql
' OR 1=1 --
```

---

### XSS Protection

Kiểm tra dữ liệu đầu vào:

```python
elif "<script>" in seats.lower():
```

Kết hợp cơ chế auto-escape của Jinja2 nhằm hạn chế thực thi JavaScript độc hại.

---

### CSRF Protection

```python
from flask_wtf import CSRFProtect

csrf = CSRFProtect(app)
```

Mọi form quan trọng đều sử dụng CSRF Token.

---

### Password Security

Mật khẩu được mã hóa bằng Bcrypt:

```python
bcrypt.hashpw(
    password.encode(),
    bcrypt.gensalt()
)
```

Không lưu mật khẩu dạng plaintext.

---

### Brute Force Protection

Sử dụng Flask-Limiter:

```python
@limiter.limit("5 per minute")
```

Giới hạn số lần đăng nhập nhằm giảm nguy cơ dò mật khẩu.

---

### Session Security

```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
```

Ngăn JavaScript truy cập Session Cookie.

---

### Password Reset Token

Reset mật khẩu bằng Token có thời hạn sử dụng.

Ngăn việc sử dụng lại liên kết đặt lại mật khẩu sau khi hết hạn.

---

### Logging & Monitoring

Hệ thống ghi nhận:

* Đăng nhập
* Đăng xuất
* Đặt vé
* Đổi mật khẩu
* Phát hiện XSS
* Phát hiện truy cập bất thường

Ví dụ:

```python
logging.warning(
    "Malicious script injection blocked"
)
```

---

## Privacy by Design

Ứng dụng triển khai các nguyên tắc Privacy by Design:

### 1. Proactive not Reactive

* Chống SQL Injection
* Chống XSS
* Chống CSRF
* Chống Brute Force

### 2. Privacy as the Default Setting

* Chỉ thu thập dữ liệu cần thiết
* Người dùng chủ động lựa chọn nhận email quảng cáo

### 3. Privacy Embedded into Design

* Tích hợp bảo mật ngay từ giai đoạn phát triển

### 4. Full Functionality

* Đảm bảo bảo mật nhưng vẫn duy trì đầy đủ chức năng đặt vé

### 5. End-to-End Security

* Bcrypt
* Session Security
* Password Reset Token

### 6. Visibility and Transparency

* Chính sách bảo mật công khai
* Minh bạch cách thu thập và sử dụng dữ liệu

### 7. Respect for User Privacy

* Người dùng được quyền quản lý tài khoản
* Người dùng được quyền xóa tài khoản
* Tùy chọn nhận email marketing

---

## Cài đặt

### Clone project

```bash
git clone <repository_url>
```

### Cài đặt thư viện

```bash
pip install -r requirements.txt
```

### Chạy ứng dụng

```bash
python app.py
```

### Truy cập

```text
http://127.0.0.1:5000
```

---

## Tài khoản mặc định

### Admin System

```text
Email: admins@gmail.com
Password: Aa123456@
```

### Admin Content

```text
Email: adminc@example.com
Password: Aa123456@
```

---

* [Tên giảng viên]
