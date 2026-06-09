from flask import Flask, abort, render_template, request, redirect, session, url_for, make_response
import sqlite3
import bcrypt
import re
import logging 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded 
from datetime import datetime
import pytz
import os
from werkzeug.utils import secure_filename
from flask import flash
from werkzeug.security import generate_password_hash

# --- Cấu hình Logging ---
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.secret_key = "secret123"

UPLOAD_FOLDER = 'static/posters'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from itsdangerous import URLSafeTimedSerializer

# Khởi tạo Serializer (dùng chung secret_key với app)
s = URLSafeTimedSerializer(app.secret_key)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        
        if user:
            # Tạo token
            token = s.dumps(email, salt='reset-password')
            
            # Ghi log terminal để kiểm tra (vẫn giữ để bạn an tâm)
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"\n--- [DEBUG] Auto-redirecting to: {reset_link} ---\n")
            
            # TỰ ĐỘNG CHUYỂN HƯỚNG SANG TRANG RESET MẬT KHẨU
            return redirect(url_for('reset_password', token=token))
        else:
            error = "Email không tồn tại trong hệ thống."
            
    return render_template('forgot_password.html', error=error)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=3600)
    except:
        return "Token không hợp lệ hoặc đã hết hạn."

    error = None
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Kiểm tra xác nhận mật khẩu
        if password != confirm_password:
            error = "Mật khẩu xác nhận không khớp!"
        else:
            # Kiểm tra chính sách mật khẩu
            is_valid, msg = validate_password_policy(password)
            if not is_valid:
                error = msg
            else:
                # Kiểm tra mật khẩu cũ trong DB
                conn = get_db()
                user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                
                if user and bcrypt.checkpw(password.encode(), user['password']):
                    conn.close()
                    error = "Mật khẩu mới không được trùng với mật khẩu cũ!"
                else:
                    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                    conn.execute("UPDATE users SET password=? WHERE email=?", (hashed, email))
                    conn.commit()
                    conn.close()
                    return redirect(url_for('login', msg='reset_success'))
    
    return render_template('reset_password.html', token=token, error=error)

def get_db_connection():
    # Thay 'database.db' bằng tên file database của bạn
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Giúp lấy dữ liệu dạng cột giống dictionary
    return conn

def add_log(user_id, action):
    conn = get_db()

    conn.execute("""
        INSERT INTO logs(user_id, action, created_at)
        VALUES (?, ?, ?)
    """, (
        user_id,
        action,
        vn_now()
    ))

    conn.commit()
    conn.close()

def validate_password_policy(password):
    """Trả về (True, "") nếu hợp lệ, (False, "Lỗi") nếu không hợp lệ."""
    if len(password) < 8:
        return False, "Mật khẩu phải có ít nhất 8 ký tự"
    if not re.search(r"[A-Z]", password):
        return False, "Mật khẩu phải có ít nhất 1 chữ hoa"
    if not re.search(r"[a-z]", password):
        return False, "Mật khẩu phải có ít nhất 1 chữ thường"
    if not re.search(r"[0-9]", password):
        return False, "Mật khẩu phải có ít nhất 1 số"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Mật khẩu phải có ít nhất 1 ký tự đặc biệt"
    return True, ""

def vn_now():
    vn_tz = pytz.timezone("Asia/Ho_Chi_Minh")
    return datetime.now(vn_tz).strftime("%Y-%m-%d %H:%M:%S")

# --- HELPER: FORMAT DATE ---
from datetime import datetime

@app.template_filter('format_date')
def format_date(value):
    try:
        # Chuyển đổi chuỗi YYYY-MM-DD sang DD/MM/YYYY
        return datetime.strptime(value, "%Y-%m-%d").strftime("%d/%m/%Y")
    except:
        # Nếu dữ liệu lỗi, trả về nguyên bản
        return value
    
# 🔒 Cấu hình bảo mật Cookie (Chặn tấn công XSS đánh cắp Session)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# 🔧 Khởi tạo Rate Limiter (Giới hạn tần suất gửi yêu cầu)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"]
)

from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)

# 🔥 CUSTOM HANDLER CHO LỖI 429 (RATE LIMIT)
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template(
        "login.html",
        error="Bạn đã đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 1 phút.",
        blocked=True
    ), 429

# --- Database Setup ---
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # USERS
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password BLOB,
        role VARCHAR(20) DEFAULT 'user',
        created_at TEXT,
        is_active INTEGER DEFAULT 1
    )
    ''')

    # MOVIES
    c.execute('''
    CREATE TABLE IF NOT EXISTS movies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        genre TEXT,
        duration INTEGER,
        rating REAL,
        poster TEXT
    )
    ''')

    # SHOWTIMES
    c.execute('''
   CREATE TABLE IF NOT EXISTS showtimes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    movie_id INTEGER,
    cinema TEXT,
    hall TEXT,
    date TEXT,
    time TEXT,
    price INTEGER,
    FOREIGN KEY(movie_id) REFERENCES movies(id)
)
    ''')

    # BOOKINGS
    c.execute('''
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        showtime_id INTEGER,
        total_price INTEGER,
        created_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(showtime_id) REFERENCES showtimes(id)
    )
    ''')

    # BOOKING SEATS
    c.execute('''
    CREATE TABLE IF NOT EXISTS booking_seats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER,
        seat_name TEXT,
        FOREIGN KEY(booking_id) REFERENCES bookings(id)
    )
    ''')

    # LOGS
    c.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        created_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    conn.commit()
    conn.close()

def seed_movies():
    conn = get_db()
    
    # 🌟 Cách 1: Xóa sạch bảng cũ để nạp lại từ đầu (Khuyên dùng khi đang làm bài tập/dev)
    conn.execute("DELETE FROM movies")
    
    # Reset luôn cả bộ đếm ID về 1 để tránh ID phim bị nhảy số quá lớn
    conn.execute("DELETE FROM sqlite_sequence WHERE name='movies'") 
    
    # Nạp dữ liệu chuẩn chỉnh (Đã thêm số 8.7 vào phim Spider-Man để đủ 5 cột)
    conn.execute("""
    INSERT INTO movies (title, genre, duration, rating, poster)
    VALUES
    ('Avengers Endgame', 'Action | Sci-Fi', 181, 8.9, 'avengers.jpg'),
    ('Batman Dark Knight', 'Action | Crime', 152, 9.0, 'batman.jpg'),
    ('Spider-Man No Way Home', 'Action | Adventure', 148, 8.7, 'spider-man.jpg')
    """)
    
    conn.commit()
    conn.close()
    print("=== Đã làm sạch và cập nhật dữ liệu phim thành công! ===")

def seed_showtimes():
    conn = get_db()

    showtimes = conn.execute(
        "SELECT * FROM showtimes"
    ).fetchall()

    if not showtimes:
        conn.execute("""
        INSERT INTO showtimes(movie_id, cinema, hall, date, time, price)
        VALUES

        -- Avengers
        (1, 'Galaxy Nguyễn Du', 'Phòng 01', '2026-06-05', '10:00', 75000),
        (1, 'Galaxy Nguyễn Du', 'Phòng 01', '2026-06-06', '14:00', 85000),
        (1, 'CGV Landmark 81', 'Phòng 03', '2026-06-07', '19:00', 120000),

        -- Batman
        (2, 'Lotte Cinema Gò Vấp', 'Phòng 02', '2026-06-05', '13:00', 80000),
        (2, 'CGV Vincom', 'Phòng 05', '2026-06-04', '18:00', 110000),

        -- Spider-Man
        (3, 'Galaxy Tân Bình', 'Phòng 04', '2026-06-03', '09:30', 70000),
        (3, 'CGV Aeon Mall', 'Phòng 06', '2026-06-07', '20:00', 125000)
        """)

        conn.commit()

    conn.close()

init_db()
seed_movies()
seed_showtimes()

# --- AUTH ROUTES ---
@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # Lấy giá trị từ checkbox (nếu checkbox được tích, giá trị thường là 'on', nếu không sẽ là None)
        agree_terms = request.form.get('agree_terms')

        is_valid, msg = validate_password_policy(password)
        
        # 1. Kiểm tra Email
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            error = "Email không hợp lệ"
        
        # 2. Kiểm tra điều khoản (Checkbox)
        elif not agree_terms:
            error = "Bạn cần đồng ý với Điều khoản dịch vụ và Chính sách bảo mật"
            
        # 3. Kiểm tra chính sách mật khẩu
        elif not is_valid:
            error = msg
            
        # 4. Xử lý đăng ký nếu hợp lệ
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                conn = get_db()
                conn.execute("INSERT INTO users(email, password, created_at) VALUES (?, ?, ?)", 
                             (email, hashed, vn_now()))                
                conn.commit()
                logging.info(f"New user registered: {email}")
                return redirect(url_for('login', msg='registered')) 
            except sqlite3.IntegrityError:
                error = "Email này đã được đăng ký trước đó"
            finally:
                conn.close()
                

    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        # Kiểm tra user tồn tại và mật khẩu khớp
        if user and bcrypt.checkpw(password.encode(), user['password']):
            
            # --- BẮT ĐẦU ĐOẠN KIỂM TRA TRẠNG THÁI ---
            if user['is_active'] == 0:
                error = "Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên."
                logging.warning(f"Attempted login with blocked account: {email}")
            else:
                # Đăng nhập thành công
                session['user_id'] = user['id']
                add_log(user['id'], "Đăng nhập hệ thống")
                session['role'] = user['role']
                logging.info(f"User login: {email} with role: {user['role']}")
                
                if user['role'] in ['admin_system', 'admin_content']:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('home'))
            # --- KẾT THÚC ĐOẠN KIỂM TRA ---

        else:
            logging.warning(f"Failed login attempt for: {email}")
            error = "Email hoặc mật khẩu không chính xác"
           
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    # 1. Lấy ID từ session trước khi xóa session
    current_user_id = session.get('user_id')
    
    # 2. Ghi log (Dùng current_user_id thay cho user_id)
    logging.info(f"User {current_user_id} logged out")
    
    add_log(session['user_id'], "Đăng xuất")

    # 3. Xóa session
    session.clear()
    return redirect(url_for('login'))

# --- APP ROUTES ---
@app.route('/')
def home():
    conn = get_db()
    
    # Chỉ lấy danh sách phim
    movies_raw = conn.execute("SELECT * FROM movies").fetchall()
    
    movies = []
    for m in movies_raw:
        movie_dict = dict(m)
        showtimes = conn.execute("""
            SELECT id, time, date, cinema 
            FROM showtimes 
            WHERE movie_id = ? 
            ORDER BY time ASC
        """, (m['id'],)).fetchall()
        movie_dict['showtimes'] = [dict(s) for s in showtimes]
        movies.append(movie_dict)
        
    conn.close()
    return render_template('home.html', movies=movies)

@app.route('/book', methods=['GET', 'POST'])
def book():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    showtime_id = request.args.get('showtime_id') or request.form.get('showtime_id')
    
    if not showtime_id:
        conn.close()
        return "Thiếu thông tin suất chiếu (showtime_id)", 400

    showtime = conn.execute("""
        SELECT s.*, m.title, m.id as movie_id, m.genre, m.duration, m.rating
        FROM showtimes s
        JOIN movies m ON s.movie_id = m.id
        WHERE s.id = ?
    """, (showtime_id,)).fetchone()

    if not showtime:
        conn.close()
        # 🔧 SỬA LỖI: Mã lỗi 44 không hợp lệ đổi thành 404 Not Found
        return "Suất chiếu không tồn tại", 404
        
    rows = conn.execute("""
        SELECT bs.seat_name 
        FROM booking_seats bs
        JOIN bookings b ON bs.booking_id = b.id
        WHERE b.showtime_id = ?
    """, (showtime_id,)).fetchall()
    booked_seats = [row['seat_name'] for row in rows]

    if request.method == 'POST':
        seats = request.form.get('seats', '').strip()
        quantity = request.form.get('quantity')
        error = None

        if not seats:
            error = "Chưa chọn ghế"
        elif "<script>" in seats.lower():
            error = "Dữ liệu không hợp lệ"
            logging.warning(f"Malicious script injection blocked from User ID: {session.get('user_id')}")
        elif not quantity or int(quantity) <= 0:
            error = "Số lượng ghế không hợp lệ"
        elif len(seats.split(",")) != int(quantity):
            error = "Dữ liệu ghế không khớp với số lượng"
        else:
            selected_list = [s.strip() for s in seats.split(",") if s.strip()]
            if any(s in booked_seats for s in selected_list):
                error = "Một trong các ghế bạn chọn vừa có người đặt. Vui lòng chọn lại."

        if error:
            conn.close()
            return render_template(
                "booking.html",
                error=error,
                showtime=showtime,
                booked_seats=booked_seats
            )

        total_price = showtime['price'] * int(quantity)

        try:
            # ⚡ Khởi tạo con trỏ cursor để thực hiện các thao tác ghi dữ liệu liên chuỗi
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            
            # ✅ CẬP NHẬT MỚI: Chỉ insert thông tin hóa đơn tổng gọn gàng vào bảng `bookings`
            cursor.execute("""
                INSERT INTO bookings(user_id, showtime_id, total_price, created_at) 
                VALUES (?, ?, ?, ?)
            """, (session['user_id'], showtime_id, total_price, vn_now()))
            
            # Trích xuất ID vừa tự sinh ra của hóa đơn này
            booking_id = cursor.lastrowid 

            # ✅ CẬP NHẬT MỚI: Tách mảng và insert từng ghế riêng lẻ vào bảng `booking_seats`
            selected_list = [s.strip() for s in seats.split(",") if s.strip()]
            for seat in selected_list:
                cursor.execute("""
                    INSERT INTO booking_seats(booking_id, seat_name) 
                    VALUES (?, ?)
                """, (booking_id, seat))

            conn.commit()
            add_log(
                session['user_id'],
                f"Đặt vé phim {showtime['title']}"
            )            
            return redirect(url_for('home'))
            
        except Exception as e:
            conn.execute("ROLLBACK;")
            logging.error(f"Booking database transaction error: {e}")
            error = "Có lỗi hệ thống xảy ra trong quá trình giữ chỗ. Vui lòng thử lại."
            return render_template("booking.html", error=error, showtime=showtime, booked_seats=booked_seats)
        finally:
            conn.close()

    conn.close()
    return render_template(
        'booking.html', 
        showtime=showtime, 
        booked_seats=booked_seats
    )

@app.route('/delete')
def delete():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.execute("DELETE FROM bookings WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    logging.info(f"User {user_id} deleted account")
    session.clear()
    return redirect(url_for('login', msg="deleted"))

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/tickets')
def tickets():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    bookings = conn.execute("""
        SELECT
            b.id,
            b.total_price,
            b.created_at,
            s.date,
            s.time,
            s.cinema,
            m.title,
            GROUP_CONCAT(bs.seat_name, ', ') as seat_list
        FROM bookings b
        JOIN showtimes s ON b.showtime_id = s.id
        JOIN movies m ON s.movie_id = m.id
        LEFT JOIN booking_seats bs ON bs.booking_id = b.id
        WHERE b.user_id = ?
        GROUP BY b.id
        ORDER BY b.created_at DESC
    """, (session['user_id'],)).fetchall()

    conn.close()

    return render_template('tickets.html', bookings=bookings)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (session['user_id'],)
    ).fetchone()

    success = None
    error = None

    if request.method == 'POST':
        new_email = request.form.get('email')

        if not new_email:
            error = "Email không được để trống"

        elif not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            error = "Email không hợp lệ"

        else:
            try:
                conn.execute(
                    "UPDATE users SET email=? WHERE id=?",
                    (new_email, session['user_id'])
                )

                conn.commit()

                success = "Cập nhật email thành công"

                logging.info(
                    f"User {session['user_id']} updated email"
                )

                user = conn.execute(
                    "SELECT * FROM users WHERE id=?",
                    (session['user_id'],)
                ).fetchone()

            except sqlite3.IntegrityError:
                error = "Email đã tồn tại"

    conn.close()

    return render_template(
        'account.html',
        user=user,
        success=success,
        error=error
    )

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    error = None
    success = None

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()

        # 1. Kiểm tra mật khẩu hiện tại
        if not bcrypt.checkpw(current_password.encode(), user['password']):
            error = "Mật khẩu hiện tại không đúng"
        
        # 2. Kiểm tra chính sách mật khẩu mới
        else:
            is_valid, msg = validate_password_policy(new_password)
            if not is_valid:
                error = msg
            
            # 3. Kiểm tra xem mật khẩu mới có trùng với mật khẩu cũ không
            elif bcrypt.checkpw(new_password.encode(), user['password']):
                error = "Mật khẩu mới không được trùng mật khẩu cũ"
            
            else:
                # Nếu mọi kiểm tra đều vượt qua, tiến hành update
                hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                conn.execute("UPDATE users SET password=? WHERE id=?", (hashed, session['user_id']))
                conn.commit()
                add_log(session['user_id'], "Đổi mật khẩu")
                success = "Đổi mật khẩu thành công"
                logging.info(f"User {session['user_id']} changed password")

        conn.close()

    return render_template('change_password.html', error=error, success=success)

@app.route('/admin')
def admin_dashboard():
    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM bookings")
    booking_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM movies")
    movie_count = c.fetchone()[0]

    conn.close()

    return render_template(
    'admin/admin_dashboard.html',
    user_count=user_count,
    booking_count=booking_count,
    movie_count=movie_count
)

@app.route('/admin/movies')
def admin_movies():

    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM movies")
    movies = c.fetchall()

    conn.close()

    return render_template(
        "admin/movies.html",
        movies=movies
    )

@app.route('/admin/movies/add', methods=['GET', 'POST'])
def admin_add_movie():
    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    if request.method == "POST":
        title = request.form["title"]
        genre = request.form["genre"]
        duration = request.form["duration"]
        rating = request.form["rating"]

        poster_file = request.files["poster"]

        filename = ""

        if poster_file and poster_file.filename != "":
            filename = secure_filename(poster_file.filename)
            poster_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            poster_file.save(poster_path)

        conn = get_db()
        c = conn.cursor()

        c.execute("""
            INSERT INTO movies(title, genre, duration, rating, poster)
            VALUES (?, ?, ?, ?, ?)
        """, (title, genre, duration, rating, filename))

        conn.commit()

        add_log(
            session['user_id'],
            f"Thêm phim {title}"
        )

        conn.close()

        flash("Thêm phim thành công", "success")

        return redirect(url_for("admin_movies"))

    return render_template("admin/add_movie.html")

@app.route('/admin/movies/delete/<int:movie_id>')
def admin_delete_movie(movie_id):

    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    conn = get_db()
    c = conn.cursor()

    c.execute("DELETE FROM movies WHERE id=?", (movie_id,))

    conn.commit()

    add_log(
        session['user_id'],
        f"Xóa phim ID {movie_id}"
    )

    conn.close()

    flash("Đã xóa phim", "success")

    return redirect(url_for("admin_movies"))

@app.route('/admin/movies/edit/<int:movie_id>', methods=['GET', 'POST'])
def admin_edit_movie(movie_id):

    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))
    
    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":

        title = request.form["title"]
        genre = request.form["genre"]
        duration = request.form["duration"]
        rating = request.form["rating"]

        poster_file = request.files["poster"]

        if poster_file and poster_file.filename != "":
            filename = secure_filename(poster_file.filename)

            poster_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            poster_file.save(poster_path)

            c.execute("""
                UPDATE movies
                SET title=?, genre=?, duration=?, rating=?, poster=?
                WHERE id=?
            """, (title, genre, duration, rating, filename, movie_id))

        else:
            c.execute("""
                UPDATE movies
                SET title=?, genre=?, duration=?, rating=?
                WHERE id=?
            """, (title, genre, duration, rating, movie_id))

        conn.commit()

        flash("Cập nhật phim thành công", "success")

        return redirect(url_for("admin_movies"))

    c.execute("SELECT * FROM movies WHERE id=?", (movie_id,))
    movie = c.fetchone()

    conn.close()

    return render_template("admin/edit_movie.html", movie=movie)

@app.route('/admin/showtimes')
def admin_showtimes():
    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    conn = get_db()
    # Giả sử bạn đang query lấy danh sách showtimes
    rows = conn.execute("SELECT s.*, m.title FROM showtimes s JOIN movies m ON s.movie_id = m.id").fetchall()
    
    showtimes = []
    for row in rows:
        s = dict(row)
        # Chuyển đổi YYYY-MM-DD sang DD/MM/YYYY
        dt = datetime.strptime(s['date'], '%Y-%m-%d')
        s['formatted_date'] = dt.strftime('%d/%m/%Y')
        showtimes.append(s)
        
    conn.close()
    return render_template('admin/showtimes.html', showtimes=showtimes)

@app.route('/admin/showtimes/add', methods=['GET', 'POST'])
def admin_add_showtime():

    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":

        movie_id = request.form["movie_id"]
        cinema = request.form["cinema"]
        hall = request.form["hall"]
        date = request.form["date"]
        time = request.form["time"]
        price = request.form["price"]

        c.execute("""
            INSERT INTO showtimes(
                movie_id,
                cinema,
                hall,
                date,
                time,
                price
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            movie_id,
            cinema,
            hall,
            date,
            time,
            price
        ))

        conn.commit()

        flash("Thêm suất chiếu thành công", "success")

        return redirect(url_for("admin_showtimes"))

    c.execute("SELECT * FROM movies")
    movies = c.fetchall()

    conn.close()

    return render_template(
        "admin/add_showtime.html",
        movies=movies
    )

@app.route('/admin/showtimes/edit/<int:showtime_id>', methods=['GET', 'POST'])
def admin_edit_showtime(showtime_id):

    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":

        movie_id = request.form["movie_id"]
        cinema = request.form["cinema"]
        hall = request.form["hall"]
        date = request.form["date"]
        time = request.form["time"]
        price = request.form["price"]

        c.execute("""
            UPDATE showtimes
            SET
                movie_id=?,
                cinema=?,
                hall=?,
                date=?,
                time=?,
                price=?
            WHERE id=?
        """, (
            movie_id,
            cinema,
            hall,
            date,
            time,
            price,
            showtime_id
        ))

        conn.commit()

        flash("Cập nhật suất chiếu thành công", "success")

        return redirect(url_for("admin_showtimes"))

    c.execute("SELECT * FROM showtimes WHERE id=?", (showtime_id,))
    showtime = c.fetchone()

    c.execute("SELECT * FROM movies")
    movies = c.fetchall()

    conn.close()

    return render_template(
        "admin/edit_showtime.html",
        showtime=showtime,
        movies=movies
    )

@app.route('/admin/showtimes/delete/<int:showtime_id>')
def admin_delete_showtime(showtime_id):

    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('home'))

    conn = get_db()
    c = conn.cursor()

    c.execute(
        "DELETE FROM showtimes WHERE id=?",
        (showtime_id,)
    )

    conn.commit()
    conn.close()

    flash("Đã xóa suất chiếu", "success")

    return redirect(url_for("admin_showtimes"))

@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'admin_system':
        return redirect(url_for('login'))

    # Lấy các tham số lọc từ URL
    search = request.args.get('search', '')
    role = request.args.get('role', '')
    status = request.args.get('status', '')

    conn = get_db()
    c = conn.cursor()

    # Xây dựng câu lệnh SQL cơ bản
    query = "SELECT * FROM users WHERE 1=1"
    params = []

    # Thêm điều kiện lọc vào query
    if search:
        query += " AND email LIKE ?"
        params.append(f'%{search}%')
    
    if role:
        query += " AND role = ?"
        params.append(role)
        
    if status == 'active':
        query += " AND is_active = 1"
    elif status == 'locked':
        query += " AND is_active = 0"

    query += " ORDER BY id ASC"
    
    # Thực thi với tham số đã chuẩn bị
    c.execute(query, params)
    users = c.fetchall()
    conn.close()

    return render_template('admin/users.html', users=users)

@app.route('/admin/user/toggle/<int:user_id>')
def toggle_user(user_id):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin_system':
        abort(403)

    conn = get_db()
    c = conn.cursor()

    # Không cho admin tự khóa chính mình
    if user_id == session['user_id']:
        conn.close()
        return redirect(url_for('admin_users'))

    c.execute("""
        SELECT is_active
        FROM users
        WHERE id=?
    """, (user_id,))

    user = c.fetchone()

    if user:
        new_status = 0 if user['is_active'] == 1 else 1

        c.execute("""
            UPDATE users
            SET is_active=?
            WHERE id=?
        """, (new_status, user_id))

        conn.commit()

        action_text = "Khóa tài khoản" if new_status == 0 else "Mở khóa tài khoản"

        add_log(
            session['user_id'],
            f"{action_text} user ID {user_id}"
        )

    conn.close()

    return redirect(url_for('admin_users'))

@app.route('/admin/user/role/<int:user_id>')
def change_role(user_id):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin_system':
        abort(403)

    conn = get_db()
    c = conn.cursor()

    # Không đổi role chính mình
    if user_id == session['user_id']:
        conn.close()
        return redirect(url_for('admin_users'))

    c.execute("""
        SELECT role
        FROM users
        WHERE id=?
    """, (user_id,))

    user = c.fetchone()

    if user:
        if user['role'] == 'user':
            new_role = 'admin_content'
        elif user['role'] == 'admin_content':
            new_role = 'user'
        else:
            conn.close()
            return redirect(url_for('admin_users'))

        c.execute("""
            UPDATE users
            SET role=?
            WHERE id=?
        """, (new_role, user_id))

        conn.commit()

        add_log(
            session['user_id'],
            f"Đổi role user ID {user_id} thành {new_role}"
        )

    conn.close()

    return redirect(url_for('admin_users'))

@app.route('/admin/user/reset/<int:user_id>')
def admin_reset_password(user_id):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin_system':
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()

    new_password = bcrypt.hashpw(
        "123456".encode(),
        bcrypt.gensalt()
    )
    
    c.execute("""
        UPDATE users
        SET password=?
        WHERE id=?
    """, (new_password, user_id))

    conn.commit()
    conn.close()

    return redirect(url_for('admin_users'))

@app.route('/admin/user/bookings/<int:user_id>')
def admin_user_bookings(user_id):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin_system':
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT
            bookings.id,
            bookings.total_price,
            bookings.created_at,

            movies.title,

            showtimes.date,
            showtimes.time

        FROM bookings

        JOIN showtimes
        ON bookings.showtime_id = showtimes.id

        JOIN movies
        ON showtimes.movie_id = movies.id

        WHERE bookings.user_id=?

        ORDER BY bookings.id DESC
    """, (user_id,))

    bookings = c.fetchall()

    conn.close()

    return render_template(
        'admin/user_bookings.html',
        bookings=bookings
    )

@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    # Kiểm tra xem user có phải admin không (nếu cần bảo mật)
    if session.get('role') != 'admin_system':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # Xóa booking trước để tránh lỗi khóa ngoại (nếu không dùng ON DELETE CASCADE)
    conn.execute("DELETE FROM bookings WHERE user_id = ?", (user_id,))
    # Xóa user
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/bookings') # Hoặc tên route tương ứng của bạn
def admin_bookings():
    if session.get('role') not in ['admin_content', 'admin_system']:
        return redirect(url_for('login'))

    conn = get_db()
    # Truy vấn lấy danh sách vé
    rows = conn.execute("""
        SELECT b.*, u.email, m.title, s.time, s.date 
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN showtimes s ON b.showtime_id = s.id
        JOIN movies m ON s.movie_id = m.id
        ORDER BY b.created_at DESC
    """).fetchall()

    bookings = []
    for row in rows:
        b = dict(row)
        
        # 1. Định dạng ngày suất chiếu
        dt_show = datetime.strptime(b['date'], '%Y-%m-%d')
        b['formatted_date'] = dt_show.strftime('%d/%m/%Y')
        
        # 2. Định dạng ngày đặt (created_at)
        # Giả sử created_at có dạng 'YYYY-MM-DD HH:MM:SS'
        dt_created = datetime.strptime(b['created_at'], '%Y-%m-%d %H:%M:%S')
        b['formatted_created_at'] = dt_created.strftime('%d/%m/%Y %H:%M') 
        
        bookings.append(b)
        
    conn.close()
    return render_template('admin/admin_bookings.html', bookings=bookings)

@app.route('/admin/logs')
def admin_logs():
    if session.get('role') != 'admin_system':
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()

    # Lấy dữ liệu
    c.execute("""
        SELECT logs.*, users.email FROM logs 
        LEFT JOIN users ON logs.user_id = users.id 
        ORDER BY logs.id DESC
    """)
    
    # Chuyển đổi định dạng ngày tháng trước khi gửi sang template
    logs = []
    for row in c.fetchall():
        log_dict = dict(row) # Chuyển sqlite3.Row thành dict để có thể chỉnh sửa
        dt = datetime.strptime(log_dict['created_at'], '%Y-%m-%d %H:%M:%S')
        log_dict['formatted_time'] = dt.strftime('%d/%m/%Y %H:%M:%S')
        logs.append(log_dict)

    conn.close()
    return render_template('admin/logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)