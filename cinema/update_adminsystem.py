import sqlite3

# 1. Kết nối đúng file database của bạn
db_path = 'database.db' # Hãy đảm bảo tên file này giống với file trong app.py
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 2. Kiểm tra xem user có tồn tại không
cursor.execute("SELECT id, email, role FROM users WHERE email = 'admins@gmail.com'")
user = cursor.fetchone()

if user:
    print(f"Tìm thấy user: {user[1]} với role hiện tại: {user[2]}")
    
    # 3. Thực hiện UPDATE
    cursor.execute("UPDATE users SET role = 'admin_system' WHERE email = 'admins@gmail.com'")
    conn.commit()
    
    # 4. Kiểm tra lại ngay sau khi update
    cursor.execute("SELECT role FROM users WHERE email = 'admins@gmail.com'")
    new_role = cursor.fetchone()[0]
    print(f"Cập nhật thành công! Role mới của {user[1]} là: {new_role}")
else:
    print("LỖI: Không tìm thấy email 'admin@gmail.com' trong database.")
    print("Vui lòng kiểm tra lại xem email có bị viết sai chính tả hoặc thừa khoảng trắng không.")

conn.close()