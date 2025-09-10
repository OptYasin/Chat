from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, make_response
from flask_socketio import SocketIO, send
import sqlite3, os, secrets, hashlib

app = Flask(__name__)
app.secret_key = "supersecret"
socketio = SocketIO(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Veritabanı Bağlantısı (thread-safe) ---
def get_db_connection():
    conn = sqlite3.connect("chat.db", check_same_thread=False)
    return conn

# --- Veritabanı ---
def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # Kullanıcılar tablosu
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )""")

    # Mesajlar tablosu
    c.execute("""CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        content TEXT,
        type TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Ana Sayfa ---
@app.route("/")
def index():
    return render_template("index.html")

# --- Kayıt ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            session["username"] = username
            return redirect(url_for("chat"))
        except sqlite3.IntegrityError:
            return "❌ Bu kullanıcı adı alınmış."
        finally:
            conn.close()

    return render_template("register.html")

# --- Giriş ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        remember = request.form.get("remember")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session["username"] = username
            resp = make_response(redirect(url_for("chat")))
            if remember:
                resp.set_cookie("username", username, max_age=7*24*60*60)  # 7 gün
            return resp
        else:
            return "❌ Kullanıcı adı veya şifre yanlış."

    # Cookie varsa → otomatik giriş
    saved_user = request.cookies.get("username")
    if saved_user:
        session["username"] = saved_user
        return redirect(url_for("chat"))

    return render_template("login.html")

# --- Sohbet Odası ---
@app.route("/chat")
def chat():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, content, type, timestamp FROM messages ORDER BY id ASC")
    messages = c.fetchall()
    conn.close()

    return render_template("chat.html", username=session["username"], messages=messages)

# --- Çıkış ---
@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("username")
    return resp

# --- Dosya Yükleme ---
@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return "Dosya yok", 400
    file = request.files["file"]
    filename = secrets.token_hex(8) + "_" + file.filename
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return f"/uploads/{filename}"

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# --- WebSocket Mesajlaşma ---
@socketio.on("message")
def handle_message(msg):
    username = session.get("username", "Anonim")

    # Mesajı DB’ye kaydet
    conn = get_db_connection()
    c = conn.cursor()
    msg_type = "file" if "/uploads/" in msg else "text"
    c.execute("INSERT INTO messages (username, content, type) VALUES (?, ?, ?)",
              (username, msg, msg_type))
    conn.commit()
    conn.close()

    # Yayınla (hemen DOM’a düşsün diye)
    send(f"{username}: {msg}", broadcast=True)

if __name__ == "__main__":
    init_db()
    socketio.run(app, debug=True)
    
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)

