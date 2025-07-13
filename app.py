import cv2
from deepface import DeepFace
import sqlite3
from datetime import datetime
import time
from flask import Flask, render_template, request, redirect, url_for, session
import bcrypt
import threading
import os

# Flask uygulaması
app = Flask(__name__)
app.secret_key = 'super-secret-key'  # Güvenli bir anahtar kullan

# Veritabanı oluşturma
def init_db():
    conn = sqlite3.connect('visitor_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            face_id TEXT,
            entry_time TEXT,
            exit_time TEXT,
            emotion_entry TEXT,
            emotion_exit TEXT,
            duration REAL,
            visit_count INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Kullanıcı kaydı (örnek admin kullanıcısı)
def register_user(username, password):
    conn = sqlite3.connect('visitor_data.db')
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Kullanıcı zaten mevcut")
    conn.close()

# Örnek admin kullanıcısı
register_user('admin', 'password123')

# Kamera ve analiz fonksiyonu
def analyze_face(frame):
    try:
        result = DeepFace.analyze(frame, actions=['emotion'], enforce_detection=False)
        emotion = result[0]['dominant_emotion']
        face_id = str(hash(str(frame)))  # Basit bir yüz ID'si (gerçek uygulamada DeepFace.verify kullanılabilir)
        return face_id, emotion
    except:
        return None, None

# Kamera akışını işleme
def process_camera():
    cap = cv2.VideoCapture(0)  # IP kamera için: 'rtsp://kamera_ip_adresi:554/stream'
    while True:
        ret, frame = cap.read()
        if not ret:
            continue

        face_id, emotion = analyze_face(frame)
        if face_id:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = sqlite3.connect('visitor_data.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO visitors (face_id, entry_time, emotion_entry, visit_count)
                VALUES (?, ?, ?, (SELECT IFNULL((SELECT visit_count + 1 FROM visitors WHERE face_id = ?), 1)))
            ''', (face_id, timestamp, emotion, face_id))
            conn.commit()
            # Çıkış zamanı (örnek: 5 saniye sonra çıkış varsayımı)
            time.sleep(5)
            cursor.execute('''
                UPDATE visitors SET exit_time = ?, emotion_exit = ?, duration = ?
                WHERE face_id = ? AND exit_time IS NULL
            ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), emotion, 5.0, face_id))
            conn.commit()
            conn.close()

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

# Flask rotaları
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('visitor_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        session['username'] = username
        return redirect(url_for('dashboard'))
    return "Giriş başarısız!"

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    conn = sqlite3.connect('visitor_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM visitors')
    data = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', data=data)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Kamera işlemini ayrı bir thread'de başlat
if __name__ == '__main__':
    camera_thread = threading.Thread(target=process_camera)
    camera_thread.daemon = True
    camera_thread.start()
    app.run(debug=True, host='0.0.0.0', port=5000)