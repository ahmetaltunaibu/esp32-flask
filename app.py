import os
import sqlite3
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file
from datetime import datetime, timedelta
import time
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd
import io
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-123')

# Veritabanı bağlantısı
def get_db():
    conn = sqlite3.connect('sensor_data.db')
    conn.row_factory = sqlite3.Row
    return conn

# Veritabanı tabloları oluştur
def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cihaz_id TEXT NOT NULL,
            cihaz_adi TEXT,
            konum TEXT,
            mac TEXT,
            sensor_id TEXT,
            sensor_value REAL,
            sensor_unit TEXT,
            timestamp INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Kullanıcı tablosu oluştur
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Uygulama başlatılırken veritabanını oluştur
init_db()

# Kullanıcı işlemleri
def get_users():
    conn = get_db()
    users_data = conn.execute('SELECT username, password, name FROM users').fetchall()
    conn.close()
    
    users = {}
    for user in users_data:
        users[user['username']] = {
            'password': user['password'],
            'name': user['name']
        }
    
    # Varsayılan admin kullanıcısı yoksa ekle
    if 'admin' not in users:
        add_user('admin', 'admin123', 'Admin')
        users['admin'] = {
            'password': generate_password_hash('admin123'),
            'name': 'Admin'
        }
    
    return users

def add_user(username, password, name):
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO users (username, password, name)
            VALUES (?, ?, ?)
        ''', (username, generate_password_hash(password), name))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def user_exists(username):
    conn = get_db()
    user = conn.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user is not None

# Cihaz verileri (anlık için)
cihazlar = {}

# Template filtreleri
def format_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%d.%m.%Y %H:%M:%S')
    except:
        return "N/A"

def format_date_only(timestamp):
    try:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%d.%m.%Y')
    except:
        return "N/A"

def format_time_only(timestamp):
    try:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%H:%M:%S')  
    except:
        return "N/A"

app.jinja_env.filters['format_timestamp'] = format_timestamp
app.jinja_env.filters['format_date_only'] = format_date_only
app.jinja_env.filters['format_time_only'] = format_time_only

# Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Lütfen giriş yapın', 'danger')
            return redirect(url_for('login'))
        
        # Kullanıcının hala var olup olmadığını kontrol et
        if not user_exists(session['username']):
            session.pop('username', None)
            flash('Kullanıcı bulunamadı. Lütfen tekrar giriş yapın', 'danger')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Rotlar
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = get_users()
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            flash('Başarıyla giriş yapıldı', 'success')
            return redirect(url_for('index'))
        flash('Kullanıcı adı veya şifre hatalı', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Başarıyla çıkış yapıldı', 'success')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        
        if not all([username, password, name]):
            flash('Tüm alanları doldurun', 'danger')
        elif user_exists(username):
            flash('Bu kullanıcı adı zaten alınmış', 'danger')
        else:
            if add_user(username, password, name):
                flash('Hesap oluşturuldu. Giriş yapabilirsiniz.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Hesap oluşturulurken hata oluştu', 'danger')
    return render_template('signup.html')

@app.route('/')
@login_required
def index():
    current_time = int(time.time() * 1000)
    users = get_users()
    return render_template('index.html',
                         cihazlar=cihazlar,
                         now=current_time,
                         user=users[session['username']],
                         users=users,
                         session=session)

@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    if data and 'cihaz_id' in data:
        timestamp = int(time.time() * 1000)
        data['timestamp'] = timestamp
        cihazlar[data['cihaz_id']] = data
        
        # Veritabanına kaydet
        conn = get_db()
        if 'veriler' in data:
            for veri in data['veriler']:
                conn.execute('''
                    INSERT INTO sensor_data 
                    (cihaz_id, cihaz_adi, konum, mac, sensor_id, sensor_value, sensor_unit, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['cihaz_id'],
                    data.get('cihaz_adi', ''),
                    data.get('konum', ''),
                    data.get('mac', ''),
                    veri.get('sensor_id', ''),
                    veri.get('deger', 0),
                    veri.get('birim', ''),
                    timestamp
                ))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route('/cihaz/<cihaz_id>')
@login_required
def cihaz_detay(cihaz_id):
    if cihaz_id in cihazlar:
        users = get_users()
        return render_template('cihaz_detay.html',
                             cihaz=cihazlar[cihaz_id],
                             user=users[session['username']])
    flash('Cihaz bulunamadı', 'danger')
    return redirect(url_for('index'))

@app.route('/gecmis/<cihaz_id>')
@login_required
def gecmis_veriler(cihaz_id):
    # Filtreleme parametreleri
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sensor_filter = request.args.get('sensor_id')
    
    # SQL sorgusu oluştur
    query = '''
        SELECT * FROM sensor_data 
        WHERE cihaz_id = ?
    '''
    params = [cihaz_id]
    
    if start_date:
        start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
        query += ' AND timestamp >= ?'
        params.append(start_timestamp)
    
    if end_date:
        end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
        query += ' AND timestamp < ?'
        params.append(end_timestamp)
    
    if sensor_filter:
        query += ' AND sensor_id = ?'
        params.append(sensor_filter)
    
    query += ' ORDER BY timestamp DESC LIMIT 1000'
    
    conn = get_db()
    veriler = conn.execute(query, params).fetchall()
    
    # Sensör listesi al
    sensors_query = '''
        SELECT DISTINCT sensor_id FROM sensor_data 
        WHERE cihaz_id = ? 
        ORDER BY sensor_id
    '''
    sensors = conn.execute(sensors_query, [cihaz_id]).fetchall()
    conn.close()
    
    cihaz_adi = cihazlar.get(cihaz_id, {}).get('cihaz_adi', cihaz_id)
    users = get_users()
    
    return render_template('gecmis_veriler.html',
                         veriler=veriler,
                         cihaz_id=cihaz_id,
                         cihaz_adi=cihaz_adi,
                         sensors=sensors,
                         start_date=start_date,
                         end_date=end_date,
                         sensor_filter=sensor_filter,
                         user=users[session['username']])

@app.route('/excel/<cihaz_id>')
@login_required  
def excel_export(cihaz_id):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sensor_filter = request.args.get('sensor_id')
    
    # Aynı filtrelemeyi uygula
    query = '''
        SELECT cihaz_id, cihaz_adi, konum, sensor_id, sensor_value, 
               sensor_unit, timestamp, created_at
        FROM sensor_data 
        WHERE cihaz_id = ?
    '''
    params = [cihaz_id]
    
    if start_date:
        start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
        query += ' AND timestamp >= ?'
        params.append(start_timestamp)
    
    if end_date:
        end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
        query += ' AND timestamp < ?'
        params.append(end_timestamp)
    
    if sensor_filter:
        query += ' AND sensor_id = ?'
        params.append(sensor_filter)
    
    query += ' ORDER BY timestamp DESC'
    
    conn = get_db()
    veriler = conn.execute(query, params).fetchall()
    conn.close()
    
    # DataFrame oluştur
    data = []
    for veri in veriler:
        data.append({
            'Cihaz ID': veri['cihaz_id'],
            'Cihaz Adı': veri['cihaz_adi'],
            'Konum': veri['konum'],
            'Sensör ID': veri['sensor_id'],
            'Değer': veri['sensor_value'],
            'Birim': veri['sensor_unit'],
            'Tarih': datetime.fromtimestamp(veri['timestamp'] / 1000).strftime('%d.%m.%Y'),
            'Saat': datetime.fromtimestamp(veri['timestamp'] / 1000).strftime('%H:%M:%S'),
            'Kayıt Zamanı': veri['created_at']
        })
    
    df = pd.DataFrame(data)
    
    # Excel dosyası oluştur
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Sensor Data', index=False)
    
    output.seek(0)
    
    # Dosya adı oluştur
    cihaz_adi = cihazlar.get(cihaz_id, {}).get('cihaz_adi', cihaz_id)
    filename = f"{cihaz_adi}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=True)
