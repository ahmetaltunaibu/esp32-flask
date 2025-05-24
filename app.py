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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-123')
app.config['FIRMWARE_FOLDER'] = 'firmware'
app.config['ALLOWED_EXTENSIONS'] = {'bin'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

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
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS firmware_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT UNIQUE NOT NULL,
            release_notes TEXT,
            file_path TEXT,
            signature_path TEXT,
            is_active BOOLEAN DEFAULT 1,
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
    users_data = conn.execute('SELECT username, password, name, is_admin FROM users').fetchall()
    conn.close()
    
    users = {}
    for user in users_data:
        users[user['username']] = {
            'password': user['password'],
            'name': user['name'],
            'is_admin': user['is_admin']
        }
    
    # Varsayılan admin kullanıcısı yoksa ekle
    if 'admin' not in users:
        add_user('admin', 'admin123', 'Admin', True)
        users['admin'] = {
            'password': generate_password_hash('admin123'),
            'name': 'Admin',
            'is_admin': True
        }
    
    return users

def add_user(username, password, name, is_admin=False):
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO users (username, password, name, is_admin)
            VALUES (?, ?, ?, ?)
        ''', (username, generate_password_hash(password), name, is_admin))
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
        
        if not user_exists(session['username']):
            session.pop('username', None)
            flash('Kullanıcı bulunamadı. Lütfen tekrar giriş yapın', 'danger')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        users = get_users()
        if not users.get(session['username'], {}).get('is_admin', False):
            flash('Bu işlem için yetkiniz yok', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Ana Sayfa
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

# Firmware Yönetimi
@app.route('/firmware')
@login_required
@admin_required
def firmware_management():
    conn = get_db()
    versions = conn.execute('SELECT * FROM firmware_versions ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('firmware_management.html', versions=versions)

@app.route('/firmware/upload', methods=['POST'])
@login_required
@admin_required
def upload_firmware():
    if 'file' not in request.files:
        flash('Dosya seçilmedi', 'danger')
        return redirect(url_for('firmware_management'))
    
    file = request.files['file']
    version = request.form.get('version')
    release_notes = request.form.get('release_notes')
    
    if file.filename == '':
        flash('Dosya seçilmedi', 'danger')
        return redirect(url_for('firmware_management'))
    
    if not version:
        flash('Versiyon bilgisi gerekli', 'danger')
        return redirect(url_for('firmware_management'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"firmware_v{version}.bin")
        if not os.path.exists(app.config['FIRMWARE_FOLDER']):
            os.makedirs(app.config['FIRMWARE_FOLDER'])
        
        file_path = os.path.join(app.config['FIRMWARE_FOLDER'], filename)
        file.save(file_path)
        
        # İmzala
        signature = sign_firmware(file_path)
        sig_filename = f"firmware_v{version}.sig"
        sig_path = os.path.join(app.config['FIRMWARE_FOLDER'], sig_filename)
        
        with open(sig_path, 'wb') as f:
            f.write(signature)
        
        # Veritabanına kaydet
        conn = get_db()
        try:
            conn.execute('''
                INSERT INTO firmware_versions (version, release_notes, file_path, signature_path)
                VALUES (?, ?, ?, ?)
            ''', (version, release_notes, file_path, sig_path))
            conn.commit()
            flash('Firmware başarıyla yüklendi', 'success')
        except sqlite3.IntegrityError:
            flash('Bu versiyon zaten mevcut', 'danger')
        finally:
            conn.close()
    else:
        flash('Geçersiz dosya türü', 'danger')
    
    return redirect(url_for('firmware_management'))

@app.route('/firmware/download/<version>')
@login_required
def download_firmware(version):
    conn = get_db()
    firmware = conn.execute('''
        SELECT file_path FROM firmware_versions 
        WHERE version = ? AND is_active = 1
    ''', (version,)).fetchone()
    conn.close()
    
    if not firmware:
        flash('Firmware bulunamadı', 'danger')
        return redirect(url_for('index'))
    
    return send_file(firmware['file_path'], as_attachment=True)

@app.route('/firmware/check/<cihaz_id>')
@login_required
def check_firmware(cihaz_id):
    conn = get_db()
    latest = conn.execute('''
        SELECT version, release_notes FROM firmware_versions
        WHERE is_active = 1
        ORDER BY created_at DESC LIMIT 1
    ''').fetchone()
    conn.close()
    
    if not latest:
        return jsonify({"error": "No active firmware available"}), 404
    
    return jsonify({
        "current_version": "1.0.0",  # Cihazdan gelen versiyon
        "latest_version": latest['version'],
        "release_notes": latest['release_notes'],
        "url": url_for('download_firmware', version=latest['version'], _external=True),
        "signature_url": url_for('download_signature', version=latest['version'], _external=True)
    })

@app.route('/firmware/signature/<version>')
@login_required
def download_signature(version):
    conn = get_db()
    firmware = conn.execute('''
        SELECT signature_path FROM firmware_versions 
        WHERE version = ? AND is_active = 1
    ''', (version,)).fetchone()
    conn.close()
    
    if not firmware:
        return jsonify({"error": "Signature not found"}), 404
        
    return send_file(firmware['signature_path'], as_attachment=True)

# Kullanıcı Yönetimi Route'ları
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

# Veri Alım Route'ları
@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    if data and 'cihaz_id' in data:
        timestamp = int(time.time() * 1000)
        data['timestamp'] = timestamp
        data['firmware_version'] = data.get('firmware_version', '1.0.0')
        cihazlar[data['cihaz_id']] = data
        
        # Veritabanına kaydet
        conn = get_db()
        if 'veriler' in data:
            for veri in data['veriler']:
                conn.execute('''
                    INSERT INTO sensor_data 
                    (cihaz_id, cihaz_adi, konum, mac, sensor_id, sensor_value, sensor_unit, timestamp, firmware_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['cihaz_id'],
                    data.get('cihaz_adi', ''),
                    data.get('konum', ''),
                    data.get('mac', ''),
                    veri.get('sensor_id', ''),
                    veri.get('deger', 0),
                    veri.get('birim', ''),
                    timestamp,
                    data['firmware_version']
                ))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

# Cihaz Yönetim Route'ları
@app.route('/cihaz/<cihaz_id>')
@login_required
def cihaz_detay(cihaz_id):
    if cihaz_id in cihazlar:
        users = get_users()
        return render_template('cihaz_detay.html',
                            cihaz=cihazlar[cihaz_id],
                            now=int(time.time() * 1000),
                            user=users[session['username']])
    flash('Cihaz bulunamadı', 'danger')
    return redirect(url_for('index'))

@app.route('/gecmis/<cihaz_id>')
@login_required
def gecmis_veriler(cihaz_id):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sensor_filter = request.args.get('sensor_id')
    
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
    
    query = '''
        SELECT cihaz_id, cihaz_adi, konum, sensor_id, sensor_value, 
               sensor_unit, timestamp, created_at, firmware_version
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
            'Firmware Versiyon': veri['firmware_version'],
            'Kayıt Zamanı': veri['created_at']
        })
    
    df = pd.DataFrame(data)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Sensor Data', index=False)
    
    output.seek(0)
    
    cihaz_adi = cihazlar.get(cihaz_id, {}).get('cihaz_adi', cihaz_id)
    filename = f"{cihaz_adi}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

# Güncelleme Stream Route'u
@app.route('/firmware/update_stream')
@login_required
def firmware_update_stream():
    device_id = request.args.get('device_id')
    version = request.args.get('version')
    
    def generate():
        # Burada gerçek güncelleme süreci simüle ediliyor
        for i in range(0, 101, 5):
            time.sleep(0.5)
            yield f"data: {{\"progress\": {i}}}\n\n"
        
        time.sleep(1)
        yield "data: {\"status\": \"completed\", \"message\": \"Güncelleme başarıyla tamamlandı\"}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/firmware/cancel')
@login_required
def cancel_update():
    # Güncelleme iptal işlemleri
    return jsonify({"status": "cancelled"})

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def sign_firmware(file_path):
    # Örnek private key (gerçek uygulamada .env'de saklayın)
    private_key_pem = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAz7v5P5Z8vI3Jj9X9K2sL6v2Qx1Yt8uZ7W3bN1cX6y5MvG0P
    ... (gerçek private key buraya) ...
    -----END RSA PRIVATE KEY-----
    """
    
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    with open(file_path, 'rb') as f:
        firmware = f.read()
    
    signature = private_key.sign(
        firmware,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

if __name__ == '__main__':
    if not os.path.exists('firmware'):
        os.makedirs('firmware')
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=True)
