#deneme satır
import os
import sqlite3
import logging
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file, Response
from datetime import datetime, timedelta
import time
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd
import io
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend
from apscheduler.schedulers.background import BackgroundScheduler
import shutil
import zipfile
from werkzeug.utils import secure_filename
import json
from datetime import datetime, timedelta
import pytz


# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['FIRMWARE_FOLDER'] = 'firmware'
app.config['ALLOWED_EXTENSIONS'] = {'bin'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# app.py'nin en üstünde, Flask setup'tan sonra
app.permanent_session_lifetime = timedelta(hours=24)

@app.before_request
def make_session_permanent():
    session.permanent = True


# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 🔑 Sabit Private Key kullan (kalıcı çözüm)
FIXED_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyX02NRFPfvod4
YWvHl4eNCA30OYvO4qQVAAakliBzC4inbc/D8OIB5HQ//uMyu1n96872TKUc59ic
7UDLKUpznBiXl0U2j7CdrK4Fj4brhJWhAPfIaqNsIyAuMQ/nNe6jEounKi6WBMd+
2Kty2VcJUOScudMqm1Ska+6vJYsYjkDpOXAehrv+VgS2B8BLjWb4d6UXlFFMyShd
K/i0W1MhIimAazvgmS9sm4fVLoX1ps6s7QL5APnVNt2aBiNXRkQ/4DATeAw6NrgA
AqmgRbLPGOxiq9wszxh4DJpG/Bwhx+wW+Fr409ktidzA2zEPVLc47dZgoYs8AxBJ
6CVyt97fAgMBAAECggEACLuKt+5O7ubMihO265wbCkgJKtpAYn4NC2wnZxpkd01q
wMuq/sxFvFL7cACiDeNHOhu3064X7UzaeYBSCkA4wWU0fQNuY4fwXR/Nmz8WG2Sv
0KST/O9fldU4Z5qGTUsCJmCrjqENi9GrFKY16pcCYFXiA1xDntPg9nXERzXe0/Ja
AJu2HrGx4cpVkI2b15BnqrCyVDu+Nf2ZBTHPH6LOYRC5L3v6byx3HTIv+rjp9Ewz
DbIRXFoqJUwhTN+d1vnR1t4D5KFRBiVuMN/eWqAxwu5ZIgw4TKsjzc6q2f0eGnR2
5tBGRxEbwUjZTRgzvcY/kOKujQIvkgJ8xXeepkTwHQKBgQDfRIK1zlBFZdEJ6DKC
OUfa/qQyTCwnj24dVCwPvG/GofRt94O9Ccssy1Dgvd+IHwION/wg9BS77VhJSCwm
4ynKRmlOBytElIQgZbBmSrtrFCIAVxQvObCS+7ruXW5ARA6vBvKx0UXeJSojevrG
S+PDbSqR3dMxQv4h5tL34gJ4TQKBgQDMhdGZIQhrYwEaAplUemAZCJkAiyv3p23f
SbisflQmVqNcK+XyM1O2TMWhytcYjPJv9YJ92gjiynIPUBAa9xIUMJwLIJbZzVDn
mx1OL46jPLsn2tBWWUC2es4rCsnP7pfmCBGzlFrPjod9wW2deHstjUTZOIEmdDUZ
y50gpgFJ2wKBgQC5o+F7AZzE1y/EqQi2NqKEeI5WM/fSvPO19zLbsrbN1gPDG7ay
C96f1D3fYIDoUcAHyo0daVWEHIj4BcaQXvl0cq9EbbmQQFzMA0F1DFZhZlAPMFhc
G/+xdxWq9IyjavM6nPBW4cbSOtyau7qf/qHW8IIg3uynXSipT5/C9G1RUQKBgFJk
rrXD6wJoFi+GUIMJ8eDj58+iQYo5tze3GWDUW84+JP2i6bYTG2xbrVqqvtCzJ5AX
FgTha6cB68VjebmDQ5NCqfqJnHwODMPhZ4LyAcKdWsCJlFjVCA77lkccx4SvGB6h
rY/s+lCXmNn+rMw9l1IYkV35N35oXmQP9TML7YT1AoGBAMqsIF37730UcuAVhi0B
k4o5JKCcT+GcxtaAKJOgXkI+nAeJQ54IAFbB3rM8WbeObC6KRNsczwLAFMmE4JZo
7flrv1fZ62DyRcf/qzjT/G+GQb/tS4GrNVnmMZDRMF6/KmRDfeHykAGiDPQl+IWR
tCn7yg2wEZnfCpxiCB0bBtv2
-----END PRIVATE KEY-----"""

# Private key'i sabit PEM'den yükle
try:
    private_key = serialization.load_pem_private_key(
        FIXED_PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend()
    )
    logger.info("🔑 Sabit Private Key başarıyla yüklendi")
except Exception as e:
    logger.error(f"❌ Private Key yükleme hatası: {str(e)}")
    # Fallback: Yeni key generate et
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    logger.warning("⚠️ Yeni Private Key generate edildi")

# Private key'i PEM formatında al
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Public key'i türet
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

logger.info("\n📋 ESP32 için Public Key:")
logger.info("=" * 50)
logger.info(public_pem.decode('utf-8'))
logger.info("=" * 50)
logger.info("Bu Public Key'i ESP32 koduna kopyala!")

# Sabit admin kullanıcısı
HARDCODED_ADMIN = {
    "username": "admin",
    "password": "admin123",
    "is_admin": True
}

# Database Setup
def get_db():
    conn = sqlite3.connect('sensor_data.db', isolation_level=None)  # ← Bu kısmı ekle
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA synchronous = FULL')  # ← Bu satırı ekle
    conn.execute('PRAGMA journal_mode = WAL')   # ← Bu satırı ekle
    return conn

def init_db():
    with get_db() as conn:
        # Mevcut sensor verileri tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT NOT NULL,
                sensor_id TEXT NOT NULL,
                sensor_value REAL NOT NULL,
                sensor_unit TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Cihazlar tablosu - FABRİKA EKLENDİ
        conn.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                cihaz_id TEXT PRIMARY KEY,
                cihaz_adi TEXT NOT NULL,
                fabrika_adi TEXT,                    -- 🏭 YENİ ALAN
                konum TEXT NOT NULL,
                mac TEXT NOT NULL,
                firmware_version TEXT NOT NULL,
                target_firmware TEXT,
                last_seen INTEGER NOT NULL,
                online_status BOOLEAN DEFAULT 0,
                ip_address TEXT,
                device_type TEXT DEFAULT 'default',
                update_channel TEXT DEFAULT 'stable',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_update DATETIME
            )
        ''')
        
        # Mevcut tabloya sütun ekleme (eğer yoksa)
        try:
            conn.execute('ALTER TABLE devices ADD COLUMN fabrika_adi TEXT')
            logger.info("✅ fabrika_adi sütunu eklendi")
        except sqlite3.OperationalError:
            logger.info("ℹ️ fabrika_adi sütunu zaten mevcut")
        
        # Kullanıcılar tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )
        ''')
        
        # Firmware versiyonları tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS firmware_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE NOT NULL,
                release_notes TEXT,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                signature_path TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                is_verified BOOLEAN DEFAULT 0,
                compatible_devices TEXT DEFAULT 'all',
                uploader_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users(id)
            )
        ''')
        
        # Güncelleme geçmişi tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT NOT NULL,
                old_version TEXT NOT NULL,
                new_version TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                initiated_by INTEGER,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (cihaz_id) REFERENCES devices(cihaz_id),
                FOREIGN KEY (initiated_by) REFERENCES users(id)
            )
        ''')
        
        # Cihaz grupları tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS device_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Cihaz-grup ilişkileri
        conn.execute('''
            CREATE TABLE IF NOT EXISTS device_group_mapping (
                group_id INTEGER NOT NULL,
                cihaz_id TEXT NOT NULL,
                PRIMARY KEY (group_id, cihaz_id),
                FOREIGN KEY (group_id) REFERENCES device_groups(id) ON DELETE CASCADE,
                FOREIGN KEY (cihaz_id) REFERENCES devices(cihaz_id) ON DELETE CASCADE
            )
        ''')
        
        # Varsayılan admin kullanıcısı
        try:
            conn.execute('''
                INSERT INTO users (username, password, name, is_admin)
                VALUES (?, ?, ?, ?)
            ''', (
                'admin',
                generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'securepassword123')),
                'System Admin',
                1
            ))
        except sqlite3.IntegrityError:
            pass
        
        conn.commit()
        logger.info("✅ Database initialized with factory support")

init_db()

# Template Filters
@app.template_filter('format_timestamp')
def format_timestamp(timestamp):
    try:
        # Türkiye saat dilimini ayarla
        turkey_tz = pytz.timezone('Europe/Istanbul')
        
        # Unix timestamp'i datetime'a çevir (milisaniye varsa böl)
        if timestamp > 1000000000000:  # Milisaniye formatında
            dt = datetime.fromtimestamp(timestamp / 1000, tz=turkey_tz)
        else:  # Saniye formatında
            dt = datetime.fromtimestamp(timestamp, tz=turkey_tz)
        
        return dt.strftime('%d.%m.%Y %H:%M:%S')
    except:
        return "N/A"

@app.template_filter('format_date_only')
def format_date_only(timestamp):
    try:
        turkey_tz = pytz.timezone('Europe/Istanbul')
        
        if timestamp > 1000000000000:
            dt = datetime.fromtimestamp(timestamp / 1000, tz=turkey_tz)
        else:
            dt = datetime.fromtimestamp(timestamp, tz=turkey_tz)
        
        return dt.strftime('%d.%m.%Y')
    except:
        return "N/A"

@app.template_filter('format_time_only')
def format_time_only(timestamp):
    try:
        turkey_tz = pytz.timezone('Europe/Istanbul')
        
        if timestamp > 1000000000000:
            dt = datetime.fromtimestamp(timestamp / 1000, tz=turkey_tz)
        else:
            dt = datetime.fromtimestamp(timestamp, tz=turkey_tz)
        
        return dt.strftime('%H:%M:%S')
    except:
        return "N/A"

# Authentication Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Lütfen giriş yapın', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            if request.is_json:
                return jsonify({"error": "Bu işlem için admin yetkisi gerekli"}), 403
            flash('Bu işlem için ADMIN yetkisi gerekiyor!', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Context Processors
@app.context_processor
def inject_user():
    if 'username' not in session:
        return dict(current_user=None, is_admin=False)
    
    # Session kontrol et
    username = session.get('username')
    is_admin = session.get('is_admin', False)
    
    if not username:
        return dict(current_user=None, is_admin=False)
    
    return dict(
        current_user=dict(name=username), 
        is_admin=is_admin
    )


# Routes
# Yedekleme ve geri yükleme route'ları

@app.route('/admin/database')
@login_required
@admin_required
def database_management():
    """Veritabanı yönetim sayfası"""
    try:
        with get_db() as conn:
            # Veritabanı istatistikleri
            stats = {
                'devices': conn.execute('SELECT COUNT(*) as count FROM devices').fetchone()['count'],
                'sensor_data': conn.execute('SELECT COUNT(*) as count FROM sensor_data').fetchone()['count'],
                'users': conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count'],
                'firmware_versions': conn.execute('SELECT COUNT(*) as count FROM firmware_versions').fetchone()['count'],
                'update_history': conn.execute('SELECT COUNT(*) as count FROM update_history').fetchone()['count']
            }
            
            # Veritabanı boyutu
            db_size = os.path.getsize('sensor_data.db') if os.path.exists('sensor_data.db') else 0
            stats['db_size'] = db_size
            
            # Son yedekleme tarihi (eğer varsa)
            backup_dir = 'backups'
            last_backup = None
            if os.path.exists(backup_dir):
                backups = [f for f in os.listdir(backup_dir) if f.endswith('.zip')]
                if backups:
                    backups.sort(reverse=True)
                    last_backup = backups[0]
            
            return render_template('database_management.html', stats=stats, last_backup=last_backup)
            
    except Exception as e:
        flash(f'Veritabanı bilgileri alınırken hata: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/admin/backup', methods=['POST'])
@login_required
@admin_required
def create_backup():
    """Tam veritabanı yedeği oluştur"""
    try:
        # Yedek klasörü oluştur
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        # Firmware klasörü de var mı kontrol et
        firmware_dir = app.config['FIRMWARE_FOLDER']
        
        # Zaman damgası ile dosya adı oluştur
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"database_backup_{timestamp}.zip"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Veritabanı dosyasını ekle
            if os.path.exists('sensor_data.db'):
                zipf.write('sensor_data.db', 'sensor_data.db')
                logger.info("✅ Database file added to backup")
            
            # Firmware dosyalarını ekle
            if os.path.exists(firmware_dir):
                for root, dirs, files in os.walk(firmware_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, '.')
                        zipf.write(file_path, arc_path)
                logger.info(f"✅ Firmware files added to backup")
            
            # Yedekleme bilgilerini JSON olarak ekle
            backup_info = {
                'backup_date': timestamp,
                'backup_type': 'full_backup',
                'created_by': session.get('username'),
                'database_size': os.path.getsize('sensor_data.db') if os.path.exists('sensor_data.db') else 0,
                'firmware_count': len([f for f in os.listdir(firmware_dir) if f.endswith('.bin')]) if os.path.exists(firmware_dir) else 0
            }
            
            zipf.writestr('backup_info.json', json.dumps(backup_info, indent=2))
        
        file_size = os.path.getsize(backup_path)
        
        flash(f'Yedekleme başarılı! Dosya: {backup_filename} ({file_size/1024/1024:.1f} MB)', 'success')
        logger.info(f"✅ Backup created: {backup_filename} ({file_size} bytes)")
        
        return jsonify({
            'success': True,
            'filename': backup_filename,
            'size': file_size,
            'message': 'Yedekleme başarıyla oluşturuldu'
        })
        
    except Exception as e:
        logger.error(f"❌ Backup creation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/admin/download_backup/<filename>')
@login_required
@admin_required
def download_backup(filename):
    """Yedek dosyasını indir"""
    try:
        backup_dir = 'backups'
        file_path = os.path.join(backup_dir, secure_filename(filename))
        
        if not os.path.exists(file_path):
            flash('Yedek dosyası bulunamadı', 'danger')
            return redirect(url_for('database_management'))
        
        logger.info(f"📥 Backup download: {filename} by {session.get('username')}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip'
        )
        
    except Exception as e:
        logger.error(f"❌ Backup download error: {str(e)}")
        flash(f'Dosya indirilemedi: {str(e)}', 'danger')
        return redirect(url_for('database_management'))

@app.route('/admin/restore', methods=['POST'])
@login_required
@admin_required
def restore_database():
    """Veritabanını yedekten geri yükle"""
    if 'backup_file' not in request.files:
        return jsonify({'success': False, 'error': 'Dosya seçilmedi'}), 400
    
    file = request.files['backup_file']
    
    if file.filename == '' or not file.filename.endswith('.zip'):
        return jsonify({'success': False, 'error': 'Geçerli bir ZIP dosyası seçin'}), 400
    
    try:
        # Geçici dosya adı oluştur
        temp_filename = secure_filename(file.filename)
        temp_path = os.path.join('temp', temp_filename)
        
        # Temp klasörü oluştur
        os.makedirs('temp', exist_ok=True)
        
        # Dosyayı kaydet
        file.save(temp_path)
        
        # ZIP dosyasını kontrol et ve çıkart
        with zipfile.ZipFile(temp_path, 'r') as zipf:
            # ZIP içeriğini kontrol et
            file_list = zipf.namelist()
            
            if 'sensor_data.db' not in file_list:
                os.remove(temp_path)
                return jsonify({'success': False, 'error': 'Geçersiz yedek dosyası (sensor_data.db bulunamadı)'}), 400
            
            # Backup info varsa oku
            backup_info = {}
            if 'backup_info.json' in file_list:
                with zipf.open('backup_info.json') as info_file:
                    backup_info = json.loads(info_file.read().decode('utf-8'))
            
            # Mevcut veritabanını yedekle (güvenlik için)
            if os.path.exists('sensor_data.db'):
                safety_backup = f"sensor_data_before_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                shutil.copy2('sensor_data.db', safety_backup)
                logger.info(f"🛡️ Safety backup created: {safety_backup}")
            
            # Scheduler'ı durdur (veritabanı işlemleri için)
            try:
                if 'scheduler' in globals():
                    scheduler.shutdown(wait=False)
                    logger.info("⏸️ Scheduler stopped for restore")
            except:
                pass
            
            # Veritabanını geri yükle
            zipf.extract('sensor_data.db', '.')
            logger.info("✅ Database restored")
            
            # Firmware dosyalarını geri yükle
            firmware_files = [f for f in file_list if f.startswith('firmware/')]
            if firmware_files:
                for firmware_file in firmware_files:
                    zipf.extract(firmware_file, '.')
                logger.info(f"✅ {len(firmware_files)} firmware files restored")
        
        # Geçici dosyayı temizle
        os.remove(temp_path)
        
        # Scheduler'ı yeniden başlat
        try:
            if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
                scheduler = BackgroundScheduler()
                scheduler.add_job(update_device_status, 'interval', minutes=1)
                scheduler.start()
                logger.info("▶️ Scheduler restarted after restore")
        except:
            pass
        
        logger.info(f"✅ Database restore completed by {session.get('username')}")
        
        return jsonify({
            'success': True,
            'message': 'Veritabanı başarıyla geri yüklendi',
            'backup_info': backup_info
        })
        
    except Exception as e:
        logger.error(f"❌ Database restore error: {str(e)}")
        
        # Geçici dosyayı temizle
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return jsonify({
            'success': False,
            'error': f'Geri yükleme hatası: {str(e)}'
        }), 500

@app.route('/admin/list_backups')
@login_required
@admin_required
def list_backups():
    """Mevcut yedekleri listele"""
    try:
        backup_dir = 'backups'
        backups = []
        
        if os.path.exists(backup_dir):
            for filename in os.listdir(backup_dir):
                if filename.endswith('.zip'):
                    file_path = os.path.join(backup_dir, filename)
                    stat = os.stat(file_path)
                    
                    # Backup info'yu oku (varsa)
                    backup_info = {}
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zipf:
                            if 'backup_info.json' in zipf.namelist():
                                with zipf.open('backup_info.json') as info_file:
                                    backup_info = json.loads(info_file.read().decode('utf-8'))
                    except:
                        pass
                    
                    backups.append({
                        'filename': filename,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime).strftime('%d.%m.%Y %H:%M:%S'),
                        'info': backup_info
                    })
        
        # Tarihe göre sırala (en yeni önce)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({'backups': backups})
        
    except Exception as e:
        logger.error(f"❌ List backups error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete_backup/<filename>', methods=['DELETE'])
@login_required
@admin_required
def delete_backup(filename):
    """Yedek dosyasını sil"""
    try:
        backup_dir = 'backups'
        file_path = os.path.join(backup_dir, secure_filename(filename))
        
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'Dosya bulunamadı'}), 404
        
        os.remove(file_path)
        logger.info(f"🗑️ Backup deleted: {filename} by {session.get('username')}")
        
        return jsonify({
            'success': True,
            'message': f'{filename} başarıyla silindi'
        })
        
    except Exception as e:
        logger.error(f"❌ Delete backup error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500



# Background Tasks - fonksiyon tanımlaması
def update_device_status():
    with app.app_context():
        try:
            current_time_ms = int(time.time() * 1000)
            threshold = current_time_ms - 120000  # 2 minutes
            
            with get_db() as conn:
                cursor = conn.execute('''
                    UPDATE devices 
                    SET online_status = CASE 
                        WHEN last_seen >= ? AND last_seen > 0 THEN 1 
                        ELSE 0 
                    END
                ''', (threshold,))
                
                rows_affected = cursor.rowcount
                conn.commit()
                
                logger.info(f"🔄 Device status updated: {rows_affected} devices")
                
        except Exception as e:
            logger.error(f"❌ Error updating device status: {str(e)}")

# Index route'unu da güncelleyin
@app.route('/')
@login_required
def index():
    with get_db() as conn:
        # Gerçek zamanlı online durum hesaplama
        current_time_ms = int(time.time() * 1000)
        threshold = current_time_ms - 120000  # 2 dakika
        
        # Tüm cihazları getir - İSİM SIRASINA GÖRE SIRALA
        cihazlar_raw = conn.execute('''
            SELECT *,
                CASE 
                    WHEN last_seen >= ? AND last_seen > 0 THEN 1 
                    ELSE 0 
                END as real_online_status
            FROM devices 
            ORDER BY cihaz_adi ASC
        ''', (threshold,)).fetchall()
        
        # Her cihaz için sensor verilerini al
        cihazlar = []
        for cihaz in cihazlar_raw:
            cihaz_dict = dict(cihaz)
            
            # En son sensor değerlerini getir (cihaz detayındaki gibi)
            veriler = conn.execute('''
                SELECT s1.* FROM sensor_data s1
                JOIN (
                    SELECT sensor_id, MAX(timestamp) as max_timestamp
                    FROM sensor_data
                    WHERE cihaz_id = ?
                    GROUP BY sensor_id
                ) s2 ON s1.sensor_id = s2.sensor_id AND s1.timestamp = s2.max_timestamp
                ORDER BY s1.sensor_id
            ''', (cihaz['cihaz_id'],)).fetchall()
            
            # Sensor verilerini dictionary'ye çevir
            for veri in veriler:
                sensor_key = f"sensor_{veri['sensor_id']}"
                cihaz_dict[sensor_key] = veri['sensor_value']
            
            # Özel sensor değerleri için kontrol et
            cihaz_dict['sensor_oee'] = None
            cihaz_dict['sensor_active_time'] = None  
            cihaz_dict['sensor_total_time'] = None
            cihaz_dict['sensor_total_products'] = None
            
            # Debug: Hangi sensor_id'ler var görelim
            sensor_ids = [veri['sensor_id'] for veri in veriler]
            logger.info(f"🔍 {cihaz['cihaz_adi']} sensor_ids: {sensor_ids}")
            
            for veri in veriler:
                sensor_id = veri['sensor_id'].lower()
                logger.info(f"   Kontrol ediliyor: {veri['sensor_id']} = {veri['sensor_value']}")
                
                if sensor_id == 'oee':
                    cihaz_dict['sensor_oee'] = veri['sensor_value']
                    logger.info(f"   ✅ OEE bulundu: {veri['sensor_value']}")
                elif sensor_id == 'aktif_calisma':
                    cihaz_dict['sensor_active_time'] = veri['sensor_value']
                    logger.info(f"   ✅ Aktif çalışma bulundu: {veri['sensor_value']}")
                elif sensor_id == 'toplam_calisma':
                    cihaz_dict['sensor_total_time'] = veri['sensor_value'] 
                    logger.info(f"   ✅ Toplam çalışma bulundu: {veri['sensor_value']}")
                elif sensor_id == 'toplam_urun':
                    cihaz_dict['sensor_total_products'] = veri['sensor_value']
                    logger.info(f"   ✅ Toplam ürün bulundu: {veri['sensor_value']}")
                # Yedek aramalar
                elif 'oee' in sensor_id:
                    if not cihaz_dict['sensor_oee']:
                        cihaz_dict['sensor_oee'] = veri['sensor_value']
                elif 'aktif' in sensor_id and 'calis' in sensor_id:
                    if not cihaz_dict['sensor_active_time']:
                        cihaz_dict['sensor_active_time'] = veri['sensor_value']
                elif 'toplam' in sensor_id and 'calis' in sensor_id:
                    if not cihaz_dict['sensor_total_time']:
                        cihaz_dict['sensor_total_time'] = veri['sensor_value']
                elif 'toplam' in sensor_id and 'urun' in sensor_id:
                    if not cihaz_dict['sensor_total_products']:
                        cihaz_dict['sensor_total_products'] = veri['sensor_value']
            
            cihazlar.append(cihaz_dict)
        
        # Debug logları
        logger.info(f"📊 Cihaz Durumu Debug:")
        logger.info(f"   Şu anki zaman: {current_time_ms}")
        logger.info(f"   Threshold (2 dk önce): {threshold}")
        logger.info(f"   Toplam cihaz: {len(cihazlar)}")
        
        online_count = 0
        for cihaz in cihazlar:
            if cihaz['real_online_status']:
                online_count += 1
                fabrika_info = f" - {cihaz.get('fabrika_adi', 'Bilinmeyen Fabrika')}" if cihaz.get('fabrika_adi') else ""
                logger.info(f"   🟢 {cihaz['cihaz_adi']}{fabrika_info}: ONLINE (OEE: {cihaz.get('sensor_oee', 'N/A')})")
            else:
                fabrika_info = f" - {cihaz.get('fabrika_adi', 'Bilinmeyen Fabrika')}" if cihaz.get('fabrika_adi') else ""
                logger.info(f"   🔴 {cihaz['cihaz_adi']}{fabrika_info}: OFFLINE")
        
        logger.info(f"   📈 Online: {online_count}, Offline: {len(cihazlar) - online_count}")
        
        return render_template('index.html', cihazlar=cihazlar)

# Also update the background task to be more robust
def update_device_status():
    """Cihazların online/offline durumunu güncelle"""
    with app.app_context():
        try:
            current_time_ms = int(time.time() * 1000)
            threshold = current_time_ms - 120000  # 2 dakika (120 saniye = 120000 milisaniye)
            
            with get_db() as conn:
                # Online durumunu güncelle
                cursor = conn.execute('''
                    UPDATE devices 
                    SET online_status = CASE 
                        WHEN last_seen >= ? AND last_seen > 0 THEN 1 
                        ELSE 0 
                    END
                ''', (threshold,))
                
                rows_updated = cursor.rowcount
                
                # Debug için sayıları al
                online_count = conn.execute('''
                    SELECT COUNT(*) as count FROM devices 
                    WHERE last_seen >= ? AND last_seen > 0
                ''', (threshold,)).fetchone()['count']
                
                total_count = conn.execute('SELECT COUNT(*) as count FROM devices').fetchone()['count']
                
                conn.commit()
                
                logger.info(f"🔄 Cihaz durumları güncellendi: {online_count}/{total_count} online ({rows_updated} kayıt güncellendi)")
                
        except Exception as e:
            logger.error(f"❌ Cihaz durumu güncelleme hatası: {str(e)}")


# Alternative debug route to check device status manually
@app.route('/debug/device_status')
@login_required
@admin_required
def debug_device_status():
    """Debug endpoint to check device status calculation"""
    current_time_ms = int(time.time() * 1000)
    threshold = current_time_ms - 120000  # 2 minutes
    
    with get_db() as conn:
        devices = conn.execute('''
            SELECT 
                cihaz_id,
                cihaz_adi,
                last_seen,
                online_status,
                CASE 
                    WHEN last_seen >= ? AND last_seen > 0 THEN 1 
                    ELSE 0 
                END as calculated_online_status,
                CASE 
                    WHEN last_seen > 0 THEN (? - last_seen) / 1000 
                    ELSE -1 
                END as seconds_since_last_seen
            FROM devices 
            ORDER BY last_seen DESC
        ''', (threshold, current_time_ms)).fetchall()
    
    debug_info = {
        'current_time_ms': current_time_ms,
        'threshold': threshold,
        'devices': [dict(device) for device in devices]
    }
    
    return jsonify(debug_info)
    with get_db() as conn:
        # Tüm cihazları getir (online ve offline)
        cihazlar = conn.execute('''
            SELECT *,
                CASE 
                    WHEN last_seen >= ? THEN 1 
                    ELSE 0 
                END as real_online_status
            FROM devices 
            ORDER BY last_seen DESC
        ''', (int(time.time() * 1000) - 120000,)).fetchall()
        
        return render_template('index.html', cihazlar=cihazlar)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Sabit kullanıcı kontrolü
        if username == HARDCODED_ADMIN["username"] and password == HARDCODED_ADMIN["password"]:
            session['username'] = username
            session['is_admin'] = True
            flash('ADMIN olarak giriş yapıldı!', 'success')
            return redirect(url_for('index'))
        
        # Veritabanı kontrolü
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                session['is_admin'] = bool(user['is_admin'])
                flash('Giriş başarılı!', 'success')
                return redirect(url_for('index'))
        
        flash('Kullanıcı adı/şifre hatalı', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
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
            return redirect(url_for('signup'))
        
        try:
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO users (username, password, name)
                    VALUES (?, ?, ?)
                ''', (username, generate_password_hash(password), name))
                conn.commit()
                flash('Hesap oluşturuldu. Giriş yapabilirsiniz.', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Bu kullanıcı adı zaten alınmış', 'danger')
    
    return render_template('signup.html')

@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    if not data or 'cihaz_id' not in data:
        return jsonify({"status": "error", "message": "Geçersiz veri"}), 400
    
    timestamp = int(time.time() * 1000)
    data['timestamp'] = timestamp
    data['firmware_version'] = data.get('firmware_version', '1.0.0')
    
    try:
        with get_db() as conn:
            # Update device info - FABRİKA EKLENDİ
            conn.execute('''
                INSERT OR REPLACE INTO devices 
                (cihaz_id, cihaz_adi, fabrika_adi, konum, mac, firmware_version, last_seen, online_status, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
            ''', (
                data['cihaz_id'],
                data.get('cihaz_adi', 'Bilinmeyen'),
                data.get('fabrika_adi', 'Belirtilmemiş'),  # 🏭 YENİ ALAN
                data.get('konum', 'Bilinmeyen'),
                data.get('mac', ''),
                data['firmware_version'],
                timestamp,
                request.remote_addr
            ))
            
            # Save sensor data
            if 'veriler' in data:
                for veri in data['veriler']:
                    conn.execute('''
                        INSERT INTO sensor_data 
                        (cihaz_id, sensor_id, sensor_value, sensor_unit, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        data['cihaz_id'],
                        veri.get('sensor_id', ''),
                        veri.get('deger', 0),
                        veri.get('birim', ''),
                        timestamp
                    ))
            
            conn.commit()
            return jsonify({"status": "success", "message": "Veri alındı"})
    
    except Exception as e:
        logger.error(f"Data receive error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/cihaz/<cihaz_id>')
@login_required
def cihaz_detay(cihaz_id):
    try:
        with get_db() as conn:
            cihaz = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not cihaz:
                flash('Cihaz bulunamadı', 'danger')
                return redirect(url_for('index'))
            
            # Get latest sensor values
            veriler = conn.execute('''
                SELECT s1.* FROM sensor_data s1
                JOIN (
                    SELECT sensor_id, MAX(timestamp) as max_timestamp
                    FROM sensor_data
                    WHERE cihaz_id = ?
                    GROUP BY sensor_id
                ) s2 ON s1.sensor_id = s2.sensor_id AND s1.timestamp = s2.max_timestamp
                ORDER BY s1.sensor_id
            ''', (cihaz_id,)).fetchall()
            
            sensor_data = {}
            for veri in veriler:
                sensor_data[veri['sensor_id']] = {
                    'deger': veri['sensor_value'],
                    'birim': veri['sensor_unit'],
                    'timestamp': veri['timestamp']
                }
            
            return render_template('cihaz_detay.html', cihaz=cihaz, sensor_data=sensor_data)
    
    except Exception as e:
        flash(f'Veri alınırken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))


@app.route('/gecmis/<cihaz_id>')
@login_required
def gecmis_veriler(cihaz_id):
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        sensor_filter = request.args.get('sensor_id')
        limit = request.args.get('limit', 'all')  # Varsayılan: tümü
        
        with get_db() as conn:
            cihaz = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not cihaz:
                flash('Cihaz bulunamadı', 'danger')
                return redirect(url_for('index'))
            
            # Veritabanındaki min/max tarihleri al
            date_range = conn.execute('''
                SELECT 
                    MIN(timestamp) as min_timestamp,
                    MAX(timestamp) as max_timestamp
                FROM sensor_data 
                WHERE cihaz_id = ?
            ''', (cihaz_id,)).fetchone()
            
            # Varsayılan tarih aralığını belirle
            default_start_date = None
            default_end_date = None
            
            if date_range and date_range['min_timestamp'] and date_range['max_timestamp']:
                # Min tarihi al
                min_date = datetime.fromtimestamp(date_range['min_timestamp'] / 1000)
                max_date = datetime.fromtimestamp(date_range['max_timestamp'] / 1000)
                
                default_start_date = min_date.strftime('%Y-%m-%d')
                default_end_date = max_date.strftime('%Y-%m-%d')
            
            # Eğer tarih parametresi yoksa varsayılanları kullan
            if not start_date and default_start_date:
                start_date = default_start_date
            if not end_date and default_end_date:
                end_date = default_end_date
            
            # Base query
            query = 'SELECT * FROM sensor_data WHERE cihaz_id = ?'
            params = [cihaz_id]
            
            # Tarih filtreleri
            if start_date:
                start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
                query += ' AND timestamp >= ?'
                params.append(start_timestamp)
            
            if end_date:
                end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
                query += ' AND timestamp < ?'
                params.append(end_timestamp)
            
            # Sensör filtresi
            if sensor_filter:
                query += ' AND sensor_id = ?'
                params.append(sensor_filter)
            
            # Sıralama
            query += ' ORDER BY timestamp DESC'
            
            # Limit (sadece gerekirse)
            if limit and limit != 'all':
                try:
                    limit_num = int(limit)
                    query += f' LIMIT {limit_num}'
                except ValueError:
                    pass  # Geçersiz limit değeri, sınır koyma
            
            veriler = conn.execute(query, params).fetchall()
            
            # Tüm mevcut sensörleri al
            sensors = conn.execute('''
                SELECT DISTINCT sensor_id FROM sensor_data 
                WHERE cihaz_id = ? 
                ORDER BY sensor_id
            ''', (cihaz_id,)).fetchall()
            
            return render_template('gecmis_veriler.html',
                                veriler=veriler,
                                cihaz_id=cihaz_id,
                                cihaz_adi=cihaz['cihaz_adi'],
                                cihaz=cihaz,
                                sensors=sensors,
                                start_date=start_date,
                                end_date=end_date,
                                sensor_filter=sensor_filter,
                                current_limit=limit,
                                default_start_date=default_start_date,
                                default_end_date=default_end_date)
    
    except Exception as e:
        flash(f'Geçmiş veriler alınırken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        sensor_filter = request.args.get('sensor_id')
        limit = request.args.get('limit', 'all')  # Varsayılan: tümü
        
        with get_db() as conn:
            cihaz = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not cihaz:
                flash('Cihaz bulunamadı', 'danger')
                return redirect(url_for('index'))
            
            # Base query
            query = 'SELECT * FROM sensor_data WHERE cihaz_id = ?'
            params = [cihaz_id]
            
            # Tarih filtreleri
            if start_date:
                start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
                query += ' AND timestamp >= ?'
                params.append(start_timestamp)
            
            if end_date:
                end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
                query += ' AND timestamp < ?'
                params.append(end_timestamp)
            
            # Sensör filtresi
            if sensor_filter:
                query += ' AND sensor_id = ?'
                params.append(sensor_filter)
            
            # Sıralama
            query += ' ORDER BY timestamp DESC'
            
            # Limit (sadece gerekirse)
            if limit and limit != 'all':
                try:
                    limit_num = int(limit)
                    query += f' LIMIT {limit_num}'
                except ValueError:
                    pass  # Geçersiz limit değeri, sınır koyma
            
            veriler = conn.execute(query, params).fetchall()
            
            # Tüm mevcut sensörleri al
            sensors = conn.execute('''
                SELECT DISTINCT sensor_id FROM sensor_data 
                WHERE cihaz_id = ? 
                ORDER BY sensor_id
            ''', (cihaz_id,)).fetchall()
            
            return render_template('gecmis_veriler.html',
                                veriler=veriler,
                                cihaz_id=cihaz_id,
                                cihaz_adi=cihaz['cihaz_adi'],
                                cihaz=cihaz,
                                sensors=sensors,
                                start_date=start_date,
                                end_date=end_date,
                                sensor_filter=sensor_filter,
                                current_limit=limit)
    
    except Exception as e:
        flash(f'Geçmiş veriler alınırken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        sensor_filter = request.args.get('sensor_id')  # Tek sensör seçimi (basit versiyon)
        
        with get_db() as conn:
            cihaz = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not cihaz:
                flash('Cihaz bulunamadı', 'danger')
                return redirect(url_for('index'))
            
            # Base query
            query = 'SELECT * FROM sensor_data WHERE cihaz_id = ?'
            params = [cihaz_id]
            
            # Tarih filtreleri
            if start_date:
                start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
                query += ' AND timestamp >= ?'
                params.append(start_timestamp)
            
            if end_date:
                end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
                query += ' AND timestamp < ?'
                params.append(end_timestamp)
            
            # Sensör filtresi
            if sensor_filter:
                query += ' AND sensor_id = ?'
                params.append(sensor_filter)
            
            query += ' ORDER BY timestamp DESC LIMIT 1000'
            veriler = conn.execute(query, params).fetchall()
            
            # Tüm mevcut sensörleri al
            sensors = conn.execute('''
                SELECT DISTINCT sensor_id FROM sensor_data 
                WHERE cihaz_id = ? 
                ORDER BY sensor_id
            ''', (cihaz_id,)).fetchall()
            
            return render_template('gecmis_veriler.html',
                                veriler=veriler,
                                cihaz_id=cihaz_id,
                                cihaz_adi=cihaz['cihaz_adi'],
                                cihaz=cihaz,  # Bu satır eksikti!
                                sensors=sensors,
                                start_date=start_date,
                                end_date=end_date,
                                sensor_filter=sensor_filter)
    
    except Exception as e:
        flash(f'Geçmiş veriler alınırken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/excel/<cihaz_id>')
@login_required  
def excel_export(cihaz_id):
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        sensor_filter = request.args.get('sensor_id')
        limit = request.args.get('limit', 'all')
        
        query = '''
            SELECT cihaz_id, sensor_id, sensor_value, sensor_unit, timestamp
            FROM sensor_data 
            WHERE cihaz_id = ?
        '''
        params = [cihaz_id]
        
        # Tarih filtreleri
        if start_date:
            start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
            query += ' AND timestamp >= ?'
            params.append(start_timestamp)
        
        if end_date:
            end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
            query += ' AND timestamp < ?'
            params.append(end_timestamp)
        
        # Sensör filtresi
        if sensor_filter:
            query += ' AND sensor_id = ?'
            params.append(sensor_filter)
        
        # Sıralama
        query += ' ORDER BY timestamp DESC'
        
        # Limit
        if limit and limit != 'all':
            try:
                limit_num = int(limit)
                query += f' LIMIT {limit_num}'
            except ValueError:
                pass
        
        with get_db() as conn:
            veriler = conn.execute(query, params).fetchall()
            cihaz_adi = conn.execute('SELECT cihaz_adi FROM devices WHERE cihaz_id = ?', 
                                   (cihaz_id,)).fetchone()['cihaz_adi']
            
            data = []
            for veri in veriler:
                data.append({
                    'Cihaz ID': veri['cihaz_id'],
                    'Sensör ID': veri['sensor_id'],
                    'Değer': veri['sensor_value'],
                    'Birim': veri['sensor_unit'],
                    'Tarih': datetime.fromtimestamp(veri['timestamp'] / 1000).strftime('%d.%m.%Y'),
                    'Saat': datetime.fromtimestamp(veri['timestamp'] / 1000).strftime('%H:%M:%S')
                })
            
            df = pd.DataFrame(data)
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Sensor Data', index=False)
            
            output.seek(0)
            
            # Dosya adını limit bilgisi ile oluştur
            limit_suffix = f"_{limit}" if limit != 'all' else "_all"
            filename = f"{cihaz_adi}{limit_suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=filename
            )
    
    except Exception as e:
        flash(f'Excel oluşturulurken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('gecmis_veriler', cihaz_id=cihaz_id))
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        selected_sensors = request.args.getlist('sensor_ids')  # Çoklu seçim
        limit = request.args.get('limit', '1000')
        order = request.args.get('order', 'desc')
        
        query = '''
            SELECT cihaz_id, sensor_id, sensor_value, sensor_unit, timestamp
            FROM sensor_data 
            WHERE cihaz_id = ?
        '''
        params = [cihaz_id]
        
        # Tarih filtreleri
        if start_date:
            start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
            query += ' AND timestamp >= ?'
            params.append(start_timestamp)
        
        if end_date:
            end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
            query += ' AND timestamp < ?'
            params.append(end_timestamp)
        
        # Çoklu sensör filtresi
        if selected_sensors:
            placeholders = ','.join(['?'] * len(selected_sensors))
            query += f' AND sensor_id IN ({placeholders})'
            params.extend(selected_sensors)
        
        # Sıralama
        if order == 'asc':
            query += ' ORDER BY timestamp ASC'
        else:
            query += ' ORDER BY timestamp DESC'
        
        # Limit
        if limit != 'all':
            query += f' LIMIT {int(limit)}'
        
        with get_db() as conn:
            veriler = conn.execute(query, params).fetchall()
            cihaz_adi = conn.execute('SELECT cihaz_adi FROM devices WHERE cihaz_id = ?', 
                                   (cihaz_id,)).fetchone()['cihaz_adi']
            
            data = []
            for veri in veriler:
                data.append({
                    'Cihaz ID': veri['cihaz_id'],
                    'Sensör ID': veri['sensor_id'],
                    'Değer': veri['sensor_value'],
                    'Birim': veri['sensor_unit'],
                    'Tarih': datetime.fromtimestamp(veri['timestamp'] / 1000).strftime('%d.%m.%Y'),
                    'Saat': datetime.fromtimestamp(veri['timestamp'] / 1000).strftime('%H:%M:%S')
                })
            
            df = pd.DataFrame(data)
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Sensor Data', index=False)
            
            output.seek(0)
            
            # Dosya adını sensör seçimine göre oluştur
            sensor_suffix = ""
            if selected_sensors:
                if len(selected_sensors) == 1:
                    sensor_suffix = f"_{selected_sensors[0]}"
                else:
                    sensor_suffix = f"_{len(selected_sensors)}_sensors"
            
            filename = f"{cihaz_adi}{sensor_suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=filename
            )
    
    except Exception as e:
        flash(f'Excel oluşturulurken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('gecmis_veriler', cihaz_id=cihaz_id))

# Firmware Management
@app.route('/firmware')
@login_required
@admin_required
def firmware_management():
    with get_db() as conn:
        versions = conn.execute('SELECT * FROM firmware_versions ORDER BY created_at DESC').fetchall()
        cihazlar = conn.execute('SELECT * FROM devices ORDER BY cihaz_adi').fetchall()
    return render_template('firmware_management.html', versions=versions, cihazlar=cihazlar)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def sign_firmware(file_path):
    """
    🔐 Firmware dosyasını sabit private key ile imzala
    """
    try:
        with open(file_path, 'rb') as f:
            firmware = f.read()
        
        # Global private_key değişkenini kullan
        signature = private_key.sign(
            firmware,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        logger.info(f"✅ Firmware imzalandı: {os.path.basename(file_path)}")
        return signature
        
    except Exception as e:
        logger.error(f"❌ Firmware imzalama hatası: {str(e)}")
        raise

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
    
    if not file or file.filename == '':
        flash('Dosya seçilmedi', 'danger')
        return redirect(url_for('firmware_management'))
    
    if not version:
        flash('Versiyon bilgisi gerekli', 'danger')
        return redirect(url_for('firmware_management'))
    
    if not allowed_file(file.filename):
        flash('Geçersiz dosya türü', 'danger')
        return redirect(url_for('firmware_management'))
    
    try:
        os.makedirs(app.config['FIRMWARE_FOLDER'], exist_ok=True)
        
        filename = secure_filename(f"firmware_v{version}.bin")
        file_path = os.path.join(app.config['FIRMWARE_FOLDER'], filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)
        
        # Sign firmware
        signature = sign_firmware(file_path)
        sig_filename = f"firmware_v{version}.sig"
        sig_path = os.path.join(app.config['FIRMWARE_FOLDER'], sig_filename)
        
        with open(sig_path, 'wb') as f:
            f.write(signature)
        
        # Save to database
        with get_db() as conn:
            try:
                conn.execute('''
                    INSERT INTO firmware_versions (version, release_notes, file_path, file_size, signature_path)
                    VALUES (?, ?, ?, ?, ?)
                ''', (version, release_notes, file_path, file_size, sig_path))
                conn.commit()
                flash('Firmware başarıyla yüklendi', 'success')
                logger.info(f"✅ Firmware uploaded: v{version}")
            except sqlite3.IntegrityError:
                flash('Bu versiyon zaten mevcut', 'danger')
        
        return redirect(url_for('firmware_management'))
    
    except Exception as e:
        logger.error(f"Firmware upload error: {str(e)}")
        flash(f'Firmware yüklenirken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('firmware_management'))

# 🚀 DÜZELTME: Firmware atama endpoint'i - TAMAMEN YENİ
@app.route('/assign_firmware', methods=['POST'])
@admin_required
def assign_firmware():
    """
    🎯 Cihaza firmware ata - debug mesajlarıyla
    """
    data = request.get_json()
    logger.info(f"🔍 Assign firmware request: {data}")
    
    if not data or 'device_id' not in data or 'version' not in data:
        logger.error("❌ Invalid request data")
        return jsonify({"error": "Geçersiz istek - device_id ve version gerekli"}), 400

    device_id = data['device_id'] 
    version = data['version']
    
    logger.info(f"📱 Device ID: {device_id}")
    logger.info(f"💾 Version: {version}")

    try:
        with get_db() as conn:
            # Transaction başlat
            conn.execute('BEGIN IMMEDIATE')
            logger.info("🔄 Transaction started")
            
            # 1. Firmware versiyonunu kontrol et
            firmware = conn.execute('''
                SELECT version, file_path, file_size, is_active 
                FROM firmware_versions 
                WHERE version = ?
            ''', (version,)).fetchone()

            logger.info(f"🔍 Firmware found: {firmware is not None}")
            if firmware:
                logger.info(f"📋 Firmware details: version={firmware['version']}, active={firmware['is_active']}, file_exists={os.path.exists(firmware['file_path'])}")

            if not firmware:
                conn.rollback()
                return jsonify({"error": f"Firmware v{version} bulunamadı"}), 404
                
            if not firmware['is_active']:
                conn.rollback()
                return jsonify({"error": f"Firmware v{version} aktif değil"}), 400

            # 2. Cihazı kontrol et  
            device = conn.execute('''
                SELECT cihaz_id, cihaz_adi, firmware_version, target_firmware
                FROM devices 
                WHERE cihaz_id = ?
            ''', (device_id,)).fetchone()

            logger.info(f"🔍 Device found: {device is not None}")
            if device:
                logger.info(f"📋 Device details: id={device['cihaz_id']}, name={device['cihaz_adi']}, current={device['firmware_version']}, target={device['target_firmware']}")

            if not device:
                conn.rollback()
                return jsonify({"error": f"Cihaz bulunamadı: {device_id}"}), 404

            # 3. Güncelleme gerekli mi kontrol et
            if device['firmware_version'] == version:
                conn.rollback()
                return jsonify({"error": f"Cihaz zaten v{version} kullanıyor"}), 400

            # 4. Target firmware'i güncelle
            logger.info(f"🔄 Updating device {device['cihaz_id']} with target firmware {firmware['version']}")
            
            cursor = conn.execute('''
                UPDATE devices 
                SET target_firmware = ?, last_update = CURRENT_TIMESTAMP
                WHERE cihaz_id = ?
            ''', (firmware['version'], device['cihaz_id']))

            rows_affected = cursor.rowcount
            logger.info(f"📊 Update result - rows affected: {rows_affected}")

            if rows_affected == 0:
                conn.rollback()
                return jsonify({"error": "Cihaz güncellenemedi - rowcount = 0"}), 500

            # 5. Güncelleme geçmişine kaydet
            conn.execute('''
                INSERT INTO update_history (cihaz_id, old_version, new_version, status, timestamp)
                VALUES (?, ?, ?, 'pending', ?)
            ''', (device['cihaz_id'], device['firmware_version'], firmware['version'], int(time.time() * 1000)))

            # 6. Sonucu doğrula
            updated_device = conn.execute('''
                SELECT target_firmware FROM devices WHERE cihaz_id = ?
            ''', (device['cihaz_id'],)).fetchone()
            
            logger.info(f"✅ Verification - target_firmware: {updated_device['target_firmware'] if updated_device else 'NOT FOUND'}")

            if not updated_device or updated_device['target_firmware'] != firmware['version']:
                conn.rollback()
                return jsonify({"error": "Güncelleme doğrulanamadı"}), 500

            # 7. Transaction'ı commit et
            conn.commit()
            logger.info("✅ Transaction committed successfully")

            # 8. Başarı sonucu döndür
            result = {
                "success": True,
                "message": f"{device['cihaz_adi']} cihazına v{firmware['version']} başarıyla atandı",
                "device": device['cihaz_adi'],
                "device_id": device['cihaz_id'],
                "version": firmware['version'],
                "current_version": device['firmware_version'],
                "file_size": firmware['file_size'],
                "debug": {
                    "rows_affected": rows_affected,
                    "verified_target": updated_device['target_firmware']
                }
            }
            
            logger.info(f"🎉 Assignment successful: {result}")
            return jsonify(result)

    except sqlite3.Error as e:
        logger.error(f"❌ Database error: {str(e)}")
        try:
            conn.rollback()
        except:
            pass
        return jsonify({
            "error": "Veritabanı hatası",
            "details": str(e)
        }), 500
    except Exception as e:
        logger.error(f"❌ Unexpected error: {str(e)}")
        try:
            conn.rollback()
        except:
            pass
        return jsonify({
            "error": "Beklenmeyen hata",
            "details": str(e)
        }), 500

# 🔍 Firmware kontrol endpoint'i - debug mesajlarıyla
@app.route('/firmware/check/<cihaz_id>')
def check_firmware(cihaz_id):
    """
    🔍 Cihaz için firmware güncellemesi kontrol et
    """
    api_key = request.args.get('api_key')
    if api_key != "GUVENLI_ANAHTAR_123":
        return jsonify({"error": "Yetkisiz erişim"}), 401

    try:
        with get_db() as conn:
            # Cihaz ve target firmware bilgilerini al
            device_query = '''
                SELECT 
                    d.cihaz_id,
                    d.cihaz_adi,
                    d.firmware_version as current_version, 
                    d.target_firmware,
                    f.file_path, 
                    f.signature_path, 
                    f.release_notes,
                    f.file_size,
                    f.is_active as firmware_is_active
                FROM devices d
                LEFT JOIN firmware_versions f ON d.target_firmware = f.version
                WHERE d.cihaz_id = ?
            '''
            
            device = conn.execute(device_query, (cihaz_id,)).fetchone()

            # DEBUG logging
            logger.info(f"🔍 Firmware check for device: {cihaz_id}")
            logger.info(f"📱 Device found: {device is not None}")
            
            if device:
                logger.info(f"📋 Device details:")
                logger.info(f"   - Name: {device['cihaz_adi']}")
                logger.info(f"   - Current Version: {device['current_version']}")
                logger.info(f"   - Target Firmware: {device['target_firmware']}")
                logger.info(f"   - File Path: {device['file_path']}")
                logger.info(f"   - Firmware Active: {device['firmware_is_active']}")
                logger.info(f"   - File Exists: {os.path.exists(device['file_path']) if device['file_path'] else False}")
            else:
                logger.warning("❌ Device not found!")

            if not device:
                return jsonify({
                    "update_available": False,
                    "current_version": "1.0.0",
                    "latest_version": "1.0.0",
                    "debug": "Device not found"
                })

            current_version = device['current_version'] or "1.0.0"
            target_version = device['target_firmware']

            logger.info(f"🔄 Version comparison: Current='{current_version}', Target='{target_version}'")

            # Güncelleme kontrol koşulları
            update_needed = (
                target_version and                                    # Target version var
                target_version != current_version and                 # Farklı versiyonlar
                device['file_path'] and                              # Dosya yolu var
                os.path.exists(device['file_path']) and              # Dosya gerçekten var
                device['firmware_is_active']                         # Firmware aktif
            )

            logger.info(f"📊 Update check result: {update_needed}")

            if update_needed:
                base_url = request.url_root.rstrip('/')
                
                result = {
                    "update_available": True,
                    "current_version": current_version,
                    "latest_version": target_version,
                    "version": target_version,
                    "firmware_url": f"{base_url}/firmware/download/{target_version}?api_key={api_key}",
                    "signature_url": f"{base_url}/firmware/signature/{target_version}?api_key={api_key}",
                    "file_size": device['file_size'] or 0,
                    "release_notes": device['release_notes'] or "Yeni sürüm güncellemesi",
                    "debug": f"Update available: {current_version} -> {target_version}"
                }
                
                logger.info(f"✅ Update available: {current_version} -> {target_version}")
                return jsonify(result)

            logger.info(f"ℹ️  No update needed")
            
            return jsonify({
                "update_available": False,
                "current_version": current_version,
                "latest_version": target_version or current_version,
                "debug": f"No update needed. Current: {current_version}, Target: {target_version}"
            })

    except Exception as e:
        logger.error(f"❌ Firmware check error: {str(e)}")
        return jsonify({
            "error": str(e),
            "update_available": False,
            "debug": f"Exception occurred: {str(e)}"
        }), 500

@app.route('/firmware/delete', methods=['POST'])
@admin_required
def delete_firmware():
    """
    🗑️ Firmware versiyonunu sil (dosya + database)
    """
    data = request.get_json()
    if not data or 'version' not in data:
        return jsonify({"error": "Versiyon bilgisi gerekli"}), 400
    
    version = data['version']
    logger.info(f"🗑️ Delete firmware request: v{version}")
    
    try:
        with get_db() as conn:
            # Firmware bilgilerini al
            firmware = conn.execute('''
                SELECT id, version, file_path, signature_path, is_active
                FROM firmware_versions 
                WHERE version = ?
            ''', (version,)).fetchone()
            
            if not firmware:
                return jsonify({"error": f"Firmware v{version} bulunamadı"}), 404
            
            # Aktif firmware silinmesin
            if firmware['is_active']:
                return jsonify({"error": "Aktif firmware silinemez. Önce başka bir firmware'i aktif edin"}), 400
            
            # Cihazlarda kullanılıyor mu kontrol et
            devices_using = conn.execute('''
                SELECT COUNT(*) as count FROM devices 
                WHERE target_firmware = ? OR firmware_version = ?
            ''', (version, version)).fetchone()
            
            if devices_using['count'] > 0:
                return jsonify({
                    "error": f"Bu firmware {devices_using['count']} cihaz tarafından kullanılıyor. Önce cihazları güncelleyin"
                }), 400
            
            # Fiziksel dosyaları sil
            files_deleted = []
            files_failed = []
            
            if firmware['file_path'] and os.path.exists(firmware['file_path']):
                try:
                    os.remove(firmware['file_path'])
                    files_deleted.append(firmware['file_path'])
                    logger.info(f"✅ Deleted file: {firmware['file_path']}")
                except Exception as e:
                    files_failed.append(f"firmware: {str(e)}")
                    logger.error(f"❌ Failed to delete file {firmware['file_path']}: {str(e)}")
            
            if firmware['signature_path'] and os.path.exists(firmware['signature_path']):
                try:
                    os.remove(firmware['signature_path'])
                    files_deleted.append(firmware['signature_path'])
                    logger.info(f"✅ Deleted signature: {firmware['signature_path']}")
                except Exception as e:
                    files_failed.append(f"signature: {str(e)}")
                    logger.error(f"❌ Failed to delete signature {firmware['signature_path']}: {str(e)}")
            
            # Database'den sil
            conn.execute('DELETE FROM firmware_versions WHERE version = ?', (version,))
            conn.commit()
            
            logger.info(f"✅ Firmware v{version} deleted successfully")
            
            return jsonify({
                "success": True,
                "message": f"Firmware v{version} başarıyla silindi",
                "files_deleted": files_deleted,
                "files_failed": files_failed
            })
            
    except Exception as e:
        logger.error(f"❌ Firmware delete error: {str(e)}")
        return jsonify({
            "error": "Firmware silinirken hata oluştu",
            "details": str(e)
        }), 500

@app.route('/firmware/set_status', methods=['POST'])
@admin_required
def set_firmware_status():
    """
    🔄 Firmware aktif/pasif durumunu değiştir
    """
    data = request.get_json()
    if not data or 'version' not in data or 'is_active' not in data:
        return jsonify({"error": "Geçersiz istek"}), 400
    
    version = data['version']  
    is_active = bool(data['is_active'])
    
    try:
        with get_db() as conn:
            if is_active:
                # Diğer tüm firmware'leri pasif yap
                conn.execute('UPDATE firmware_versions SET is_active = 0')
            
            # Seçilen firmware'in durumunu değiştir
            conn.execute('''
                UPDATE firmware_versions 
                SET is_active = ?
                WHERE version = ?
            ''', (is_active, version))
            
            conn.commit()
            
            status_text = "aktif" if is_active else "pasif"
            logger.info(f"✅ Firmware v{version} {status_text} edildi")
            
            return jsonify({
                "success": True,
                "message": f"Firmware v{version} {status_text} edildi"
            })
            
    except Exception as e:
        logger.error(f"❌ Firmware status change error: {str(e)}")
        return jsonify({
            "error": "Durum değiştirilemedi",
            "details": str(e)
        }), 500

@app.route('/firmware/download/<version>')
def download_firmware(version):
    api_key = request.args.get('api_key')
    if api_key != "GUVENLI_ANAHTAR_123":
        return jsonify({"error": "Yetkisiz erişim"}), 401
        
    with get_db() as conn:
        firmware = conn.execute('''
            SELECT file_path FROM firmware_versions 
            WHERE version = ?
        ''', (version,)).fetchone()
        
        if not firmware or not os.path.exists(firmware['file_path']):
            return jsonify({"error": "Firmware bulunamadı"}), 404
        
        logger.info(f"📥 Firmware download: v{version}")
        return send_file(firmware['file_path'], as_attachment=True)

@app.route('/firmware/signature/<version>')
def download_signature(version):
    api_key = request.args.get('api_key')
    if api_key != "GUVENLI_ANAHTAR_123":
        return jsonify({"error": "Yetkisiz erişim"}), 401
        
    with get_db() as conn:
        firmware = conn.execute('''
            SELECT signature_path FROM firmware_versions 
            WHERE version = ?
        ''', (version,)).fetchone()
        
        if not firmware or not os.path.exists(firmware['signature_path']):
            return jsonify({"error": "Signature bulunamadı"}), 404
            
        logger.info(f"🔐 Signature download: v{version}")
        return send_file(firmware['signature_path'], as_attachment=True)

# 🔧 DEBUG ENDPOINT'LERİ
@app.route('/debug/device/<cihaz_id>')
@admin_required
def debug_device_firmware(cihaz_id):
    """🔍 Cihaz firmware durumunu debug et"""
    with get_db() as conn:
        # Cihaz bilgilerini al
        device_query = '''
            SELECT 
                d.cihaz_id,
                d.cihaz_adi,
                d.firmware_version as current_version, 
                d.target_firmware,
                d.online_status,
                d.last_seen,
                f.file_path, 
                f.signature_path, 
                f.release_notes,
                f.file_size,
                f.is_active as firmware_is_active
            FROM devices d
            LEFT JOIN firmware_versions f ON d.target_firmware = f.version
            WHERE d.cihaz_id = ?
        '''
        
        device = conn.execute(device_query, (cihaz_id,)).fetchone()
        
        # Tüm firmware versiyonlarını al  
        firmwares = conn.execute('SELECT * FROM firmware_versions ORDER BY created_at DESC').fetchall()
        
        return jsonify({
            "device_id": cihaz_id,
            "device_found": device is not None,
            "device_data": dict(device) if device else None,
            "all_firmwares": [dict(f) for f in firmwares],
            "debug_info": {
                "current_version": device['current_version'] if device else None,
                "target_firmware": device['target_firmware'] if device else None,
                "has_file_path": bool(device['file_path']) if device else False,
                "firmware_is_active": device['firmware_is_active'] if device else None,
                "file_exists": os.path.exists(device['file_path']) if device and device['file_path'] else False
            }
        })

@app.route('/admin/force_assign/<cihaz_id>/<version>')
@admin_required
def admin_force_assign(cihaz_id, version):
    """💪 Force firmware assignment"""
    try:
        with get_db() as conn:
            # Cihaz var mı kontrol et
            device = conn.execute('SELECT cihaz_id, cihaz_adi FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not device:
                return jsonify({"error": f"Cihaz bulunamadı: {cihaz_id}"})
            
            # Firmware var mı kontrol et
            firmware = conn.execute('SELECT version FROM firmware_versions WHERE version = ?', (version,)).fetchone()
            if not firmware:
                return jsonify({"error": f"Firmware bulunamadı: {version}"})
            
            # Force update
            result = conn.execute('''
                UPDATE devices 
                SET target_firmware = ?, last_update = CURRENT_TIMESTAMP
                WHERE cihaz_id = ?
            ''', (version, cihaz_id))
            
            conn.commit()
            conn.close() 
            
            # Kontrol et
            updated_device = conn.execute('SELECT target_firmware FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            
            logger.info(f"🔧 Force assign: {device['cihaz_adi']} -> v{version}")
            
            return jsonify({
                "success": True,
                "message": f"Force assign: {device['cihaz_adi']} -> v{version}",
                "rows_affected": result.rowcount,
                "updated_target": updated_device['target_firmware'] if updated_device else None
            })
            
    except Exception as e:
        logger.error(f"Force assign error: {str(e)}")
        return jsonify({"error": str(e)})

@app.route('/admin/db_dump')
@admin_required
def admin_db_dump():
    with get_db() as conn:
        cihazlar = conn.execute('SELECT * FROM devices').fetchall()
        firmwareler = conn.execute('SELECT * FROM firmware_versions').fetchall()

    return render_template('db_debug.html', cihazlar=cihazlar, firmwareler=firmwareler)

@app.route('/admin/download_db')
@admin_required
def download_db():
    return send_file('sensor_data.db', as_attachment=True)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint bulunamadı"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Sunucu hatası"}), 500

# Debug endpoint'leri ekle
@app.route('/debug/database_info')
@login_required
@admin_required
def debug_database_info():
    try:
        with get_db() as conn:
            sensor_count = conn.execute('SELECT COUNT(*) as count FROM sensor_data').fetchone()
            device_count = conn.execute('SELECT COUNT(*) as count FROM devices').fetchone()
            
            recent_data = conn.execute('''
                SELECT * FROM sensor_data 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''').fetchall()
            
            return jsonify({
                'sensor_count': sensor_count['count'],
                'device_count': device_count['count'],
                'recent_data': [dict(row) for row in recent_data]
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/test_insert')
@login_required
@admin_required
def test_insert():
    try:
        timestamp = int(time.time() * 1000)
        
        with get_db() as conn:
            # Test cihazı ekle
            conn.execute('''
                INSERT OR REPLACE INTO devices 
                (cihaz_id, cihaz_adi, konum, mac, firmware_version, last_seen, online_status, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            ''', ('TEST_001', 'Test Cihazı', 'Test Lokasyon', '00:11:22:33:44:55', '1.0.0', timestamp, '127.0.0.1'))
            
            # Test sensor verisi ekle
            conn.execute('''
                INSERT INTO sensor_data 
                (cihaz_id, sensor_id, sensor_value, sensor_unit, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', ('TEST_001', 'temp', 25.5, '°C', timestamp))
            
            conn.commit()
            
            # Toplam sayıyı kontrol et
            total = conn.execute('SELECT COUNT(*) as count FROM sensor_data').fetchone()
            
            return jsonify({
                'success': True,
                'message': 'Test verisi eklendi',
                'total_count': total['count']
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.after_request
def after_request(response):
    # Cache kontrolü
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

with app.app_context():
        try:
            current_time_ms = int(time.time() * 1000)
            threshold = current_time_ms - 120000  # 2 minutes in milliseconds
            
            with get_db() as conn:
                # Update online status for all devices
                cursor = conn.execute('''
                    UPDATE devices 
                    SET online_status = CASE 
                        WHEN last_seen >= ? AND last_seen > 0 THEN 1 
                        ELSE 0 
                    END
                ''', (threshold,))
                
                rows_affected = cursor.rowcount
                
                # Get current counts for logging
                online_count = conn.execute('''
                    SELECT COUNT(*) as count FROM devices 
                    WHERE last_seen >= ? AND last_seen > 0
                ''', (threshold,)).fetchone()['count']
                
                total_count = conn.execute('SELECT COUNT(*) as count FROM devices').fetchone()['count']
                
                conn.commit()
                
                logger.info(f"🔄 Device status updated: {online_count}/{total_count} online (updated {rows_affected} rows)")
                
        except Exception as e:
            logger.error(f"❌ Error updating device status: {str(e)}")


if __name__ == '__main__':
    os.makedirs(app.config['FIRMWARE_FOLDER'], exist_ok=True)
    logger.info("🚀 Flask server starting...")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
