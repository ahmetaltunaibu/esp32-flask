# deneme satır

import os
import sqlite3
import logging
import secrets
from collections import defaultdict
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
# Brute force koruması için basit rate limiting
from datetime import datetime, timedelta

# 🔐 Environment Variables Yükleme - BU SATIRLARI EKLE
from dotenv import load_dotenv

load_dotenv()  # .env dosyasını yükle

# Login attempt tracking
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# Flask app setup
app = Flask(__name__)
# Güvenli secret key - mevcut app.secret_key satırının yerine
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

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

# 🔐 GÜVENLİ ADMIN KONFİGÜRASYONU - Eski HARDCODED_ADMIN yerine
SECURE_ADMIN_CONFIG = {
    "username": "admin",
    "password": os.environ.get('ADMIN_PASSWORD', 'IoT@dmin2024#Secure!'),  # Güçlü varsayılan şifre
    "role": "admin",
    "is_admin": True
}


# Database Setup
def get_db():
    conn = sqlite3.connect('sensor_data.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:

        conn.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT UNIQUE NOT NULL,
                cihaz_adi TEXT NOT NULL,
                fabrika_adi TEXT,
                konum TEXT,
                mac TEXT,
                firmware_version TEXT DEFAULT '1.0.0',
                target_firmware TEXT,
                last_seen INTEGER,
                online_status INTEGER DEFAULT 0,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_update DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
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

        # *** GÜNCELLENMİŞ İŞ EMRİ TABLOSU - 13 SENSÖR VERİSİ EKLENDİ ***
        conn.execute('''
            CREATE TABLE IF NOT EXISTS work_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT NOT NULL,
                is_emri_no TEXT NOT NULL,
                urun_tipi TEXT,
                hedef_urun INTEGER,
                operator_ad TEXT,
                shift_bilgisi TEXT,
                baslama_zamani TEXT,
                bitis_zamani TEXT,
                gerceklesen_urun INTEGER DEFAULT 0,
                fire_sayisi INTEGER DEFAULT 0,
                makine_durumu INTEGER DEFAULT 0,
                is_emri_durum INTEGER DEFAULT 0,

                -- *** YENİ: 13 SENSÖR VERİSİ ALANLARI ***
                aktif_calisma REAL DEFAULT 0,
                toplam_calisma REAL DEFAULT 0,
                mola_dahil_durus REAL DEFAULT 0,
                plansiz_durus REAL DEFAULT 0,
                mola_durus REAL DEFAULT 0,
                toplam_urun REAL DEFAULT 0,
                tag_zamani REAL DEFAULT 0,
                hatali_urun REAL DEFAULT 0,
                saglam_urun REAL DEFAULT 0,
                kullanilabilirlik REAL DEFAULT 0,
                kalite REAL DEFAULT 0,
                performans REAL DEFAULT 0,
                oee REAL DEFAULT 0,

                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cihaz_id) REFERENCES devices(cihaz_id)
            )
        ''')

        # *** MEVCUT TABLOYA YENİ SÜTUNLARI EKLE (GÜVENLİ MİGRATİON) ***
        try:
            # work_orders tablosunun mevcut sütunlarını kontrol et
            cursor = conn.execute("PRAGMA table_info(work_orders)")
            existing_columns = [column[1] for column in cursor.fetchall()]

            sensor_columns_to_add = [
                ('aktif_calisma', 'REAL DEFAULT 0'),
                ('toplam_calisma', 'REAL DEFAULT 0'),
                ('mola_dahil_durus', 'REAL DEFAULT 0'),
                ('plansiz_durus', 'REAL DEFAULT 0'),
                ('mola_durus', 'REAL DEFAULT 0'),
                ('toplam_urun', 'REAL DEFAULT 0'),
                ('tag_zamani', 'REAL DEFAULT 0'),
                ('hatali_urun', 'REAL DEFAULT 0'),
                ('saglam_urun', 'REAL DEFAULT 0'),
                ('kullanilabilirlik', 'REAL DEFAULT 0'),
                ('kalite', 'REAL DEFAULT 0'),
                ('performans', 'REAL DEFAULT 0'),
                ('oee', 'REAL DEFAULT 0')
            ]

            # Eksik sütunları ekle
            added_columns = []
            for column_name, column_def in sensor_columns_to_add:
                if column_name not in existing_columns:
                    try:
                        alter_query = f"ALTER TABLE work_orders ADD COLUMN {column_name} {column_def}"
                        conn.execute(alter_query)
                        added_columns.append(column_name)
                        logger.info(f"✅ Sütun eklendi: {column_name}")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"⚠️ Sütun eklenemedi {column_name}: {str(e)}")

            if added_columns:
                logger.info(f"📊 Work_orders tablosuna {len(added_columns)} yeni sensör sütunu eklendi")
            else:
                logger.info("ℹ️ Work_orders tablosunda tüm sensör sütunları mevcut")

        except Exception as e:
            logger.error(f"❌ Work orders tablo migration hatası: {str(e)}")

        # Diğer tablolar... (değişmez)
        # ... (geri kalan tablolar aynı kalır)




# init_db() çağrısını garanti et
init_db()
init_db()


def is_ip_locked(ip_address):
    """IP adresinin kilitli olup olmadığını kontrol et"""
    now = datetime.now()
    attempts = login_attempts[ip_address]

    # Eski denemeleri temizle
    login_attempts[ip_address] = [attempt for attempt in attempts
                                  if now - attempt < LOCKOUT_DURATION]

    return len(login_attempts[ip_address]) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(ip_address):
    """Başarısız login denemesini kaydet"""
    login_attempts[ip_address].append(datetime.now())


def clear_login_attempts(ip_address):
    """Başarılı login sonrası denemeleri temizle"""
    if ip_address in login_attempts:
        del login_attempts[ip_address]


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

    # 🔧 FİX: is_admin kontrolünü role kontrolü ile değiştir
    is_admin = session.get('is_admin', False)

    # Eğer session'da role bilgisi varsa onu kullan
    if 'role' in session:
        is_admin = session.get('role') == 'admin'
    elif 'is_admin' in session:
        is_admin = session.get('is_admin', False)

    if not username:
        return dict(current_user=None, is_admin=False)

    return dict(
        current_user=dict(name=username),
        is_admin=is_admin
    )


# 2. ESP32'den iş emri alma endpoint'i
@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    if not data or 'cihaz_id' not in data:
        return jsonify({"status": "error", "message": "Geçersiz veri"}), 400

    timestamp = int(time.time() * 1000)

    try:
        with get_db() as conn:
            # Cihaz bilgilerini güncelle/ekle (değişmez)
            cursor = conn.execute('''
                UPDATE devices 
                SET cihaz_adi = ?, fabrika_adi = ?, konum = ?, mac = ?, 
                    firmware_version = ?, last_seen = ?, online_status = 1, ip_address = ?
                WHERE cihaz_id = ?
            ''', (
                data.get('cihaz_adi', 'Bilinmeyen'),
                data.get('fabrika_adi', 'Belirtilmemiş'),
                data.get('konum', 'Bilinmeyen'),
                data.get('mac', ''),
                data.get('firmware_version', '1.0.0'),
                timestamp,
                request.remote_addr,
                data['cihaz_id']
            ))

            if cursor.rowcount == 0:
                conn.execute('''
                    INSERT INTO devices 
                    (cihaz_id, cihaz_adi, fabrika_adi, konum, mac, firmware_version, last_seen, online_status, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                ''', (
                    data['cihaz_id'],
                    data.get('cihaz_adi', 'Bilinmeyen'),
                    data.get('fabrika_adi', 'Belirtilmemiş'),
                    data.get('konum', 'Bilinmeyen'),
                    data.get('mac', ''),
                    data.get('firmware_version', '1.0.0'),
                    timestamp,
                    request.remote_addr
                ))

            # *** GÜNCELLENMİŞ: İş emri verilerini kaydet (13 sensör verisi dahil) ***
            if 'is_emri' in data:
                is_emri = data['is_emri']

                print(f"📋 İş emri verisi alındı: {is_emri}")  # Debug

                # Sensör verilerini hazırla (varsa al, yoksa 0)
                sensor_values = {}
                if 'veriler' in data:
                    for veri in data['veriler']:
                        sensor_id = veri.get('sensor_id', '')
                        sensor_value = veri.get('deger', 0)
                        sensor_values[sensor_id] = sensor_value

                print(f"📊 Sensör verileri: {sensor_values}")  # Debug

                # Aktif iş emri var mı kontrol et
                existing = conn.execute('''
                    SELECT id FROM work_orders 
                    WHERE cihaz_id = ? AND is_emri_no = ? AND is_emri_durum IN (0, 1)
                ''', (data['cihaz_id'], is_emri.get('is_emri_no', ''))).fetchone()

                if existing:
                    # *** GÜNCELLENMİŞ: Mevcut iş emrini güncelle (sensör verileri dahil) ***
                    conn.execute('''
                        UPDATE work_orders 
                        SET urun_tipi = ?, hedef_urun = ?, operator_ad = ?, 
                            shift_bilgisi = ?, baslama_zamani = ?, bitis_zamani = ?,
                            makine_durumu = ?, is_emri_durum = ?,
                            aktif_calisma = ?, toplam_calisma = ?, mola_dahil_durus = ?,
                            plansiz_durus = ?, mola_durus = ?, toplam_urun = ?,
                            tag_zamani = ?, hatali_urun = ?, saglam_urun = ?,
                            kullanilabilirlik = ?, kalite = ?, performans = ?, oee = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (
                        is_emri.get('urun_tipi', ''),
                        is_emri.get('hedef_urun', 0),
                        is_emri.get('operator_ad', ''),
                        is_emri.get('shift_bilgisi', ''),
                        is_emri.get('baslama_zamani', ''),
                        is_emri.get('bitis_zamani', ''),
                        is_emri.get('makine_durumu', 0),
                        is_emri.get('is_emri_durum', 0),
                        # 13 sensör verisi
                        sensor_values.get('aktif_calisma', 0),
                        sensor_values.get('toplam_calisma', 0),
                        sensor_values.get('mola_dahil_durus', 0),
                        sensor_values.get('plansiz_durus', 0),
                        sensor_values.get('mola_durus', 0),
                        sensor_values.get('toplam_urun', 0),
                        sensor_values.get('tag_zamani', 0),
                        sensor_values.get('hatali_urun', 0),
                        sensor_values.get('saglam_urun', 0),
                        sensor_values.get('kullanilabilirlik', 0),
                        sensor_values.get('kalite', 0),
                        sensor_values.get('performans', 0),
                        sensor_values.get('OEE', 0),  # Büyük harfli OEE
                        existing['id']
                    ))
                    print(f"✅ İş emri güncellendi: {existing['id']}")  # Debug
                else:
                    # *** GÜNCELLENMİŞ: Yeni iş emri oluştur (sensör verileri dahil) ***
                    conn.execute('''
                        INSERT INTO work_orders 
                        (cihaz_id, is_emri_no, urun_tipi, hedef_urun, operator_ad, 
                         shift_bilgisi, baslama_zamani, bitis_zamani, makine_durumu, is_emri_durum,
                         aktif_calisma, toplam_calisma, mola_dahil_durus, plansiz_durus, mola_durus,
                         toplam_urun, tag_zamani, hatali_urun, saglam_urun, kullanilabilirlik,
                         kalite, performans, oee)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        data['cihaz_id'],
                        is_emri.get('is_emri_no', ''),
                        is_emri.get('urun_tipi', ''),
                        is_emri.get('hedef_urun', 0),
                        is_emri.get('operator_ad', ''),
                        is_emri.get('shift_bilgisi', ''),
                        is_emri.get('baslama_zamani', ''),
                        is_emri.get('bitis_zamani', ''),
                        is_emri.get('makine_durumu', 0),
                        is_emri.get('is_emri_durum', 0),
                        # 13 sensör verisi
                        sensor_values.get('aktif_calisma', 0),
                        sensor_values.get('toplam_calisma', 0),
                        sensor_values.get('mola_dahil_durus', 0),
                        sensor_values.get('plansiz_durus', 0),
                        sensor_values.get('mola_durus', 0),
                        sensor_values.get('toplam_urun', 0),
                        sensor_values.get('tag_zamani', 0),
                        sensor_values.get('hatali_urun', 0),
                        sensor_values.get('saglam_urun', 0),
                        sensor_values.get('kullanilabilirlik', 0),
                        sensor_values.get('kalite', 0),
                        sensor_values.get('performans', 0),
                        sensor_values.get('OEE', 0)  # Büyük harfli OEE
                    ))
                    print(f"✅ Yeni iş emri oluşturuldu")  # Debug

            # Sensör verileri kaydetme (değişmez)
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




# 3. İş emri görüntüleme sayfası
@app.route('/work_orders')
@login_required
def work_orders():
    with get_db() as conn:
        # Tüm iş emirlerini al (13 sensör verisi dahil)
        work_orders = conn.execute('''
            SELECT wo.*, d.cihaz_adi, d.konum, d.fabrika_adi
            FROM work_orders wo
            LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
            ORDER BY wo.created_at DESC
            LIMIT 100
        ''').fetchall()

        return render_template('work_orders.html', work_orders=work_orders)

# 4. Cihaz bazlı iş emri görüntüleme
@app.route('/work_orders/<cihaz_id>')
@login_required
def device_work_orders(cihaz_id):
    with get_db() as conn:
        # Cihaz bilgisi
        device = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
        if not device:
            flash('Cihaz bulunamadı', 'danger')
            return redirect(url_for('index'))

        # İş emirleri
        work_orders = conn.execute('''
            SELECT * FROM work_orders 
            WHERE cihaz_id = ? 
            ORDER BY created_at DESC
        ''', (cihaz_id,)).fetchall()

        return render_template('device_work_orders.html',
                               device=device, work_orders=work_orders)


# 5. İş emri API endpoint'i
@app.route('/api/work_orders/<cihaz_id>')
@login_required
def api_work_orders(cihaz_id):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    with get_db() as conn:
        query = 'SELECT * FROM work_orders WHERE cihaz_id = ?'
        params = [cihaz_id]

        if start_date:
            query += ' AND created_at >= ?'
            params.append(start_date)

        if end_date:
            query += ' AND created_at <= ?'
            params.append(end_date + ' 23:59:59')

        query += ' ORDER BY created_at DESC'

        work_orders = conn.execute(query, params).fetchall()

        return jsonify({
            'work_orders': [dict(wo) for wo in work_orders]
        })


# 6. İş emri özet endpoint'i
@app.route('/api/work_order_summary/<cihaz_id>')
@login_required
def work_order_summary(cihaz_id):
    with get_db() as conn:
        # Aktif iş emri (13 sensör verisi dahil)
        active = conn.execute('''
            SELECT * FROM work_orders 
            WHERE cihaz_id = ? AND is_emri_durum = 1 
            ORDER BY created_at DESC LIMIT 1
        ''', (cihaz_id,)).fetchone()

        # Son 30 günde tamamlanan iş emirleri
        completed = conn.execute('''
            SELECT COUNT(*) as count FROM work_orders 
            WHERE cihaz_id = ? AND is_emri_durum = 2 
            AND created_at >= datetime('now', '-30 days')
        ''', (cihaz_id,)).fetchone()

        # Bu ay ortalama OEE
        avg_oee = conn.execute('''
            SELECT AVG(oee) as avg_oee FROM work_orders 
            WHERE cihaz_id = ? AND is_emri_durum = 2 
            AND created_at >= datetime('now', 'start of month')
        ''', (cihaz_id,)).fetchone()

        return jsonify({
            'active_work_order': dict(active) if active else None,
            'completed_last_30_days': completed['count'],
            'average_oee': round(avg_oee['avg_oee'] or 0, 1)
        })


# RoutesYedekleme ve geri yükleme route'ları

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
                'firmware_versions': conn.execute('SELECT COUNT(*) as count FROM firmware_versions').fetchone()[
                    'count'],
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
                'firmware_count': len([f for f in os.listdir(firmware_dir) if f.endswith('.bin')]) if os.path.exists(
                    firmware_dir) else 0
            }

            zipf.writestr('backup_info.json', json.dumps(backup_info, indent=2))

        file_size = os.path.getsize(backup_path)

        flash(f'Yedekleme başarılı! Dosya: {backup_filename} ({file_size / 1024 / 1024:.1f} MB)', 'success')
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
                fabrika_info = f" - {cihaz.get('fabrika_adi', 'Bilinmeyen Fabrika')}" if cihaz.get(
                    'fabrika_adi') else ""
                logger.info(f"   🟢 {cihaz['cihaz_adi']}{fabrika_info}: ONLINE (OEE: {cihaz.get('sensor_oee', 'N/A')})")
            else:
                fabrika_info = f" - {cihaz.get('fabrika_adi', 'Bilinmeyen Fabrika')}" if cihaz.get(
                    'fabrika_adi') else ""
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

                logger.info(
                    f"🔄 Cihaz durumları güncellendi: {online_count}/{total_count} online ({rows_updated} kayıt güncellendi)")

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


# Login route'unu güncelle - aktivite loglaması için
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

        # IP kilitli mi kontrol et
        if is_ip_locked(client_ip):
            flash('Çok fazla başarısız deneme. 15 dakika sonra tekrar deneyin.', 'danger')
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Input validation
        if not username or not password:
            flash('Kullanıcı adı ve şifre gereklidir', 'danger')
            record_failed_login(client_ip)
            return render_template('login.html')

        # Sabit admin kullanıcı kontrolü - güvenli şifre ile
        if username == SECURE_ADMIN_CONFIG["username"] and password == SECURE_ADMIN_CONFIG["password"]:
            session.permanent = True
            session['username'] = username
            session['user_id'] = 1
            session['is_admin'] = True
            session['role'] = 'admin'
            session['login_time'] = datetime.now().isoformat()

            clear_login_attempts(client_ip)

            # Güvenlik logu
            logger.info(f"Admin login successful from IP: {client_ip}")

            flash('ADMIN olarak güvenli giriş yapıldı!', 'success')
            return redirect(url_for('index'))

        # Veritabanı kullanıcı kontrolü
        with get_db() as conn:
            user = conn.execute('''
                SELECT id, username, password, name, role, 
                       COALESCE(role = 'admin', 0) as is_admin_calc,
                       COALESCE(is_active, 1) as is_active
                FROM users 
                WHERE username = ? AND is_active = 1
            ''', (username,)).fetchone()

            if user and check_password_hash(user['password'], password):
                session.permanent = True
                session['username'] = username
                session['user_id'] = user['id']
                session['role'] = user['role'] or 'user'
                session['is_admin'] = user['role'] == 'admin'
                session['login_time'] = datetime.now().isoformat()

                # Last login güncelle
                conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                conn.commit()

                clear_login_attempts(client_ip)

                # Güvenlik logu
                logger.info(f"User login successful: {username} from IP: {client_ip}")

                flash('Güvenli giriş başarılı!', 'success')
                return redirect(url_for('index'))

        # Başarısız giriş
        record_failed_login(client_ip)
        logger.warning(f"Failed login attempt for username: {username} from IP: {client_ip}")
        flash('Kullanıcı adı/şifre hatalı veya hesap pasif', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    # Session temizliği
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    username = session.get('username', 'Unknown')

    # Güvenlik logu
    logger.info(f"User logout: {username} from IP: {client_ip}")

    # Session'ı tamamen temizle
    session.clear()

    # Cache temizleme headers'ları
    response = redirect(url_for('login'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    flash('Güvenli çıkış yapıldı', 'success')
    return response


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Güvenlik: Signup'ı tamamen kapat
    flash('Yeni hesap oluşturma kapatılmıştır. Lütfen yöneticinizle iletişime geçin.', 'warning')
    return redirect(url_for('login'))


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

        # Orijinal dosya ismini kaydet
        original_filename = secure_filename(file.filename)

        # Yeni dosya ismi oluştur
        filename = secure_filename(f"firmware_v{version}.bin")
        file_path = os.path.join(app.config['FIRMWARE_FOLDER'], filename)
        file.save(file_path)

        file_size = os.path.getsize(file_path)

        # Açıklamayı otomatik genişlet
        auto_description = f"Orijinal dosya: {original_filename}"
        if release_notes:
            # Kullanıcı açıklaması varsa, orijinal dosya ismini başa ekle
            final_release_notes = f"{auto_description} | {release_notes}"
        else:
            # Sadece orijinal dosya ismi
            final_release_notes = auto_description

        # Sign firmware
        signature = sign_firmware(file_path)
        sig_filename = f"firmware_v{version}.sig"
        sig_path = os.path.join(app.config['FIRMWARE_FOLDER'], sig_filename)

        with open(sig_path, 'wb') as f:
            f.write(signature)

        # Save to database - güncellenmiş açıklama ile
        with get_db() as conn:
            try:
                conn.execute('''
                    INSERT INTO firmware_versions (version, release_notes, file_path, file_size, signature_path)
                    VALUES (?, ?, ?, ?, ?)
                ''', (version, final_release_notes, file_path, file_size, sig_path))
                conn.commit()

                flash(f'Firmware başarıyla yüklendi (v{version})', 'success')
                logger.info(f"✅ Firmware uploaded: v{version} (original: {original_filename})")

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
                logger.info(
                    f"📋 Firmware details: version={firmware['version']}, active={firmware['is_active']}, file_exists={os.path.exists(firmware['file_path'])}")

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
                logger.info(
                    f"📋 Device details: id={device['cihaz_id']}, name={device['cihaz_adi']}, current={device['firmware_version']}, target={device['target_firmware']}")

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

            logger.info(
                f"✅ Verification - target_firmware: {updated_device['target_firmware'] if updated_device else 'NOT FOUND'}")

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
                logger.info(
                    f"   - File Exists: {os.path.exists(device['file_path']) if device['file_path'] else False}")
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
                    target_version and  # Target version var
                    target_version != current_version and  # Farklı versiyonlar
                    device['file_path'] and  # Dosya yolu var
                    os.path.exists(device['file_path']) and  # Dosya gerçekten var
                    device['firmware_is_active']  # Firmware aktif
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
    🗑️ Firmware versiyonunu sil (otomatik pasif etme ile)
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

            # Eğer aktif firmware ise otomatik pasif et
            if firmware['is_active']:
                logger.info(f"⚠️ Aktif firmware siliniyor, otomatik pasif ediliyor: v{version}")

                # Aktif firmware'i pasif yap
                conn.execute('''
                    UPDATE firmware_versions 
                    SET is_active = 0 
                    WHERE version = ?
                ''', (version,))

                # Başka bir firmware'i aktif et (en son yüklenen)
                other_firmware = conn.execute('''
                    SELECT version FROM firmware_versions 
                    WHERE version != ? 
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (version,)).fetchone()

                if other_firmware:
                    conn.execute('''
                        UPDATE firmware_versions 
                        SET is_active = 1 
                        WHERE version = ?
                    ''', (other_firmware['version'],))
                    logger.info(f"✅ v{other_firmware['version']} otomatik aktif edildi")
                else:
                    logger.warning("⚠️ Aktif edilecek başka firmware bulunamadı")

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
                "message": f"Firmware v{version} başarıyla silindi" +
                           (" (otomatik pasif edildi)" if firmware['is_active'] else ""),
                "files_deleted": files_deleted,
                "files_failed": files_failed,
                "was_active": firmware['is_active']
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

            # Kontrol et
            updated_device = conn.execute('SELECT target_firmware FROM devices WHERE cihaz_id = ?',
                                          (cihaz_id,)).fetchone()

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


# Bu kodu app.py dosyasına ekleyin

@app.route('/api/chart_data/<cihaz_id>')
@login_required
def get_chart_data(cihaz_id):
    """
    📊 Grafik verileri API endpoint'i
    Saatlik, günlük, haftalık, aylık, yıllık veri aggregation
    """
    sensor_id = request.args.get('sensor', '')
    period = request.args.get('period', 'hour')  # hour, day, week, month, year

    if not sensor_id:
        return jsonify({'error': 'Sensör ID gerekli'}), 400

    try:
        with get_db() as conn:
            # Cihaz kontrolü
            cihaz = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not cihaz:
                return jsonify({'error': 'Cihaz bulunamadı'}), 404

            # Zaman aralığını hesapla
            end_time = datetime.now()

            if period == 'hour':
                start_time = end_time - timedelta(hours=24)
                date_format = "%H:00"
                group_format = "strftime('%Y-%m-%d %H', datetime(timestamp/1000, 'unixepoch'))"
                interval_minutes = 60
            elif period == 'day':
                start_time = end_time - timedelta(days=30)
                date_format = "%d.%m"
                group_format = "strftime('%Y-%m-%d', datetime(timestamp/1000, 'unixepoch'))"
                interval_minutes = 1440  # 24 saat
            elif period == 'week':
                start_time = end_time - timedelta(weeks=12)
                date_format = "%d.%m"
                group_format = "strftime('%Y-W%W', datetime(timestamp/1000, 'unixepoch'))"
                interval_minutes = 10080  # 7 gün
            elif period == 'month':
                start_time = end_time - timedelta(days=365)
                date_format = "%m.%Y"
                group_format = "strftime('%Y-%m', datetime(timestamp/1000, 'unixepoch'))"
                interval_minutes = 43200  # 30 gün
            elif period == 'year':
                start_time = end_time - timedelta(days=1825)  # 5 yıl
                date_format = "%Y"
                group_format = "strftime('%Y', datetime(timestamp/1000, 'unixepoch'))"
                interval_minutes = 525600  # 1 yıl
            else:
                return jsonify({'error': 'Geçersiz periyod'}), 400

            # Timestamp'leri milisaniye olarak hesapla
            start_timestamp = int(start_time.timestamp() * 1000)
            end_timestamp = int(end_time.timestamp() * 1000)

            # Sensör birimi al
            unit_query = conn.execute('''
                SELECT sensor_unit FROM sensor_data 
                WHERE cihaz_id = ? AND sensor_id = ? 
                LIMIT 1
            ''', (cihaz_id, sensor_id)).fetchone()

            unit = unit_query['sensor_unit'] if unit_query else ''

            # Veri aggregation stratejisi
            if period == 'hour':
                # Saatlik: Son değeri al (OEE gibi değerler için mantıklı)
                query = '''
                    SELECT 
                        {group_format} as time_group,
                        sensor_value,
                        timestamp,
                        ROW_NUMBER() OVER (PARTITION BY {group_format} ORDER BY timestamp DESC) as rn
                    FROM sensor_data 
                    WHERE cihaz_id = ? AND sensor_id = ? 
                    AND timestamp >= ? AND timestamp <= ?
                '''.format(group_format=group_format)

                all_data = conn.execute(query, (cihaz_id, sensor_id, start_timestamp, end_timestamp)).fetchall()

                # Her grup için son değeri al
                aggregated_data = {}
                for row in all_data:
                    if row['rn'] == 1:  # Son değer
                        time_key = row['time_group']
                        aggregated_data[time_key] = row['sensor_value']

            else:
                # Günlük/haftalık/aylık/yıllık: Ortalama değer al
                query = '''
                    SELECT 
                        {group_format} as time_group,
                        AVG(sensor_value) as avg_value,
                        COUNT(*) as count,
                        MIN(timestamp) as min_time
                    FROM sensor_data 
                    WHERE cihaz_id = ? AND sensor_id = ? 
                    AND timestamp >= ? AND timestamp <= ?
                    GROUP BY {group_format}
                    ORDER BY min_time
                '''.format(group_format=group_format)

                raw_data = conn.execute(query, (cihaz_id, sensor_id, start_timestamp, end_timestamp)).fetchall()

                aggregated_data = {}
                for row in raw_data:
                    time_key = row['time_group']
                    aggregated_data[time_key] = round(row['avg_value'], 2)

            if not aggregated_data:
                return jsonify({
                    'labels': [],
                    'values': [],
                    'unit': unit,
                    'period': period,
                    'sensor': sensor_id
                })

            # Zaman etiketlerini formatla
            labels = []
            values = []

            # Zaman sıralı döngü oluştur
            if period == 'hour':
                current_time = start_time
                while current_time <= end_time:
                    time_key = current_time.strftime('%Y-%m-%d %H')
                    label = current_time.strftime('%H:00')

                    if time_key in aggregated_data:
                        labels.append(label)
                        values.append(aggregated_data[time_key])

                    current_time += timedelta(hours=1)

            elif period == 'day':
                current_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
                while current_time <= end_time:
                    time_key = current_time.strftime('%Y-%m-%d')
                    label = current_time.strftime('%d.%m')

                    if time_key in aggregated_data:
                        labels.append(label)
                        values.append(aggregated_data[time_key])

                    current_time += timedelta(days=1)

            elif period == 'week':
                # Haftalık için mevcut veriyi kullan
                sorted_keys = sorted(aggregated_data.keys())
                for key in sorted_keys:
                    # Hafta formatını dönüştür (2024-W01 -> 01.01)
                    try:
                        year, week = key.split('-W')
                        week_num = int(week)
                        # Haftanın ilk gününü hesapla
                        jan_1 = datetime(int(year), 1, 1)
                        week_start = jan_1 + timedelta(weeks=week_num - 1)
                        label = week_start.strftime('%d.%m')
                    except:
                        label = key

                    labels.append(label)
                    values.append(aggregated_data[key])

            elif period == 'month':
                sorted_keys = sorted(aggregated_data.keys())
                for key in sorted_keys:
                    # Ay formatını dönüştür (2024-01 -> 01.2024)
                    try:
                        year, month = key.split('-')
                        label = f"{month}.{year}"
                    except:
                        label = key

                    labels.append(label)
                    values.append(aggregated_data[key])

            elif period == 'year':
                sorted_keys = sorted(aggregated_data.keys())
                for key in sorted_keys:
                    labels.append(key)  # Yıl zaten doğru formatta
                    values.append(aggregated_data[key])

            logger.info(f"📊 Chart data: {cihaz_id} - {sensor_id} - {period} - {len(labels)} points")

            return jsonify({
                'labels': labels,
                'values': values,
                'unit': unit,
                'period': period,
                'sensor': sensor_id,
                'device': cihaz['cihaz_adi']
            })

    except Exception as e:
        logger.error(f"❌ Chart data error: {str(e)}")
        return jsonify({'error': f'Veri alınırken hata: {str(e)}'}), 500


@app.after_request
def add_security_headers(response):
    """Güvenlik başlıklarını ekle"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com https://cdn.datatables.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.datatables.net; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self';"

    # Cache kontrolü - güvenli olmayan sayfalarda
    if request.endpoint in ['login', 'signup']:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


# Kullanıcı yönetimi route'ları

@app.route('/admin/users')
@login_required
@admin_required
def user_management():
    """Kullanıcı yönetimi sayfası"""
    return render_template('user_management.html')


@app.route('/admin/api/users', methods=['GET'])
@login_required
@admin_required
def get_users_api():
    """Kullanıcı listesi API"""
    try:
        with get_db() as conn:
            # Basit ve güvenli sorgu
            try:
                users = conn.execute('''
                    SELECT id, username, 
                           COALESCE(name, username) as name,
                           COALESCE(role, 'user') as role,
                           COALESCE(is_active, 1) as is_active,
                           created_at,
                           last_login
                    FROM users 
                    ORDER BY id
                ''').fetchall()
            except sqlite3.OperationalError as e:
                # Tablo veya sütun yoksa basit sorgu
                logger.warning(f"Column missing, using basic query: {e}")
                users = conn.execute('SELECT id, username FROM users').fetchall()

                # Basit user listesi oluştur
                user_list = []
                for user in users:
                    user_dict = dict(user)
                    user_dict['name'] = user_dict.get('username', 'Unknown')
                    user_dict['role'] = 'admin' if user_dict.get('username') == 'admin' else 'user'
                    user_dict['is_active'] = True
                    user_dict['created_at'] = None
                    user_dict['last_login'] = None
                    user_list.append(user_dict)

                return jsonify({
                    'success': True,
                    'users': user_list,
                    'message': 'Basit veri formatı (bazı sütunlar eksik)'
                })

            # Normal sonuç
            user_list = []
            for user in users:
                user_dict = dict(user)
                user_dict.pop('password', None)  # Şifreyi kaldır
                user_list.append(user_dict)

            return jsonify({
                'success': True,
                'users': user_list
            })

    except Exception as e:
        logger.error(f"❌ get_users_api error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'users': []
        }), 500


@app.route('/admin/api/users/stats', methods=['GET'])
@login_required
@admin_required
def user_stats_api():
    """Kullanıcı istatistikleri API"""
    try:
        with get_db() as conn:
            try:
                total = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']

                # Diğer istatistikler için güvenli sorgular
                try:
                    active = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count']
                except:
                    active = total  # Fallback

                try:
                    admins = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "admin"').fetchone()[
                        'count']
                except:
                    admins = 1  # En az admin var

                try:
                    recent = conn.execute('''
                        SELECT COUNT(*) as count FROM users 
                        WHERE last_login >= datetime('now', '-1 day')
                    ''').fetchone()['count']
                except:
                    recent = 0  # Fallback

            except sqlite3.OperationalError:
                # Tablo yoksa varsayılan değerler
                total = active = admins = recent = 0

            return jsonify({
                'success': True,
                'stats': {
                    'total': total,
                    'active': active,
                    'admins': admins,
                    'recent_logins': recent
                }
            })
    except Exception as e:
        logger.error(f"❌ user_stats_api error: {str(e)}")
        return jsonify({
            'success': True,
            'stats': {'total': 0, 'active': 0, 'admins': 0, 'recent_logins': 0}
        })


@app.route('/admin/api/activities', methods=['GET'])
@login_required
@admin_required
def get_activities_api():
    """Aktivite logları API"""
    try:
        with get_db() as conn:
            try:
                activities = conn.execute('''
                    SELECT ua.*, u.username
                    FROM user_activities ua
                    LEFT JOIN users u ON ua.user_id = u.id
                    ORDER BY ua.created_at DESC
                    LIMIT 50
                ''').fetchall()

                activity_list = [dict(activity) for activity in activities]

            except sqlite3.OperationalError:
                # Tablo yoksa boş liste
                activity_list = []

            return jsonify({
                'success': True,
                'activities': activity_list
            })

    except Exception as e:
        logger.error(f"❌ get_activities_api error: {str(e)}")
        return jsonify({
            'success': False,
            'activities': [],
            'error': str(e)
        })


@app.route('/admin/api/users', methods=['POST'])
@login_required
@admin_required
def create_user_api():
    """Yeni kullanıcı oluştur API"""
    try:
        data = request.get_json()

        # Validation
        required_fields = ['username', 'password', 'name', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} alanı gerekli'}), 400

        with get_db() as conn:
            # Kullanıcı adı kontrolü
            existing = conn.execute('SELECT id FROM users WHERE username = ?', (data['username'],)).fetchone()
            if existing:
                return jsonify({'success': False, 'error': 'Bu kullanıcı adı zaten kullanılıyor'}), 400

            # Kullanıcı oluştur
            conn.execute('''
                INSERT INTO users (username, password, name, role, is_active)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                data['username'],
                generate_password_hash(data['password']),
                data['name'],
                data['role'],
                data.get('is_active', True)
            ))

            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Kullanıcı başarıyla oluşturuldu'
            })

    except Exception as e:
        logger.error(f"❌ create_user_api error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user_api(user_id):
    """Kullanıcı güncelle API"""
    try:
        data = request.get_json()

        with get_db() as conn:
            # Kullanıcı var mı kontrol et
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404

            # Güncelleme alanları
            update_fields = []
            params = []

            if 'name' in data:
                update_fields.append('name = ?')
                params.append(data['name'])

            if 'username' in data:
                update_fields.append('username = ?')
                params.append(data['username'])

            if 'role' in data:
                update_fields.append('role = ?')
                params.append(data['role'])

            if 'is_active' in data:
                update_fields.append('is_active = ?')
                params.append(data['is_active'])

            if 'password' in data and data['password']:
                update_fields.append('password = ?')
                params.append(generate_password_hash(data['password']))

            if update_fields:
                params.append(user_id)
                query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
                conn.execute(query, params)
                conn.commit()

            return jsonify({
                'success': True,
                'message': 'Kullanıcı başarıyla güncellendi'
            })

    except Exception as e:
        logger.error(f"❌ update_user_api error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user_api(user_id):
    """Kullanıcı sil API"""
    try:
        current_user_id = session.get('user_id', 1)

        # Kendi kendini silmeyi engelle
        if user_id == current_user_id:
            return jsonify({'success': False, 'error': 'Kendi hesabınızı silemezsiniz'}), 400

        with get_db() as conn:
            # Kullanıcı var mı kontrol et
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404

            # Kullanıcıyı sil
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Kullanıcı başarıyla silindi'
            })

    except Exception as e:
        logger.error(f"❌ delete_user_api error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/api/users/<int:user_id>/activate', methods=['POST'])
@login_required
@admin_required
def activate_user_api(user_id):
    """Kullanıcıyı aktif et API"""
    return toggle_user_status_api(user_id, True)


@app.route('/admin/api/users/<int:user_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_user_api(user_id):
    """Kullanıcıyı pasif et API"""
    return toggle_user_status_api(user_id, False)


def toggle_user_status_api(user_id, is_active):
    """Kullanıcı durumu değiştir API yardımcı fonksiyonu"""
    try:
        with get_db() as conn:
            # Kullanıcı var mı kontrol et
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404

            # Durumu güncelle
            conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (is_active, user_id))
            conn.commit()

            status_text = 'aktif' if is_active else 'pasif'
            return jsonify({
                'success': True,
                'message': f'Kullanıcı {status_text} yapıldı'
            })

    except Exception as e:
        logger.error(f"❌ toggle_user_status_api error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/api/users/<int:user_id>/activities', methods=['GET'])
@login_required
@admin_required
def get_user_activities_api(user_id):
    """Kullanıcı aktiviteleri API"""
    try:
        with get_db() as conn:
            try:
                activities = conn.execute('''
                    SELECT * FROM user_activities
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    LIMIT 100
                ''', (user_id,)).fetchall()

                activity_list = [dict(activity) for activity in activities]

            except sqlite3.OperationalError:
                # Tablo yoksa boş liste
                activity_list = []

            return jsonify({
                'success': True,
                'activities': activity_list
            })

    except Exception as e:
        logger.error(f"❌ get_user_activities_api error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/api/activities', methods=['POST'])
@login_required
@admin_required
def create_activity_api():
    """Aktivite logu oluştur API"""
    try:
        data = request.get_json()

        with get_db() as conn:
            try:
                conn.execute('''
                    INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    session.get('user_id', 1),
                    data.get('type', 'manual'),
                    data.get('description', ''),
                    request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                    request.headers.get('User-Agent', '')
                ))
                conn.commit()

            except sqlite3.OperationalError:
                # Tablo yoksa görmezden gel
                pass

            return jsonify({'success': True})

    except Exception as e:
        logger.error(f"❌ create_activity_api error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# İlk kez kullanıcı tablosunu oluşturmak için startup function

# ESKI route'ları kaldırın ve bunları kullanın
# Ayrıca user_activities tablosunu da oluşturalım
def create_user_activities_table():
    """User activities tablosunu oluştur"""
    try:
        with get_db() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    activity_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            logger.info("✅ User activities table ready")
    except Exception as e:
        logger.error(f"❌ create_user_activities_table error: {str(e)}")


# app.py'ye bu route'u ekleyin (mevcut /admin/users route'unu değiştirin):

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    """Kullanıcı listesi API - HIZLI FİX"""
    try:
        # 1. Basit kontrol - Users tablosu var mı?
        with get_db() as conn:
            # Tablo varlığını kontrol et
            try:
                test_query = conn.execute("SELECT COUNT(*) FROM users").fetchone()
                table_exists = True
            except sqlite3.OperationalError:
                table_exists = False

            if not table_exists:
                # Basit users tablosu oluştur
                conn.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        name TEXT DEFAULT 'User',
                        role TEXT DEFAULT 'user',
                        is_active BOOLEAN DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Admin ekle
                admin_password = os.environ.get('ADMIN_PASSWORD', 'IoT@dmin2024#Secure!')
                conn.execute('''
                    INSERT INTO users (username, password, name, role, is_active)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('admin', generate_password_hash(admin_password), 'Admin', 'admin', 1))

                conn.commit()
                logger.info("✅ Users tablosu oluşturuldu")

            # 2. Kullanıcıları getir - güvenli şekilde
            try:
                users = conn.execute('''
                    SELECT id, username, 
                           COALESCE(name, username) as name,
                           COALESCE(role, 'user') as role,
                           COALESCE(is_active, 1) as is_active,
                           created_at
                    FROM users 
                    ORDER BY id
                ''').fetchall()
            except sqlite3.OperationalError as e:
                # Sütun eksikse basit sorgu kullan
                logger.warning(f"Column missing, using basic query: {e}")
                users = conn.execute('SELECT id, username, password FROM users').fetchall()

                # Eksik alanları manuel ekle
                user_list = []
                for user in users:
                    user_dict = dict(user)
                    user_dict.pop('password', None)  # Şifreyi kaldır
                    user_dict['name'] = user_dict.get('username', 'Unknown')
                    user_dict['role'] = 'admin' if user_dict.get('username') == 'admin' else 'user'
                    user_dict['is_active'] = True
                    user_dict['created_at'] = None
                    user_list.append(user_dict)

                return jsonify({
                    'success': True,
                    'users': user_list,
                    'message': 'Basic user data loaded (some columns missing)'
                })

            # Normal sonuç
            user_list = []
            for user in users:
                user_dict = dict(user)
                user_dict.pop('password', None)  # Şifreyi kaldır
                user_list.append(user_dict)

            return jsonify({
                'success': True,
                'users': user_list
            })

    except Exception as e:
        logger.error(f"❌ get_users error: {str(e)}")

        # HER DURUMDA JSON döndür
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'users': []  # Boş liste döndür
        }), 500


# Ayrıca debug endpoint'i de ekleyin:
@app.route('/admin/users/debug')
@login_required
@admin_required
def debug_users_table():
    """Users tablosu debug bilgileri"""
    try:
        with get_db() as conn:
            debug_info = {}

            # Tablo varlığı
            table_exists = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='users'
            """).fetchone()
            debug_info['table_exists'] = bool(table_exists)

            if table_exists:
                # Sütun bilgileri
                columns = conn.execute("PRAGMA table_info(users)").fetchall()
                debug_info['columns'] = [dict(col) for col in columns]
                debug_info['column_names'] = [col[1] for col in columns]

                # Kayıt sayısı
                count = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
                debug_info['record_count'] = count

                # İlk 3 kayıt (şifresiz)
                sample_users = conn.execute("""
                    SELECT id, username, name, role, is_active, created_at 
                    FROM users 
                    LIMIT 3
                """).fetchall()
                debug_info['sample_records'] = [dict(user) for user in sample_users]

            else:
                debug_info['error'] = 'Users tablosu bulunamadı'

            return jsonify({
                'success': True,
                'debug_info': debug_info
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/admin/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Yeni kullanıcı oluştur"""
    try:
        data = request.get_json()

        # Validation
        required_fields = ['username', 'password', 'name', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} alanı gerekli'}), 400

        # Kullanıcı adı kontrolü
        username = data['username'].strip()
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Kullanıcı adı en az 3 karakter olmalı'}), 400

        # Şifre kontrolü
        password = data['password']
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Şifre en az 6 karakter olmalı'}), 400

        # Rol kontrolü
        if data['role'] not in ['admin', 'user', 'viewer']:
            return jsonify({'success': False, 'error': 'Geçersiz rol'}), 400

        with get_db() as conn:
            # Kullanıcı adı benzersizlik kontrolü
            existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if existing:
                return jsonify({'success': False, 'error': 'Bu kullanıcı adı zaten kullanılıyor'}), 400

            # Email benzersizlik kontrolü (eğer verilmişse)
            email = data.get('email', '').strip()
            if email:
                existing_email = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                if existing_email:
                    return jsonify({'success': False, 'error': 'Bu email adresi zaten kullanılıyor'}), 400

            # Kullanıcı oluştur
            cursor = conn.execute('''
                INSERT INTO users (username, password, name, email, role, is_active, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                username,
                generate_password_hash(password),
                data['name'].strip(),
                email if email else None,
                data['role'],
                data.get('is_active', True),
                session.get('user_id', 1)  # Şimdilik 1, gerçekte session'dan alınmalı
            ))

            new_user_id = cursor.lastrowid
            conn.commit()

            # Aktivite logu
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type='user_created',
                description=f"Yeni kullanıcı oluşturuldu: {data['name']} (@{username})",
                conn=conn
            )

            logger.info(f"✅ New user created: {username} by {session.get('username')}")

            return jsonify({
                'success': True,
                'message': 'Kullanıcı başarıyla oluşturuldu',
                'user_id': new_user_id
            })

    except sqlite3.IntegrityError as e:
        return jsonify({'success': False, 'error': 'Kullanıcı adı zaten kullanılıyor'}), 400
    except Exception as e:
        logger.error(f"❌ Create user error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    """Kullanıcı güncelle"""
    try:
        data = request.get_json()

        with get_db() as conn:
            # Kullanıcı var mı kontrol et
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404

            # Kendi kendini admin'den çıkarmasını engelle
            current_user_id = session.get('user_id', 1)
            if user_id == current_user_id and data.get('role') != 'admin':
                return jsonify({'success': False, 'error': 'Kendi rolünüzü değiştiremezsiniz'}), 400

            # Güncelleme alanları
            update_fields = []
            params = []

            if 'name' in data:
                update_fields.append('name = ?')
                params.append(data['name'].strip())

            if 'username' in data:
                username = data['username'].strip()
                # Kullanıcı adı benzersizlik kontrolü
                existing = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?',
                                        (username, user_id)).fetchone()
                if existing:
                    return jsonify({'success': False, 'error': 'Bu kullanıcı adı zaten kullanılıyor'}), 400

                update_fields.append('username = ?')
                params.append(username)

            if 'email' in data:
                email = data['email'].strip() if data['email'] else None
                if email:
                    # Email benzersizlik kontrolü
                    existing = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?',
                                            (email, user_id)).fetchone()
                    if existing:
                        return jsonify({'success': False, 'error': 'Bu email adresi zaten kullanılıyor'}), 400

                update_fields.append('email = ?')
                params.append(email)

            if 'role' in data and data['role'] in ['admin', 'user', 'viewer']:
                update_fields.append('role = ?')
                params.append(data['role'])

            if 'is_active' in data:
                update_fields.append('is_active = ?')
                params.append(data['is_active'])

            if 'password' in data and data['password']:
                if len(data['password']) < 6:
                    return jsonify({'success': False, 'error': 'Şifre en az 6 karakter olmalı'}), 400
                update_fields.append('password = ?')
                params.append(generate_password_hash(data['password']))

            if not update_fields:
                return jsonify({'success': False, 'error': 'Güncellenecek alan bulunamadı'}), 400

            # Güncelleme yap
            params.append(user_id)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            conn.execute(query, params)
            conn.commit()

            # Aktivite logu
            log_user_activity(
                user_id=current_user_id,
                activity_type='user_updated',
                description=f"Kullanıcı güncellendi: {data.get('name', user['name'])}",
                conn=conn
            )

            logger.info(f"✅ User updated: {user_id} by {session.get('username')}")

            return jsonify({
                'success': True,
                'message': 'Kullanıcı başarıyla güncellendi'
            })

    except Exception as e:
        logger.error(f"❌ Update user error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """Kullanıcı sil"""
    try:
        current_user_id = session.get('user_id', 1)

        # Kendi kendini silmeyi engelle
        if user_id == current_user_id:
            return jsonify({'success': False, 'error': 'Kendi hesabınızı silemezsiniz'}), 400

        with get_db() as conn:
            # Kullanıcı var mı kontrol et
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404

            # Kullanıcıyı sil
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))

            # Aktivite logunu sil (isteğe bağlı, tutmak da mantıklı)
            # conn.execute('DELETE FROM user_activities WHERE user_id = ?', (user_id,))

            conn.commit()

            # Aktivite logu
            log_user_activity(
                user_id=current_user_id,
                activity_type='user_deleted',
                description=f"Kullanıcı silindi: {user['name']} (@{user['username']})",
                conn=conn
            )

            logger.info(f"✅ User deleted: {user_id} by {session.get('username')}")

            return jsonify({
                'success': True,
                'message': 'Kullanıcı başarıyla silindi'
            })

    except Exception as e:
        logger.error(f"❌ Delete user error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/users/<int:user_id>/activate', methods=['POST'])
@login_required
@admin_required
def activate_user(user_id):
    """Kullanıcıyı aktif et"""
    return toggle_user_status(user_id, True)


@app.route('/admin/users/<int:user_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_user(user_id):
    """Kullanıcıyı pasif et"""
    return toggle_user_status(user_id, False)


def toggle_user_status(user_id, is_active):
    """Kullanıcı durumunu değiştir"""
    try:
        with get_db() as conn:
            # Kullanıcı var mı kontrol et
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404

            # Durumu güncelle
            conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (is_active, user_id))
            conn.commit()

            # Aktivite logu
            status_text = 'aktif' if is_active else 'pasif'
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type='user_status_changed',
                description=f"Kullanıcı {status_text} yapıldı: {user['name']}",
                conn=conn
            )

            return jsonify({
                'success': True,
                'message': f'Kullanıcı {status_text} yapıldı'
            })

    except Exception as e:
        logger.error(f"❌ Toggle user status error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/users/stats')
@login_required
@admin_required
def user_stats():
    """User stats - HIZLI FİX"""
    try:
        with get_db() as conn:
            try:
                total = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
                # Diğer istatistikler için de basit sorgular
                active = total  # Fallback
                admins = 1  # En az admin var
                recent = 0  # Fallback

                try:
                    active = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count']
                except:
                    pass

                try:
                    admins = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "admin"').fetchone()[
                        'count']
                except:
                    pass

            except sqlite3.OperationalError:
                # Tablo yoksa varsayılan değerler
                total = active = admins = recent = 0

            return jsonify({
                'success': True,
                'stats': {
                    'total': total,
                    'active': active,
                    'admins': admins,
                    'recent_logins': recent
                }
            })
    except Exception as e:
        # Hata durumunda bile JSON döndür
        return jsonify({
            'success': True,
            'stats': {'total': 0, 'active': 0, 'admins': 0, 'recent_logins': 0}
        })


# ÖNEMLİ: Flask error handler ekleyin
@app.errorhandler(500)
def handle_500_error(e):
    """500 hatalarını JSON olarak döndür"""
    if request.path.startswith('/admin/') and request.headers.get('Accept', '').find('json') != -1:
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': 'Sunucu hatası oluştu'
        }), 500

    # Normal HTML error sayfası
    return render_template('error.html', error="Internal Server Error"), 500


@app.route('/admin/activities')
@login_required
@admin_required
def get_activities():
    """Aktivite logları"""
    try:
        with get_db() as conn:
            activities = conn.execute('''
                SELECT ua.*, u.username
                FROM user_activities ua
                LEFT JOIN users u ON ua.user_id = u.id
                ORDER BY ua.created_at DESC
                LIMIT 50
            ''').fetchall()

            activity_list = [dict(activity) for activity in activities]

            return jsonify({
                'success': True,
                'activities': activity_list
            })

    except Exception as e:
        logger.error(f"❌ Get activities error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/activities', methods=['POST'])
@login_required
@admin_required
def create_activity():
    """Aktivite logu oluştur"""
    try:
        data = request.get_json()

        with get_db() as conn:
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type=data.get('type', 'manual'),
                description=data.get('description', ''),
                conn=conn
            )

            return jsonify({'success': True})

    except Exception as e:
        logger.error(f"❌ Create activity error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/users/<int:user_id>/activities')
@login_required
@admin_required
def get_user_activities(user_id):
    """Kullanıcı aktiviteleri"""
    try:
        with get_db() as conn:
            activities = conn.execute('''
                SELECT * FROM user_activities
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 100
            ''', (user_id,)).fetchall()

            activity_list = [dict(activity) for activity in activities]

            return jsonify({
                'success': True,
                'activities': activity_list
            })

    except Exception as e:
        logger.error(f"❌ Get user activities error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Yardımcı fonksiyon
def log_user_activity(user_id, activity_type, description, conn=None, ip_address=None, user_agent=None):
    """Kullanıcı aktivitesi logla"""
    try:
        if conn is None:
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, activity_type, description, ip_address, user_agent))
                conn.commit()
        else:
            conn.execute('''
                INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, activity_type, description, ip_address, user_agent))

    except Exception as e:
        logger.error(f"❌ Log activity error: {str(e)}")


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
    # Güvenlik kontrolleri
    if not os.environ.get('SECRET_KEY'):
        logger.warning("⚠️ SECRET_KEY environment variable tanımlanmamış!")

    if not os.environ.get('ADMIN_PASSWORD'):
        logger.warning("⚠️ ADMIN_PASSWORD environment variable tanımlanmamış!")
        logger.warning("🔑 Varsayılan güvenli şifre kullanılıyor: IoT@dmin2024#Secure!")

    # SSL kontrolü (production için)
    if os.environ.get('FLASK_ENV') == 'production':
        if not os.environ.get('SSL_REQUIRED'):
            logger.warning("⚠️ Production ortamında SSL kullanılması önerilir!")

    # Firmware klasörü güvenliği
    os.makedirs(app.config['FIRMWARE_FOLDER'], exist_ok=True)
    os.chmod(app.config['FIRMWARE_FOLDER'], 0o755)  # Güvenli dosya izinleri

    logger.info("🚀 Flask server starting with enhanced security...")

    # Development vs Production
    debug_mode = os.environ.get('DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))

    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode,
        threaded=True
    )
