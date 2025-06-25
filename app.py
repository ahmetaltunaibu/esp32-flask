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

# app.py'nin başına ekle:
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import base64

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
DATABASE_PATH = 'sensor_data.db'

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


# database oluşturma
def init_db():
    """Database'i başlat - tüm tabloları oluştur"""
    with get_db() as conn:

        # 1. DEVICES TABLOSU - TÜM KOLONLAR İLE
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
                online_status INTEGER DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 2. SENSOR_DATA TABLOSU
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT NOT NULL,
                sensor_id TEXT NOT NULL,
                sensor_value REAL NOT NULL,
                sensor_unit TEXT,
                timestamp INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cihaz_id) REFERENCES devices (cihaz_id)
            )
        ''')

        # 3. WORK_ORDERS TABLOSU - Arduino sensörleri ile
        conn.execute('''
            CREATE TABLE IF NOT EXISTS work_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT NOT NULL,
                is_emri_no TEXT,
                urun_tipi TEXT,
                hedef_urun INTEGER DEFAULT 0,
                operator_ad TEXT,
                shift_bilgisi TEXT,
                baslama_zamani TEXT,
                bitis_zamani TEXT,
                makine_durumu INTEGER DEFAULT 0,
                is_emri_durum INTEGER DEFAULT 0,
                gerceklesen_urun INTEGER DEFAULT 0,
                fire_sayisi INTEGER DEFAULT 0,
                created_at TEXT,
                sensor_aktif_calisma REAL DEFAULT 0,
                sensor_toplam_calisma REAL DEFAULT 0,
                sensor_mola_dahil_durus REAL DEFAULT 0,
                sensor_plansiz_durus REAL DEFAULT 0,
                sensor_mola_durus REAL DEFAULT 0,
                sensor_toplam_urun REAL DEFAULT 0,
                sensor_tag_zamani REAL DEFAULT 0,
                sensor_hatali_urun REAL DEFAULT 0,
                sensor_saglam_urun REAL DEFAULT 0,
                sensor_kullanilabilirlik REAL DEFAULT 0,
                sensor_kalite REAL DEFAULT 0,
                sensor_performans REAL DEFAULT 0,
                sensor_oee REAL DEFAULT 0,
                FOREIGN KEY (cihaz_id) REFERENCES devices (cihaz_id)
            )
        ''')

        # 4. USERS TABLOSU
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT,
                email TEXT,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')

        # 5. USER_ACTIVITIES TABLOSU
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                activity_type TEXT,
                description TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # 6. FIRMWARE_VERSIONS TABLOSU - DÜZELTİLMİŞ
        conn.execute('''
            CREATE TABLE IF NOT EXISTS firmware_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT,
                signature_path TEXT,
                file_size INTEGER,
                release_notes TEXT,
                is_active INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 7. UPDATE_HISTORY TABLOSU
        conn.execute('''
            CREATE TABLE IF NOT EXISTS update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cihaz_id TEXT NOT NULL,
                old_version TEXT,
                new_version TEXT,
                update_status TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY (cihaz_id) REFERENCES devices (cihaz_id)
            )
        ''')

        # 8. DOWNTIMES TABLOSU
        conn.execute('''
            CREATE TABLE IF NOT EXISTS downtimes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                work_order_id INTEGER NOT NULL,
                cihaz_id TEXT NOT NULL,
                is_emri_no TEXT NOT NULL,
                downtime_id TEXT NOT NULL,
                baslama_zamani TEXT NOT NULL,
                bitis_zamani TEXT,
                neden_kodu INTEGER,
                neden_aciklama TEXT,
                yapilan_islem TEXT,
                sure_saniye INTEGER DEFAULT 0,
                sure_dakika INTEGER DEFAULT 0,
                sure_str TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (work_order_id) REFERENCES work_orders (id),
                FOREIGN KEY (cihaz_id) REFERENCES devices (cihaz_id)
            )
        ''')

        # 9. FIRES TABLOSU - YENİ! ← BU SATIRI VE ALTTAKI KODU EKLE
        conn.execute('''
                    CREATE TABLE IF NOT EXISTS fires (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        work_order_id INTEGER NOT NULL,
                        cihaz_id TEXT NOT NULL,
                        is_emri_no TEXT NOT NULL,
                        fire_id TEXT NOT NULL,
                        baslama_zamani TEXT NOT NULL,
                        bitis_zamani TEXT,
                        miktar INTEGER DEFAULT 0,
                        neden_kodu INTEGER,
                        neden_aciklama TEXT,
                        aciklama TEXT,
                        sure_saniye INTEGER DEFAULT 0,
                        sure_dakika INTEGER DEFAULT 0,
                        sure_str TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (work_order_id) REFERENCES work_orders (id),
                        FOREIGN KEY (cihaz_id) REFERENCES devices (cihaz_id)
                    )
                ''')

        try:
            # Admin kullanıcısı var mı kontrol et
            cursor = conn.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
            if cursor.fetchone()[0] == 0:
                # Şifre: admin123
                password_hash = generate_password_hash('admin123')
                conn.execute('''
                    INSERT INTO users (username, password, name, email, role, is_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('admin', password_hash, 'System Admin', 'admin@system.com', 'admin', 1))
                print("✅ Varsayılan admin kullanıcısı oluşturuldu (admin/admin123)")
        except Exception as e:
            print(f"❌ Admin kullanıcısı oluşturulurken hata: {e}")

        conn.commit()

        # Factory access kolonu ekle
        try:
            columns = conn.execute("PRAGMA table_info(users)").fetchall()
            has_factory_column = any(col[1] == 'factory_access' for col in columns)

            if not has_factory_column:
                conn.execute('ALTER TABLE users ADD COLUMN factory_access TEXT DEFAULT NULL')
                logger.info("✅ Factory access column added")
        except Exception as e:
            logger.error(f"❌ Factory column error: {str(e)}")

        print("✅ Tüm veritabanı tabloları oluşturuldu")

    # Tablo bilgilerini göster
    show_table_stats()
    validate_and_fix_tables()



def validate_and_fix_tables():
    """Database tablolarını kontrol et ve eksik sütunları ekle"""
    try:
        with get_db() as conn:
            logger.info("🔍 Database tablo kontrolü başlıyor...")

            # 1. WORK_ORDERS tablosu sütun kontrolü
            try:
                # Mevcut sütunları al
                cursor = conn.execute("PRAGMA table_info(work_orders)")
                existing_columns = [col[1] for col in cursor.fetchall()]

                # Gerekli sütunlar listesi
                required_columns = [
                    'sensor_aktif_calisma', 'sensor_toplam_calisma', 'sensor_mola_dahil_durus',
                    'sensor_plansiz_durus', 'sensor_mola_durus', 'sensor_toplam_urun',
                    'sensor_tag_zamani', 'sensor_hatali_urun', 'sensor_saglam_urun',
                    'sensor_kullanilabilirlik', 'sensor_kalite', 'sensor_performans', 'sensor_oee'
                ]

                # Eksik sütunları ekle
                for column in required_columns:
                    if column not in existing_columns:
                        try:
                            conn.execute(f'ALTER TABLE work_orders ADD COLUMN {column} REAL DEFAULT 0')
                            logger.info(f"✅ Sütun eklendi: work_orders.{column}")
                        except Exception as e:
                            logger.error(f"❌ Sütun eklenemedi {column}: {e}")

                logger.info(
                    f"✅ work_orders tablosu: {len([c for c in required_columns if c in existing_columns])}/{len(required_columns)} sensör sütunu mevcut")

            except Exception as e:
                logger.error(f"❌ work_orders tablo kontrolü hatası: {e}")

            # 2. DOWNTIMES tablosu kontrolü
            try:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downtimes'")
                if not cursor.fetchone():
                    # Downtimes tablosunu oluştur
                    conn.execute('''
                        CREATE TABLE downtimes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            work_order_id INTEGER NOT NULL,
                            cihaz_id TEXT NOT NULL,
                            is_emri_no TEXT NOT NULL,
                            downtime_id TEXT NOT NULL,
                            baslama_zamani TEXT NOT NULL,
                            bitis_zamani TEXT,
                            neden_kodu INTEGER,
                            neden_aciklama TEXT,
                            yapilan_islem TEXT,
                            sure_saniye INTEGER DEFAULT 0,
                            sure_dakika INTEGER DEFAULT 0,
                            sure_str TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (work_order_id) REFERENCES work_orders (id)
                        )
                    ''')
                    logger.info("✅ downtimes tablosu oluşturuldu")
                else:
                    logger.info("✅ downtimes tablosu mevcut")
            except Exception as e:
                logger.error(f"❌ downtimes tablo kontrolü hatası: {e}")

            # 3. FIRES tablosu kontrolü
            try:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='fires'")
                if not cursor.fetchone():
                    # Fires tablosunu oluştur
                    conn.execute('''
                        CREATE TABLE fires (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            work_order_id INTEGER NOT NULL,
                            cihaz_id TEXT NOT NULL,
                            is_emri_no TEXT NOT NULL,
                            fire_id TEXT NOT NULL,
                            baslama_zamani TEXT NOT NULL,
                            bitis_zamani TEXT,
                            miktar INTEGER DEFAULT 0,
                            neden_kodu INTEGER,
                            neden_aciklama TEXT,
                            aciklama TEXT,
                            sure_saniye INTEGER DEFAULT 0,
                            sure_dakika INTEGER DEFAULT 0,
                            sure_str TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (work_order_id) REFERENCES work_orders (id)
                        )
                    ''')
                    logger.info("✅ fires tablosu oluşturuldu")
                else:
                    logger.info("✅ fires tablosu mevcut")
            except Exception as e:
                logger.error(f"❌ fires tablo kontrolü hatası: {e}")

            # 4. DEVICES tablosu gerekli sütunları kontrol et
            try:
                cursor = conn.execute("PRAGMA table_info(devices)")
                device_columns = [col[1] for col in cursor.fetchall()]

                device_required_columns = {
                    'last_seen': 'INTEGER DEFAULT 0',
                    'online_status': 'INTEGER DEFAULT 0',
                    'ip_address': 'TEXT',
                    'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
                }

                for column, definition in device_required_columns.items():
                    if column not in device_columns:
                        try:
                            conn.execute(f'ALTER TABLE devices ADD COLUMN {column} {definition}')
                            logger.info(f"✅ Devices sütun eklendi: {column}")
                        except Exception as e:
                            logger.warning(f"⚠️ Devices sütun eklenemedi {column}: {e}")

            except Exception as e:
                logger.error(f"❌ devices tablo kontrolü hatası: {e}")

            conn.commit()
            logger.info("✅ Database tablo kontrolü tamamlandı")

    except Exception as e:
        logger.error(f"❌ Database validation genel hatası: {e}")



def show_table_stats():
    """Tablo istatistiklerini göster"""
    tables = ['devices', 'sensor_data', 'work_orders', 'users', 'user_activities',
              'firmware_versions', 'update_history']

    with get_db() as conn:
        for table in tables:
            try:
                cursor = conn.execute(f'SELECT COUNT(*) FROM {table}')
                count = cursor.fetchone()[0]
                print(f"📊 {table}: {count} kayıt")
            except Exception as e:
                print(f"❌ {table} tablosu kontrol edilemedi: {e}")


init_db()  # Tabloları oluştur


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


# ESP32'den gelen datetime string'leri için
@app.template_filter('format_work_order_time')
def format_work_order_time(datetime_str):
    """ESP32'den gelen datetime string'ini formatla - TIMEZONE FİX"""
    try:
        if not datetime_str or datetime_str in ['', 'Devam ediyor', 'Başlamamış']:
            return datetime_str or 'Belirtilmemiş'

        # ESP32'den gelen format: "2025-06-05 09:51:53"
        # Bu ZATEN Türkiye saati, UTC'ye çevirme!
        dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%d.%m.%Y %H:%M:%S')

    except Exception as e:
        print(f"Work order time format error: {e}, value: {datetime_str}")
        return datetime_str


# YENİ: Database created_at için (UTC'den Türkiye'ye)
@app.template_filter('format_db_datetime')
def format_db_datetime(datetime_str):
    """Database'den gelen datetime'ı Türkiye saatine çevir"""
    try:
        if not datetime_str:
            return "N/A"

        # Database'den gelen format genelde UTC
        dt = datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))

        # UTC'den Türkiye saatine çevir (+3 saat)
        turkey_tz = pytz.timezone('Europe/Istanbul')
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        turkey_dt = dt.astimezone(turkey_tz)

        return turkey_dt.strftime('%d.%m.%Y %H:%M:%S')

    except Exception as e:
        print(f"DB datetime format error: {e}, value: {datetime_str}")
        return datetime_str


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
        return dict(current_user=None, is_admin=False, user_factory=None)

    return dict(
        current_user=dict(name=username),
        is_admin=is_admin,
        user_factory=session.get('factory_access')
    )

# sunucuya esp32 den  gelen veriler
@app.route('/data', methods=['POST'])
def receive_data():
    """ESP32'den gelen verileri işle - ERROR HANDLING İYİLEŞTİRİLMİŞ"""
    try:
        # 1. JSON Validation
        data = request.get_json()
        if not data:
            logger.error("❌ Boş JSON verisi alındı")
            return jsonify({"status": "error", "message": "JSON verisi gerekli"}), 400

        if 'cihaz_id' not in data:
            logger.error("❌ cihaz_id eksik")
            return jsonify({"status": "error", "message": "cihaz_id gerekli"}), 400

        cihaz_id = data['cihaz_id']
        logger.info(f"📥 Data alındı: {cihaz_id}")

        # 2. Timestamp hazırlığı
        turkey_tz = pytz.timezone('Europe/Istanbul')
        current_time_turkey = datetime.now(turkey_tz)
        timestamp = int(current_time_turkey.timestamp() * 1000)

        with get_db() as conn:
            try:
                # 3. CİHAZ İŞLEMLERİ - GÜVENLİ UPDATE/INSERT
                device_updated = conn.execute('''
                    UPDATE devices 
                    SET cihaz_adi = COALESCE(?, cihaz_adi), 
                        fabrika_adi = COALESCE(?, fabrika_adi), 
                        konum = COALESCE(?, konum), 
                        mac = COALESCE(?, mac), 
                        firmware_version = COALESCE(?, firmware_version), 
                        last_seen = ?, 
                        online_status = 1, 
                        ip_address = ?
                    WHERE cihaz_id = ?
                ''', (
                    data.get('cihaz_adi'),
                    data.get('fabrika_adi'),
                    data.get('konum'),
                    data.get('mac'),
                    data.get('firmware_version', '1.0.0'),
                    timestamp,
                    request.remote_addr,
                    cihaz_id
                )).rowcount

                # Eğer device yoksa yeni ekle
                if device_updated == 0:
                    conn.execute('''
                        INSERT INTO devices 
                        (cihaz_id, cihaz_adi, fabrika_adi, konum, mac, firmware_version, last_seen, online_status, ip_address, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ''', (
                        cihaz_id,
                        data.get('cihaz_adi', cihaz_id),
                        data.get('fabrika_adi', 'Belirtilmemiş'),
                        data.get('konum', 'Bilinmeyen'),
                        data.get('mac', ''),
                        data.get('firmware_version', '1.0.0'),
                        timestamp,
                        request.remote_addr,
                        timestamp
                    ))
                    logger.info(f"✅ Yeni cihaz eklendi: {cihaz_id}")

            except Exception as e:
                logger.error(f"❌ Device update hatası: {str(e)}")
                # Device hatası olsa bile devam et
                pass

            # 4. İŞ EMRİ İŞLEMLERİ - DETAYLI ERROR HANDLING
            if 'is_emri' in data and data['is_emri']:
                try:
                    is_emri = data['is_emri']
                    is_emri_no = is_emri.get('is_emri_no', '').strip()

                    if not is_emri_no:
                        logger.warning(f"⚠️ {cihaz_id}: İş emri numarası boş, atlanıyor")
                    else:
                        logger.info(f"🔄 İş emri işleniyor: {is_emri_no}")

                        # İş emri created_at
                        created_at_turkey = current_time_turkey.strftime('%Y-%m-%d %H:%M:%S')
                        if 'created_at' in is_emri and is_emri['created_at']:
                            created_at_turkey = is_emri['created_at']

                        # 5. ARDUINO SENSÖR VERİLERİNİ HAZIRLA
                        sensor_values = {}
                        if 'sensor_verileri' in data:
                            for veri in data['sensor_verileri']:
                                sensor_id = veri.get('sensor_id', '').lower()
                                sensor_value = float(veri.get('deger', 0))

                                # Arduino sensör mapping
                                mapping = {
                                    'aktif_calisma': 'sensor_aktif_calisma',
                                    'toplam_calisma': 'sensor_toplam_calisma',
                                    'mola_dahil_durus': 'sensor_mola_dahil_durus',
                                    'plansiz_durus': 'sensor_plansiz_durus',
                                    'mola_durus': 'sensor_mola_durus',
                                    'toplam_urun': 'sensor_toplam_urun',
                                    'tag_zamani': 'sensor_tag_zamani',
                                    'hatali_urun': 'sensor_hatali_urun',
                                    'saglam_urun': 'sensor_saglam_urun',
                                    'kullanilabilirlik': 'sensor_kullanilabilirlik',
                                    'kalite': 'sensor_kalite',
                                    'performans': 'sensor_performans',
                                    'oee': 'sensor_oee'
                                }

                                if sensor_id in mapping:
                                    sensor_values[mapping[sensor_id]] = sensor_value

                        # 6. MEVCUT İŞ EMRİNİ KONTROL ET
                        existing_work_order = conn.execute('''
                            SELECT id, is_emri_durum, gerceklesen_urun, fire_sayisi 
                            FROM work_orders 
                            WHERE cihaz_id = ? AND is_emri_no = ? 
                            ORDER BY id DESC LIMIT 1
                        ''', (cihaz_id, is_emri_no)).fetchone()

                        new_durum = int(is_emri.get('is_emri_durum', 0))
                        new_gerceklesen = is_emri.get('gerceklesen_urun', 0) or 0
                        new_fire = is_emri.get('fire_sayisi', 0) or 0

                        # Güvenli int dönüşümü
                        try:
                            new_gerceklesen = int(new_gerceklesen)
                            new_fire = int(new_fire)
                        except (ValueError, TypeError):
                            new_gerceklesen = 0
                            new_fire = 0

                        if existing_work_order:
                            # 7. MEVCUT İŞ EMRİNİ GÜNCELLE
                            work_order_id = existing_work_order['id']

                            update_query = '''
                                UPDATE work_orders SET
                                    urun_tipi = ?, hedef_urun = ?, operator_ad = ?, shift_bilgisi = ?,
                                    baslama_zamani = ?, bitis_zamani = ?, makine_durumu = ?, 
                                    is_emri_durum = ?, gerceklesen_urun = ?, fire_sayisi = ?,
                                    created_at = ?
                            '''

                            update_params = [
                                is_emri.get('urun_tipi', ''),
                                is_emri.get('hedef_urun', 0),
                                is_emri.get('operator_ad', ''),
                                is_emri.get('shift_bilgisi', ''),
                                is_emri.get('baslama_zamani', ''),
                                is_emri.get('bitis_zamani', ''),
                                is_emri.get('makine_durumu', 0),
                                new_durum,
                                new_gerceklesen,
                                new_fire,
                                created_at_turkey
                            ]

                            # Sensör değerlerini ekle
                            for sensor_key in ['sensor_aktif_calisma', 'sensor_toplam_calisma',
                                               'sensor_mola_dahil_durus',
                                               'sensor_plansiz_durus', 'sensor_mola_durus', 'sensor_toplam_urun',
                                               'sensor_tag_zamani', 'sensor_hatali_urun', 'sensor_saglam_urun',
                                               'sensor_kullanilabilirlik', 'sensor_kalite', 'sensor_performans',
                                               'sensor_oee']:
                                update_query += f', {sensor_key} = ?'
                                update_params.append(sensor_values.get(sensor_key, 0))

                            update_query += ' WHERE id = ?'
                            update_params.append(work_order_id)

                            conn.execute(update_query, update_params)
                            logger.info(f"🔄 İş emri güncellendi: {is_emri_no}")

                        else:
                            # 8. YENİ İŞ EMRİ OLUŞTUR
                            insert_query = '''
                                INSERT INTO work_orders 
                                (cihaz_id, is_emri_no, urun_tipi, hedef_urun, operator_ad, shift_bilgisi,
                                 baslama_zamani, bitis_zamani, makine_durumu, is_emri_durum, 
                                 gerceklesen_urun, fire_sayisi, created_at,
                                 sensor_aktif_calisma, sensor_toplam_calisma, sensor_mola_dahil_durus,
                                 sensor_plansiz_durus, sensor_mola_durus, sensor_toplam_urun,
                                 sensor_tag_zamani, sensor_hatali_urun, sensor_saglam_urun,
                                 sensor_kullanilabilirlik, sensor_kalite, sensor_performans, sensor_oee)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            '''

                            insert_params = [
                                cihaz_id, is_emri_no,
                                is_emri.get('urun_tipi', ''),
                                is_emri.get('hedef_urun', 0),
                                is_emri.get('operator_ad', ''),
                                is_emri.get('shift_bilgisi', ''),
                                is_emri.get('baslama_zamani', ''),
                                is_emri.get('bitis_zamani', ''),
                                is_emri.get('makine_durumu', 0),
                                new_durum, new_gerceklesen, new_fire,
                                created_at_turkey
                            ]

                            # Sensör değerlerini ekle
                            for sensor_key in ['sensor_aktif_calisma', 'sensor_toplam_calisma',
                                               'sensor_mola_dahil_durus',
                                               'sensor_plansiz_durus', 'sensor_mola_durus', 'sensor_toplam_urun',
                                               'sensor_tag_zamani', 'sensor_hatali_urun', 'sensor_saglam_urun',
                                               'sensor_kullanilabilirlik', 'sensor_kalite', 'sensor_performans',
                                               'sensor_oee']:
                                insert_params.append(sensor_values.get(sensor_key, 0))

                            cursor = conn.execute(insert_query, insert_params)
                            work_order_id = cursor.lastrowid
                            logger.info(f"✅ Yeni iş emri oluşturuldu: {is_emri_no} (ID: {work_order_id})")

                        # 9. DURUŞ VERİLERİNİ İŞLE
                        if 'duruslar' in is_emri and is_emri['duruslar']:
                            try:
                                # Eski duruşları sil
                                conn.execute('DELETE FROM downtimes WHERE work_order_id = ?', (work_order_id,))

                                # Yeni duruşları ekle
                                for durus in is_emri['duruslar']:
                                    conn.execute('''
                                        INSERT INTO downtimes (
                                            work_order_id, cihaz_id, is_emri_no, downtime_id,
                                            baslama_zamani, bitis_zamani, neden_kodu, neden_aciklama,
                                            yapilan_islem, sure_saniye, sure_dakika, sure_str
                                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    ''', (
                                        work_order_id, cihaz_id, is_emri_no,
                                        durus.get('id', ''),
                                        durus.get('baslama_zamani', ''),
                                        durus.get('bitis_zamani', ''),
                                        durus.get('neden_kodu', 0),
                                        durus.get('neden_aciklama', ''),
                                        durus.get('yapilan_islem', ''),
                                        durus.get('sure_saniye', 0),
                                        durus.get('sure_dakika', 0),
                                        durus.get('sure_str', '')
                                    ))
                                logger.info(f"✅ {len(is_emri['duruslar'])} duruş kaydedildi")
                            except Exception as e:
                                logger.error(f"❌ Duruş kayıt hatası: {str(e)}")

                        # 10. FIRE VERİLERİNİ İŞLE
                        if 'fire_kayitlari' in is_emri and is_emri['fire_kayitlari']:
                            try:
                                # Eski fire kayıtlarını sil
                                conn.execute('DELETE FROM fires WHERE work_order_id = ?', (work_order_id,))

                                # Yeni fire kayıtlarını ekle
                                for fire in is_emri['fire_kayitlari']:
                                    conn.execute('''
                                        INSERT INTO fires (
                                            work_order_id, cihaz_id, is_emri_no, fire_id,
                                            baslama_zamani, bitis_zamani, miktar, neden_kodu,
                                            neden_aciklama, aciklama, sure_saniye, sure_dakika, sure_str
                                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    ''', (
                                        work_order_id, cihaz_id, is_emri_no,
                                        fire.get('id', ''),
                                        fire.get('baslama_zamani', ''),
                                        fire.get('bitis_zamani', ''),
                                        fire.get('miktar', 0),
                                        fire.get('neden_kodu', 0),
                                        fire.get('neden_aciklama', ''),
                                        fire.get('aciklama', ''),
                                        fire.get('sure_saniye', 0),
                                        fire.get('sure_dakika', 0),
                                        fire.get('sure_str', '')
                                    ))
                                logger.info(f"✅ {len(is_emri['fire_kayitlari'])} fire kaydedildi")
                            except Exception as e:
                                logger.error(f"❌ Fire kayıt hatası: {str(e)}")

                        # *** YENİ EKLEME: ANA DÜZEY DURUŞ VERİLERİNİ İŞLE ***
                        if 'durus_verileri' in data and data['durus_verileri']:
                            try:
                                # Eski duruşları sil
                                conn.execute('DELETE FROM downtimes WHERE work_order_id = ?', (work_order_id,))

                                # Yeni duruşları ekle
                                for durus in data['durus_verileri']:
                                    conn.execute('''
                                        INSERT INTO downtimes (
                                            work_order_id, cihaz_id, is_emri_no, downtime_id,
                                            baslama_zamani, bitis_zamani, neden_kodu, neden_aciklama,
                                            yapilan_islem, sure_saniye, sure_dakika, sure_str
                                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    ''', (
                                        work_order_id, cihaz_id, is_emri_no,
                                        durus.get('id', ''),
                                        durus.get('baslama_zamani', ''),
                                        durus.get('bitis_zamani', ''),
                                        durus.get('neden_kodu', 0),
                                        durus.get('neden_aciklama', ''),
                                        durus.get('yapilan_islem', ''),
                                        durus.get('sure_saniye', 0),
                                        durus.get('sure_dakika', 0),
                                        durus.get('sure_str', '')
                                    ))
                                logger.info(f"✅ Ana düzey: {len(data['durus_verileri'])} duruş kaydedildi")
                            except Exception as e:
                                logger.error(f"❌ Ana düzey duruş kayıt hatası: {str(e)}")

                        # *** YENİ EKLEME: ANA DÜZEY FİRE VERİLERİNİ İŞLE ***
                        if 'fire_kayitlari' in data and data['fire_kayitlari']:
                            try:
                                # Eski fire kayıtlarını sil
                                conn.execute('DELETE FROM fires WHERE work_order_id = ?', (work_order_id,))

                                # Yeni fire kayıtlarını ekle
                                for fire in data['fire_kayitlari']:
                                    conn.execute('''
                                        INSERT INTO fires (
                                            work_order_id, cihaz_id, is_emri_no, fire_id,
                                            baslama_zamani, bitis_zamani, miktar, neden_kodu,
                                            neden_aciklama, aciklama, sure_saniye, sure_dakika, sure_str
                                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    ''', (
                                        work_order_id, cihaz_id, is_emri_no,
                                        fire.get('id', ''),
                                        fire.get('baslama_zamani', ''),
                                        fire.get('bitis_zamani', ''),
                                        fire.get('miktar', 0),
                                        fire.get('neden_kodu', 0),
                                        fire.get('neden_aciklama', ''),
                                        fire.get('aciklama', ''),
                                        fire.get('sure_saniye', 0),
                                        fire.get('sure_dakika', 0),
                                        fire.get('sure_str', '')
                                    ))
                                logger.info(f"✅ Ana düzey: {len(data['fire_kayitlari'])} fire kaydedildi")
                            except Exception as e:
                                logger.error(f"❌ Ana düzey fire kayıt hatası: {str(e)}")

                except Exception as e:
                    logger.error(f"❌ İş emri işleme hatası: {str(e)}")
                    # İş emri hatası olsa bile sensör verilerini kaydet

            # 11. SENSÖR VERİLERİNİ KAYDET
            if 'sensor_verileri' in data:
                try:
                    for veri in data['sensor_verileri']:
                        conn.execute('''
                            INSERT INTO sensor_data 
                            (cihaz_id, sensor_id, sensor_value, sensor_unit, timestamp)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            cihaz_id,
                            veri.get('sensor_id', ''),
                            veri.get('deger', 0),
                            veri.get('birim', ''),
                            timestamp
                        ))
                    logger.info(f"📊 {len(data['sensor_verileri'])} sensör verisi kaydedildi")
                except Exception as e:
                    logger.error(f"❌ Sensör veri kayıt hatası: {str(e)}")

            # 12. COMMIT - TÜM İŞLEMLERİ KAYDET
            conn.commit()
            logger.info(f"✅ Tüm veriler başarıyla kaydedildi: {cihaz_id}")

            return jsonify({"status": "success", "message": "Veri alındı ve işlendi"})

    except Exception as e:
        # GENEL HATA YAKALAMA
        logger.error(f"❌ KRITIK HATA - Data receive error: {str(e)}")
        logger.error(f"❌ Hata detayı: {repr(e)}")

        # Debug için gelen veriyi logla
        try:
            data_preview = str(request.data)[:500] if request.data else "No data"
            logger.error(f"❌ Gelen veri preview: {data_preview}")
        except:
            pass

        return jsonify({
            "status": "error",
            "message": "Sunucu hatası",
            "error_type": type(e).__name__,
            "debug": str(e)[:200]  # Hata mesajının ilk 200 karakteri
        }), 500

@app.route('/api/downtimes/<int:work_order_id>')
@login_required
def get_downtimes(work_order_id):
    try:
        with get_db() as conn:
            downtimes = conn.execute('''
                SELECT * FROM downtimes 
                WHERE work_order_id = ? 
                ORDER BY baslama_zamani
            ''', (work_order_id,)).fetchall()

            return jsonify({
                'success': True,
                'downtimes': [dict(d) for d in downtimes]
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/fires/<int:work_order_id>')
@login_required
def get_fires(work_order_id):
    try:
        with get_db() as conn:
            fires = conn.execute('''
                SELECT * FROM fires 
                WHERE work_order_id = ? 
                ORDER BY baslama_zamani
            ''', (work_order_id,)).fetchall()

            return jsonify({
                'success': True,
                'fires': [dict(f) for f in fires]
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


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


# app.py dosyasına eklenecek yeni endpoint'ler

# 1. İş Emri Güncelleme API
# app.py dosyasındaki mevcut update_work_order fonksiyonunu bu şekilde güncelleyin:

# iş emri güncelleme fonksiyonu
@app.route('/admin/api/work_orders/<int:work_order_id>', methods=['PUT'])
@login_required
@admin_required
def update_work_order(work_order_id):
    """Admin: İş emrini güncelle - TIMEZONE FİX"""
    try:
        data = request.get_json()

        with get_db() as conn:
            # İş emri var mı kontrol et
            work_order = conn.execute('''
                SELECT wo.*, d.cihaz_adi 
                FROM work_orders wo
                LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                WHERE wo.id = ?
            ''', (work_order_id,)).fetchone()

            if not work_order:
                return jsonify({'success': False, 'error': 'İş emri bulunamadı'}), 404

            # Güncelleme alanları
            update_fields = []
            params = []
            changes_log = []

            # Güncellenebilir alanlar
            updatable_fields = {
                'is_emri_no': 'is_emri_no',
                'urun_tipi': 'urun_tipi',
                'hedef_urun': 'hedef_urun',
                'operator_ad': 'operator_ad',
                'shift_bilgisi': 'shift_bilgisi',
                'baslama_zamani': 'baslama_zamani',
                'bitis_zamani': 'bitis_zamani',
                'makine_durumu': 'makine_durumu',
                'is_emri_durum': 'is_emri_durum',
                'gerceklesen_urun': 'gerceklesen_urun',
                'fire_sayisi': 'fire_sayisi'
            }

            for field, db_column in updatable_fields.items():
                if field in data:
                    old_value = work_order[db_column]
                    new_value = data[field]

                    # ✅ TIMEZONE FİX: Tarih alanları için özel işlem
                    if field in ['baslama_zamani', 'bitis_zamani'] and new_value:
                        try:
                            # Frontend'den gelen: "2025-06-07 14:30:00"
                            # Bu zaten Türkiye saati, UTC'ye çevirme!
                            # Direkt olarak kaydet
                            processed_value = new_value

                            # Geçerli tarih formatı kontrolü
                            datetime.strptime(processed_value, '%Y-%m-%d %H:%M:%S')

                            logger.info(f"🕒 {field} güncelleniyor: {old_value} → {processed_value} (Türkiye Saati)")

                        except ValueError:
                            return jsonify({
                                'success': False,
                                'error': f'Geçersiz tarih formatı: {new_value} (YYYY-MM-DD HH:MM:SS bekleniyor)'
                            }), 400

                        new_value = processed_value

                    # Değer değişti mi kontrol et
                    if old_value != new_value:
                        update_fields.append(f'{db_column} = ?')
                        params.append(new_value)

                        # Değişiklik logunu hazırla
                        if field == 'baslama_zamani':
                            changes_log.append(f"Başlama: {old_value or 'Boş'} → {new_value or 'Boş'}")
                        elif field == 'bitis_zamani':
                            changes_log.append(f"Bitiş: {old_value or 'Boş'} → {new_value or 'Boş'}")
                        elif field == 'fire_sayisi':
                            changes_log.append(f"Fire: {old_value or 0} → {new_value or 0}")
                        elif field == 'gerceklesen_urun':
                            changes_log.append(f"Gerçekleşen: {old_value or 0} → {new_value or 0}")
                        elif field == 'hedef_urun':
                            changes_log.append(f"Hedef: {old_value or 0} → {new_value or 0}")
                        elif field == 'is_emri_durum':
                            status_map = {0: 'Bekliyor', 1: 'Aktif', 2: 'Tamamlandı', 3: 'İptal'}
                            old_status = status_map.get(old_value, f'Durum-{old_value}')
                            new_status = status_map.get(new_value, f'Durum-{new_value}')
                            changes_log.append(f"Durum: {old_status} → {new_status}")
                        else:
                            changes_log.append(f"{field}: {old_value} → {new_value}")

            if not update_fields:
                return jsonify({'success': False, 'error': 'Güncellenecek alan bulunamadı'}), 400

            # Validation
            validation_errors = []

            # Fire sayısı kontrolü
            if 'fire_sayisi' in data:
                fire_sayisi = data['fire_sayisi']
                gerceklesen_urun = data.get('gerceklesen_urun', work_order['gerceklesen_urun'] or 0)

                if fire_sayisi < 0:
                    validation_errors.append("Fire sayısı negatif olamaz")
                elif fire_sayisi > gerceklesen_urun:
                    validation_errors.append(
                        f"Fire sayısı ({fire_sayisi}) gerçekleşen üründen ({gerceklesen_urun}) büyük olamaz")

            # Hedef ürün kontrolü
            if 'hedef_urun' in data and data['hedef_urun'] < 0:
                validation_errors.append("Hedef ürün negatif olamaz")

            # Gerçekleşen ürün kontrolü
            if 'gerceklesen_urun' in data and data['gerceklesen_urun'] < 0:
                validation_errors.append("Gerçekleşen ürün negatif olamaz")

            # Zaman doğrulaması
            if 'baslama_zamani' in data and 'bitis_zamani' in data:
                if data['baslama_zamani'] and data['bitis_zamani']:
                    try:
                        baslama = datetime.strptime(data['baslama_zamani'], '%Y-%m-%d %H:%M:%S')
                        bitis = datetime.strptime(data['bitis_zamani'], '%Y-%m-%d %H:%M:%S')
                        if baslama >= bitis:
                            validation_errors.append("Başlama zamanı bitiş zamanından önce olmalı")
                    except ValueError:
                        validation_errors.append("Geçersiz tarih formatı (YYYY-MM-DD HH:MM:SS olmalı)")

            if validation_errors:
                return jsonify({
                    'success': False,
                    'error': 'Doğrulama hataları',
                    'validation_errors': validation_errors
                }), 400

            # ✅ OTOMATIK DURUM GÜNCELLEMESİ
            if 'bitis_zamani' in data and data['bitis_zamani'] and work_order['is_emri_durum'] != 2:
                if 'is_emri_durum' not in data:
                    update_fields.append('is_emri_durum = ?')
                    params.append(2)  # Tamamlandı
                    changes_log.append("Durum: Otomatik → Tamamlandı (bitiş zamanı girildi)")

            # ✅ OTOMATIK BİTİŞ ZAMANI (Durum tamamlandı yapılırsa)
            if 'is_emri_durum' in data and data['is_emri_durum'] == 2:  # Tamamlandı
                if not work_order['bitis_zamani'] and 'bitis_zamani' not in data:
                    # Şu anki Türkiye saati
                    turkey_tz = pytz.timezone('Europe/Istanbul')
                    current_turkey_time = datetime.now(turkey_tz).strftime('%Y-%m-%d %H:%M:%S')

                    update_fields.append('bitis_zamani = ?')
                    params.append(current_turkey_time)
                    changes_log.append(f"Bitiş zamanı: Otomatik → {current_turkey_time} (Türkiye saati)")

                    logger.info(f"🕒 Otomatik bitiş zamanı eklendi: {current_turkey_time} (Türkiye saati)")

            # Güncelleme yap
            params.append(work_order_id)
            query = f"UPDATE work_orders SET {', '.join(update_fields)} WHERE id = ?"
            conn.execute(query, params)
            conn.commit()

            # Aktivite logu
            changes_summary = "; ".join(changes_log) if changes_log else "Değişiklik bulunamadı"
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type='work_order_updated',
                description=f"İş emri güncellendi: {work_order['is_emri_no']} ({work_order['cihaz_adi']}) - {changes_summary}",
                conn=conn
            )

            logger.info(f"✅ Work order updated: {work_order_id} by {session.get('username')}")
            logger.info(f"📝 Changes: {changes_summary}")

            return jsonify({
                'success': True,
                'message': 'İş emri başarıyla güncellendi',
                'changes': changes_log,
                'updated_fields': list(data.keys()),
                'work_order': {
                    'id': work_order_id,
                    'is_emri_no': work_order['is_emri_no'],
                    'cihaz_adi': work_order['cihaz_adi']
                }
            })

    except Exception as e:
        logger.error(f"❌ Update work order error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'İş emri güncellenirken hata oluştu',
            'details': str(e)
        }), 500


# iş emri silme fonksiyonu
@app.route('/admin/api/work_orders/<int:work_order_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_work_order(work_order_id):
    """Admin: İş emrini sil"""
    try:
        with get_db() as conn:
            # İş emri var mı kontrol et
            work_order = conn.execute('''
                SELECT wo.*, d.cihaz_adi 
                FROM work_orders wo
                LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                WHERE wo.id = ?
            ''', (work_order_id,)).fetchone()

            if not work_order:
                return jsonify({'success': False, 'error': 'İş emri bulunamadı'}), 404

            # Güvenlik kontrolü: Aktif iş emrini silmeden önce uyar
            if work_order['is_emri_durum'] == 1:  # Aktif
                confirm = request.args.get('confirm_active', 'false').lower()
                if confirm != 'true':
                    return jsonify({
                        'success': False,
                        'error': 'Bu iş emri halen aktif! Silmek için onay gerekli.',
                        'requires_confirmation': True
                    }), 400

            # İş emrini sil
            conn.execute('DELETE FROM work_orders WHERE id = ?', (work_order_id,))
            conn.commit()

            # Aktivite logu
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type='work_order_deleted',
                description=f"İş emri silindi: {work_order['is_emri_no']} ({work_order['cihaz_adi']})",
                conn=conn
            )

            logger.info(f"✅ Work order deleted: {work_order_id} by {session.get('username')}")

            return jsonify({
                'success': True,
                'message': f"İş emri '{work_order['is_emri_no']}' başarıyla silindi"
            })

    except Exception as e:
        logger.error(f"❌ Delete work order error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# iş emri detay fonksiyonu
@app.route('/admin/api/work_orders/<int:work_order_id>', methods=['GET'])
@login_required
@admin_required
def get_work_order_detail(work_order_id):
    """Admin: İş emri detaylarını getir"""
    try:
        with get_db() as conn:
            work_order = conn.execute('''
                SELECT wo.*, d.cihaz_adi, d.konum, d.fabrika_adi
                FROM work_orders wo
                LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                WHERE wo.id = ?
            ''', (work_order_id,)).fetchone()

            if not work_order:
                return jsonify({'success': False, 'error': 'İş emri bulunamadı'}), 404

            return jsonify({
                'success': True,
                'work_order': dict(work_order)
            })

    except Exception as e:
        logger.error(f"❌ Get work order detail error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/admin/api/work_orders/<int:work_order_id>/status', methods=['PUT'])
@login_required
@admin_required
def change_work_order_status(work_order_id):
    """Admin: İş emri durumunu değiştir"""
    try:
        data = request.get_json()
        new_status = data.get('status')

        if new_status not in [0, 1, 2, 3]:  # Bekliyor, Aktif, Tamamlandı, İptal
            return jsonify({'success': False, 'error': 'Geçersiz durum değeri'}), 400

        with get_db() as conn:
            work_order = conn.execute('''
                SELECT wo.*, d.cihaz_adi 
                FROM work_orders wo
                LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                WHERE wo.id = ?
            ''', (work_order_id,)).fetchone()

            if not work_order:
                return jsonify({'success': False, 'error': 'İş emri bulunamadı'}), 404

            old_status = work_order['is_emri_durum']
            status_names = {0: 'Bekliyor', 1: 'Aktif', 2: 'Tamamlandı', 3: 'İptal'}

            # Durumu güncelle
            update_fields = ['is_emri_durum = ?']
            params = [new_status]

            # Eğer tamamlandı yapılıyorsa ve bitiş zamanı yoksa ekle
            if new_status == 2 and not work_order['bitis_zamani']:
                update_fields.append('bitis_zamani = ?')
                params.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

            params.append(work_order_id)

            conn.execute(f'''
                UPDATE work_orders 
                SET {', '.join(update_fields)}
                WHERE id = ?
            ''', params)
            conn.commit()

            # Aktivite logu
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type='work_order_status_changed',
                description=f"İş emri durumu değiştirildi: {work_order['is_emri_no']} - {status_names.get(old_status)} → {status_names.get(new_status)}",
                conn=conn
            )

            logger.info(f"✅ Work order status changed: {work_order_id} - {old_status} → {new_status}")

            return jsonify({
                'success': True,
                'message': f"İş emri durumu '{status_names.get(new_status)}' olarak değiştirildi"
            })

    except Exception as e:
        logger.error(f"❌ Change work order status error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/work_order_report/<int:work_order_id>')
@login_required
def generate_work_order_pdf_report(work_order_id):
    """İş emri PDF raporu oluştur - GERÇEK TÜRKÇE FİX"""
    try:
        with get_db() as conn:
            # İş emri bilgileri - ROW TO DICT FIX
            work_order_raw = conn.execute('''
                SELECT wo.*, d.cihaz_adi, d.konum, d.fabrika_adi
                FROM work_orders wo
                LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                WHERE wo.id = ?
            ''', (work_order_id,)).fetchone()

            if not work_order_raw:
                return jsonify({'error': 'İş emri bulunamadı'}), 404

            # 🔧 ROW'u DICT'e çevir
            work_order = dict(work_order_raw)

            # Duruş ve fire kayıtları - ROW TO DICT FIX
            downtime_records_raw = conn.execute('''
                SELECT * FROM downtimes WHERE work_order_id = ? ORDER BY baslama_zamani
            ''', (work_order_id,)).fetchall()

            fire_records_raw = conn.execute('''
                SELECT * FROM fires WHERE work_order_id = ? ORDER BY baslama_zamani
            ''', (work_order_id,)).fetchall()

            # 🔧 ROW'ları DICT'e çevir
            downtime_records = [dict(row) for row in downtime_records_raw]
            fire_records = [dict(row) for row in fire_records_raw]

        # PDF oluştur
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1 * inch)

        # 🌟 GERÇEK TÜRKÇE KARAKTER FİX
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.fonts import addMapping

        # DejaVu Sans font yükle (Türkçe karakterleri destekler)
        try:
            # İlk önce sistem fontlarını dene
            import os
            font_paths = [
                '/System/Library/Fonts/Arial.ttf',  # macOS
                'C:/Windows/Fonts/arial.ttf',  # Windows
                '/usr/share/fonts/truetype/arial.ttf',  # Linux
                '/usr/share/fonts/TTF/DejaVuSans.ttf',  # Linux DejaVu
                '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',  # Linux DejaVu
            ]

            font_registered = False
            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        pdfmetrics.registerFont(TTFont('TurkishFont', font_path))
                        font_registered = True
                        logger.info(f"✅ Font yüklendi: {font_path}")
                        break
                    except Exception as e:
                        logger.warning(f"⚠️ Font yükleme hatası {font_path}: {e}")
                        continue

            if not font_registered:
                # Fallback: Helvetica kullan (sınırlı Türkçe desteği)
                logger.warning("⚠️ TrueType font bulunamadı, Helvetica kullanılıyor")
                font_name = 'Helvetica'
                font_name_bold = 'Helvetica-Bold'
            else:
                font_name = 'TurkishFont'
                font_name_bold = 'TurkishFont'

        except Exception as e:
            logger.error(f"❌ Font yükleme genel hatası: {e}")
            font_name = 'Helvetica'
            font_name_bold = 'Helvetica-Bold'

        # Stiller - Türkçe uyumlu
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'TurkishTitle',
            parent=styles['Title'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName=font_name_bold,
            encoding='utf-8'
        )

        heading_style = ParagraphStyle(
            'TurkishHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkblue,
            fontName=font_name_bold,
            encoding='utf-8'
        )

        normal_style = ParagraphStyle(
            'TurkishNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            fontName=font_name,
            encoding='utf-8'
        )

        # 🌟 UTF-8 TEXT FUNCTİON
        def turkish_text(text):
            """UTF-8 Türkçe metin işleme"""
            if not text:
                return 'N/A'

            # String'e çevir ve UTF-8 encode et
            try:
                text_str = str(text)
                # Unicode normalize et
                import unicodedata
                normalized = unicodedata.normalize('NFC', text_str)
                return normalized
            except Exception as e:
                logger.warning(f"Text encoding hatası: {e}")
                return str(text)

        # PDF içeriği
        story = []

        # Başlık
        story.append(Paragraph(turkish_text("İŞ EMRİ RAPORU"), title_style))
        story.append(Paragraph(turkish_text(f"İŞ EMRİ #{work_order['is_emri_no'] or 'N/A'}"), title_style))
        story.append(Spacer(1, 20))

        # Temel Bilgiler
        story.append(Paragraph(turkish_text("TEMEL BİLGİLER"), heading_style))

        basic_data = [
            [turkish_text('İş Emri No:'), turkish_text(work_order['is_emri_no'] or 'N/A')],
            [turkish_text('Cihaz:'), turkish_text(work_order['cihaz_adi'] or 'N/A')],
            [turkish_text('Fabrika:'), turkish_text(work_order['fabrika_adi'] or 'N/A')],
            [turkish_text('Konum:'), turkish_text(work_order['konum'] or 'N/A')],
            [turkish_text('Ürün Tipi:'), turkish_text(work_order['urun_tipi'] or 'N/A')],
            [turkish_text('Operatör:'), turkish_text(work_order['operator_ad'] or 'N/A')],
            [turkish_text('Vardiya:'), turkish_text(work_order['shift_bilgisi'] or 'N/A')],
            [turkish_text('Başlama:'), turkish_text(work_order['baslama_zamani'] or 'N/A')],
            [turkish_text('Bitiş:'), turkish_text(work_order['bitis_zamani'] or 'N/A')]
        ]

        basic_table = Table(basic_data, colWidths=[2.5 * inch, 4 * inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
        ]))

        story.append(basic_table)
        story.append(Spacer(1, 20))

        # Performans Bilgileri
        story.append(Paragraph(turkish_text("PERFORMANS BİLGİLERİ"), heading_style))

        def safe_value(value, default='N/A'):
            return str(value) if value is not None else default

        def safe_percent(value, default='N/A'):
            try:
                return f"{float(value):.1f}%" if value is not None else default
            except (ValueError, TypeError):
                return default

        performance_data = [
            [turkish_text('Hedef Ürün:'), turkish_text(f"{safe_value(work_order['hedef_urun'])} adet")],
            [turkish_text('Gerçekleşen Ürün:'), turkish_text(f"{safe_value(work_order['gerceklesen_urun'])} adet")],
            [turkish_text('Fire Sayısı:'), turkish_text(f"{safe_value(work_order['fire_sayisi'])} adet")],
            [turkish_text('Sağlam Ürün:'), turkish_text(
                f"{safe_value((work_order['gerceklesen_urun'] or 0) - (work_order['fire_sayisi'] or 0))} adet")],
            [turkish_text('Arduino OEE:'), turkish_text(safe_percent(work_order.get('sensor_oee')))],
            [turkish_text('Kullanılabilirlik:'),
             turkish_text(safe_percent(work_order.get('sensor_kullanilabilirlik')))],
            [turkish_text('Performans:'), turkish_text(safe_percent(work_order.get('sensor_performans')))],
            [turkish_text('Kalite:'), turkish_text(safe_percent(work_order.get('sensor_kalite')))]
        ]

        performance_table = Table(performance_data, colWidths=[2.5 * inch, 4 * inch])
        performance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgreen),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
        ]))

        story.append(performance_table)
        story.append(Spacer(1, 20))

        # 🔥 FIRE ANALİZİ
        if fire_records:
            story.append(Paragraph(turkish_text("FIRE ANALİZİ"), heading_style))

            fire_data = [
                [turkish_text('Fire ID'), turkish_text('Başlama'), turkish_text('Bitiş'),
                 turkish_text('Miktar'), turkish_text('Neden'), turkish_text('Açıklama')]
            ]

            total_fire_amount = 0

            for record in fire_records:
                try:
                    fire_amount = record['miktar'] or 0
                    total_fire_amount += fire_amount

                    # Neden kodları
                    reason_map = {
                        1: 'MALZEME HATASI',
                        2: 'İŞLEM HATASI',
                        3: 'MAKİNE HATASI',
                        4: 'OPERATÖR HATASI',
                        5: 'DİĞER'
                    }

                    reason_text = reason_map.get(record['neden_kodu'],
                                                 f"Kod {record['neden_kodu']}" if record['neden_kodu'] else 'N/A')

                    fire_data.append([
                        turkish_text(record['fire_id'] or 'N/A'),
                        turkish_text(record['baslama_zamani'] or 'N/A'),
                        turkish_text(record['bitis_zamani'] or 'N/A'),
                        turkish_text(f"{fire_amount} adet"),
                        turkish_text(reason_text),
                        turkish_text(record['neden_aciklama'] or record['aciklama'] or 'N/A')
                    ])

                except Exception as e:
                    logger.error(f"Fire rapor hatası: {e}")

            # Toplam satırı
            if total_fire_amount > 0:
                fire_data.append([
                    turkish_text('TOPLAM'), '', '',
                    turkish_text(f'{total_fire_amount} adet'),
                    turkish_text(f'{len(fire_records)} kayıt'), ''
                ])

            # Fire tablosu
            fire_table = Table(fire_data,
                               colWidths=[1 * inch, 1.3 * inch, 1.3 * inch, 0.8 * inch, 0.8 * inch, 1.3 * inch])
            fire_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (-1, -1), (-1, -1), colors.orange) if total_fire_amount > 0 else ('BACKGROUND', (-1, -1),
                                                                                                 (-1, -1),
                                                                                                 colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, -1), font_name),
            ]))

            story.append(fire_table)
            story.append(Spacer(1, 20))

        # Duruş Analizi
        if downtime_records:
            story.append(Paragraph(turkish_text("DURUŞ ANALİZİ"), heading_style))

            downtime_data = [
                [turkish_text('Duruş ID'), turkish_text('Başlama'), turkish_text('Bitiş'),
                 turkish_text('Süre'), turkish_text('Neden'), turkish_text('Açıklama')]
            ]

            total_downtime = 0

            for record in downtime_records:
                try:
                    duration_seconds = record['sure_saniye'] or 0
                    total_downtime += duration_seconds

                    hours, remainder = divmod(int(duration_seconds), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                    reason_map = {
                        1: 'BAKIM',
                        2: 'ARIZA',
                        3: 'MALZEME',
                        4: 'MOLA',
                        5: 'DİĞER'
                    }

                    reason_text = reason_map.get(record['neden_kodu'],
                                                 f"Kod {record['neden_kodu']}" if record['neden_kodu'] else 'N/A')

                    downtime_data.append([
                        turkish_text(record['downtime_id'] or 'N/A'),
                        turkish_text(record['baslama_zamani'] or 'N/A'),
                        turkish_text(record['bitis_zamani'] or 'N/A'),
                        turkish_text(duration_str),
                        turkish_text(reason_text),
                        turkish_text(record['neden_aciklama'] or 'N/A')
                    ])

                except Exception as e:
                    logger.error(f"Duruş rapor hatası: {e}")

            # Toplam satırı
            if total_downtime > 0:
                total_hours, remainder = divmod(int(total_downtime), 3600)
                total_minutes, total_seconds = divmod(remainder, 60)
                total_duration_str = f"{total_hours:02d}:{total_minutes:02d}:{total_seconds:02d}"

                downtime_data.append([
                    turkish_text('TOPLAM'), '', '', turkish_text(total_duration_str),
                    turkish_text(f'{len(downtime_records)} duruş'), ''
                ])

            # Duruş tablosu
            downtime_table = Table(downtime_data,
                                   colWidths=[1 * inch, 1.3 * inch, 1.3 * inch, 0.8 * inch, 0.8 * inch, 1.3 * inch])
            downtime_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (-1, -1), (-1, -1), colors.orange) if total_downtime > 0 else ('BACKGROUND', (-1, -1),
                                                                                              (-1, -1), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, -1), font_name),
            ]))

            story.append(downtime_table)

        # Footer
        current_time = datetime.now()
        footer_text = turkish_text(f"Rapor Tarihi: {current_time.strftime('%d.%m.%Y %H:%M:%S')}")
        footer_text += turkish_text(f"<br/>Raporu Oluşturan: {session.get('username', 'N/A')}")
        story.append(Spacer(1, 20))
        story.append(Paragraph(footer_text, normal_style))

        # PDF'i oluştur
        doc.build(story)
        buffer.seek(0)

        # Türkçe karaktersiz dosya adı
        work_order_number = work_order['is_emri_no'] or 'UNKNOWN'
        safe_work_order_number = (work_order_number
                                  .replace('İ', 'I').replace('ı', 'i')
                                  .replace('Ş', 'S').replace('ş', 's')
                                  .replace('Ğ', 'G').replace('ğ', 'g')
                                  .replace('Ü', 'U').replace('ü', 'u')
                                  .replace('Ö', 'O').replace('ö', 'o')
                                  .replace('Ç', 'C').replace('ç', 'c'))

        filename = f"is_emri_rapor_{safe_work_order_number}_{current_time.strftime('%Y%m%d_%H%M%S')}.pdf"

        logger.info(f"✅ PDF raporu oluşturuldu (GERÇEK Türkçe + Fire): {filename}")

        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )

    except Exception as e:
        logger.error(f"❌ PDF rapor oluşturma hatası: {str(e)}")
        return jsonify({'error': f'PDF oluşturma hatası: {str(e)}'}), 500


@app.route('/api/work_order_excel/<int:work_order_id>')
@login_required
def generate_work_order_excel_report(work_order_id):
    """İş emri Excel raporu oluştur - FIRE VERİLERİ DAHİL"""
    try:
        with get_db() as conn:
            # İş emri bilgilerini al
            work_order = conn.execute('''
                SELECT wo.*, d.cihaz_adi, d.konum, d.fabrika_adi
                FROM work_orders wo
                LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                WHERE wo.id = ?
            ''', (work_order_id,)).fetchone()

            if not work_order:
                return jsonify({'error': 'İş emri bulunamadı'}), 404

            # Duruş verilerini al
            downtimes = conn.execute('''
                SELECT * FROM downtimes 
                WHERE work_order_id = ? 
                ORDER BY baslama_zamani
            ''', (work_order_id,)).fetchall()

            # 🔥 FIRE VERİLERİNİ AL - YENİ!
            fires = conn.execute('''
                SELECT * FROM fires 
                WHERE work_order_id = ? 
                ORDER BY baslama_zamani
            ''', (work_order_id,)).fetchall()

            # Sensör verilerini al (iş emri süresince)
            sensor_data = []
            if work_order['baslama_zamani'] and work_order['bitis_zamani']:
                try:
                    start_time = datetime.strptime(work_order['baslama_zamani'], '%Y-%m-%d %H:%M:%S')
                    end_time = datetime.strptime(work_order['bitis_zamani'], '%Y-%m-%d %H:%M:%S')

                    start_timestamp = int(start_time.timestamp() * 1000)
                    end_timestamp = int(end_time.timestamp() * 1000)

                    sensor_data = conn.execute('''
                        SELECT * FROM sensor_data 
                        WHERE cihaz_id = ? AND timestamp >= ? AND timestamp <= ?
                        ORDER BY timestamp
                    ''', (work_order['cihaz_id'], start_timestamp, end_timestamp)).fetchall()
                except:
                    pass

            # Excel dosyası oluştur
            output = io.BytesIO()

            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                # 1. İş Emri Özeti
                summary_data = {
                    'Alan': ['İş Emri No', 'Cihaz', 'Fabrika', 'Konum', 'Ürün Tipi', 'Operatör', 'Vardiya',
                             'Başlama Zamanı', 'Bitiş Zamanı', 'Durum', 'Hedef Ürün', 'Gerçekleşen Ürün',
                             'Fire Sayısı', 'Sağlam Ürün', 'Verimlilik (%)', 'Kalite (%)'],
                    'Değer': [
                        work_order['is_emri_no'] or 'N/A',
                        work_order['cihaz_adi'] or 'N/A',
                        work_order['fabrika_adi'] or 'N/A',
                        work_order['konum'] or 'N/A',
                        work_order['urun_tipi'] or 'N/A',
                        work_order['operator_ad'] or 'N/A',
                        work_order['shift_bilgisi'] or 'N/A',
                        work_order['baslama_zamani'] or 'N/A',
                        work_order['bitis_zamani'] or 'N/A',
                        'Tamamlandı' if work_order['is_emri_durum'] == 2 else 'Aktif' if work_order[
                                                                                             'is_emri_durum'] == 1 else 'Bekliyor',
                        work_order['hedef_urun'] or 0,
                        work_order['gerceklesen_urun'] or 0,
                        work_order['fire_sayisi'] or 0,
                        (work_order['gerceklesen_urun'] or 0) - (work_order['fire_sayisi'] or 0),
                        round((work_order['gerceklesen_urun'] or 0) * 100 / (work_order['hedef_urun'] or 1), 1) if
                        work_order['hedef_urun'] else 0,
                        round(((work_order['gerceklesen_urun'] or 0) - (work_order['fire_sayisi'] or 0)) * 100 / (
                                    work_order['gerceklesen_urun'] or 1), 1) if work_order['gerceklesen_urun'] else 0
                    ]
                }

                df_summary = pd.DataFrame(summary_data)
                df_summary.to_excel(writer, sheet_name='İş Emri Özeti', index=False)

                # 2. Arduino Sensör Verileri (varsa)
                if any([work_order[f'sensor_{sensor}'] for sensor in
                        ['oee', 'kullanilabilirlik', 'kalite', 'performans', 'aktif_calisma', 'toplam_calisma',
                         'toplam_urun', 'hatali_urun', 'saglam_urun']]):
                    arduino_data = {
                        'Sensör': ['OEE', 'Kullanılabilirlik', 'Kalite', 'Performans', 'Aktif Çalışma',
                                   'Toplam Çalışma', 'Toplam Ürün', 'Hatalı Ürün', 'Sağlam Ürün'],
                        'Değer': [
                            work_order['sensor_oee'] or 0,
                            work_order['sensor_kullanilabilirlik'] or 0,
                            work_order['sensor_kalite'] or 0,
                            work_order['sensor_performans'] or 0,
                            work_order['sensor_aktif_calisma'] or 0,
                            work_order['sensor_toplam_calisma'] or 0,
                            work_order['sensor_toplam_urun'] or 0,
                            work_order['sensor_hatali_urun'] or 0,
                            work_order['sensor_saglam_urun'] or 0
                        ],
                        'Birim': ['%', '%', '%', '%', 'dk', 'dk', 'adet', 'adet', 'adet']
                    }

                    df_arduino = pd.DataFrame(arduino_data)
                    df_arduino.to_excel(writer, sheet_name='Arduino Sensör Verileri', index=False)

                # 3. 🔥 FIRE VERİLERİ - YENİ SHEET!
                if fires:
                    fire_data = []
                    total_fire_amount = 0

                    for fire in fires:
                        fire_amount = fire['miktar'] or 0
                        total_fire_amount += fire_amount

                        # Süreyi formatla
                        duration_seconds = fire['sure_saniye'] or 0
                        hours, remainder = divmod(int(duration_seconds), 3600)
                        minutes, seconds = divmod(remainder, 60)
                        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                        # Neden kodlarını çevir
                        reason_map = {
                            1: 'MALZEME HATASI',
                            2: 'İŞLEM HATASI',
                            3: 'MAKİNE HATASI',
                            4: 'OPERATÖR HATASI',
                            5: 'DİĞER'
                        }

                        reason_text = reason_map.get(fire['neden_kodu'], f"Kod {fire['neden_kodu']}" if fire[
                            'neden_kodu'] else 'Belirtilmemiş')

                        fire_data.append({
                            'Fire ID': fire['fire_id'] or 'N/A',
                            'Başlama Zamanı': fire['baslama_zamani'] or 'N/A',
                            'Bitiş Zamanı': fire['bitis_zamani'] or 'N/A',
                            'Süre (HH:MM:SS)': duration_str,
                            'Süre (Saniye)': fire['sure_saniye'] or 0,
                            'Süre (Dakika)': fire['sure_dakika'] or 0,
                            'Fire Miktarı (adet)': fire_amount,
                            'Neden Kodu': fire['neden_kodu'] or 0,
                            'Neden': reason_text,
                            'Neden Açıklama': fire['neden_aciklama'] or 'N/A',
                            'Ek Açıklama': fire['aciklama'] or 'N/A'
                        })

                    # Toplam satırı ekle
                    fire_data.append({
                        'Fire ID': 'TOPLAM',
                        'Başlama Zamanı': '',
                        'Bitiş Zamanı': '',
                        'Süre (HH:MM:SS)': '',
                        'Süre (Saniye)': '',
                        'Süre (Dakika)': '',
                        'Fire Miktarı (adet)': total_fire_amount,
                        'Neden Kodu': '',
                        'Neden': f'{len(fires)} kayıt',
                        'Neden Açıklama': '',
                        'Ek Açıklama': f'Toplam {total_fire_amount} adet fire'
                    })

                    df_fires = pd.DataFrame(fire_data)
                    df_fires.to_excel(writer, sheet_name='Fire Verileri', index=False)

                # 4. Duruş Verileri
                if downtimes:
                    downtime_data = []
                    total_downtime_seconds = 0

                    for dt in downtimes:
                        duration_seconds = dt['sure_saniye'] or 0
                        total_downtime_seconds += duration_seconds

                        # Süreyi formatla
                        hours, remainder = divmod(int(duration_seconds), 3600)
                        minutes, seconds = divmod(remainder, 60)
                        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                        # Neden kodlarını çevir
                        reason_map = {
                            1: 'BAKIM',
                            2: 'ARIZA',
                            3: 'MALZEME',
                            4: 'MOLA',
                            5: 'DİĞER'
                        }

                        reason_text = reason_map.get(dt['neden_kodu'],
                                                     f"Kod {dt['neden_kodu']}" if dt['neden_kodu'] else 'Belirtilmemiş')

                        downtime_data.append({
                            'Duruş ID': dt['downtime_id'] or 'N/A',
                            'Başlama Zamanı': dt['baslama_zamani'] or 'N/A',
                            'Bitiş Zamanı': dt['bitis_zamani'] or 'N/A',
                            'Süre (HH:MM:SS)': duration_str,
                            'Süre (Saniye)': dt['sure_saniye'] or 0,
                            'Süre (Dakika)': dt['sure_dakika'] or 0,
                            'Süre (Metin)': dt['sure_str'] or 'N/A',
                            'Neden Kodu': dt['neden_kodu'] or 0,
                            'Neden': reason_text,
                            'Neden Açıklama': dt['neden_aciklama'] or 'N/A',
                            'Yapılan İşlem': dt['yapilan_islem'] or 'N/A'
                        })

                    # Toplam duruş süresi
                    total_hours, remainder = divmod(int(total_downtime_seconds), 3600)
                    total_minutes, total_secs = divmod(remainder, 60)
                    total_duration_str = f"{total_hours:02d}:{total_minutes:02d}:{total_secs:02d}"

                    # Toplam satırı ekle
                    downtime_data.append({
                        'Duruş ID': 'TOPLAM',
                        'Başlama Zamanı': '',
                        'Bitiş Zamanı': '',
                        'Süre (HH:MM:SS)': total_duration_str,
                        'Süre (Saniye)': total_downtime_seconds,
                        'Süre (Dakika)': round(total_downtime_seconds / 60, 1),
                        'Süre (Metin)': f'{len(downtimes)} duruş',
                        'Neden Kodu': '',
                        'Neden': f'{len(downtimes)} kayıt',
                        'Neden Açıklama': '',
                        'Yapılan İşlem': f'Toplam {total_duration_str}'
                    })

                    df_downtimes = pd.DataFrame(downtime_data)
                    df_downtimes.to_excel(writer, sheet_name='Duruş Verileri', index=False)

                # 5. Sensör Ham Verileri (varsa)
                if sensor_data:
                    sensor_raw_data = []
                    for sd in sensor_data:
                        sensor_raw_data.append({
                            'Tarih/Saat': datetime.fromtimestamp(sd['timestamp'] / 1000).strftime('%d.%m.%Y %H:%M:%S'),
                            'Sensör ID': sd['sensor_id'],
                            'Değer': sd['sensor_value'],
                            'Birim': sd['sensor_unit'] or 'N/A'
                        })

                    df_sensor_raw = pd.DataFrame(sensor_raw_data)
                    df_sensor_raw.to_excel(writer, sheet_name='Ham Sensör Verileri', index=False)

                # 6. 📊 ÖZET İSTATİSTİKLER - YENİ SHEET!
                summary_stats = {
                    'Metrik': [
                        'Toplam Üretim Hedefi',
                        'Gerçekleşen Üretim',
                        'Toplam Fire Miktarı',
                        'Sağlam Ürün',
                        'Hedef Tutturma Oranı (%)',
                        'Kalite Oranı (%)',
                        'Fire Oranı (%)',
                        'Toplam Duruş Süresi (dk)',
                        'Toplam Fire Kayıt Sayısı',
                        'Toplam Duruş Kayıt Sayısı',
                        'Arduino OEE (%)',
                        'Arduino Kullanılabilirlik (%)',
                        'Arduino Performans (%)',
                        'Arduino Kalite (%)'
                    ],
                    'Değer': [
                        work_order['hedef_urun'] or 0,
                        work_order['gerceklesen_urun'] or 0,
                        sum([f['miktar'] or 0 for f in fires]) if fires else (work_order['fire_sayisi'] or 0),
                        (work_order['gerceklesen_urun'] or 0) - (work_order['fire_sayisi'] or 0),
                        round((work_order['gerceklesen_urun'] or 0) * 100 / (work_order['hedef_urun'] or 1), 2) if
                        work_order['hedef_urun'] else 0,
                        round(((work_order['gerceklesen_urun'] or 0) - (work_order['fire_sayisi'] or 0)) * 100 / (
                                    work_order['gerceklesen_urun'] or 1), 2) if work_order['gerceklesen_urun'] else 0,
                        round((work_order['fire_sayisi'] or 0) * 100 / (work_order['gerceklesen_urun'] or 1), 2) if
                        work_order['gerceklesen_urun'] else 0,
                        round(total_downtime_seconds / 60, 1) if downtimes else 0,
                        len(fires) if fires else 0,
                        len(downtimes) if downtimes else 0,
                        work_order['sensor_oee'] or 0,
                        work_order['sensor_kullanilabilirlik'] or 0,
                        work_order['sensor_performans'] or 0,
                        work_order['sensor_kalite'] or 0
                    ]
                }

                df_summary_stats = pd.DataFrame(summary_stats)
                df_summary_stats.to_excel(writer, sheet_name='Özet İstatistikler', index=False)

            output.seek(0)

            # Fire miktarını dosya adına ekle
            total_fire_from_records = sum([f['miktar'] or 0 for f in fires]) if fires else (
                        work_order['fire_sayisi'] or 0)
            fire_suffix = f"_fire_{total_fire_from_records}" if total_fire_from_records > 0 else ""

            # Türkçe karaktersiz dosya adı
            work_order_name = (work_order['is_emri_no'] or 'UNKNOWN').replace('İ', 'I').replace('ı', 'i').replace('Ş',
                                                                                                                  'S').replace(
                'ş', 's').replace('Ğ', 'G').replace('ğ', 'g').replace('Ü', 'U').replace('ü', 'u').replace('Ö',
                                                                                                          'O').replace(
                'ö', 'o').replace('Ç', 'C').replace('ç', 'c')

            filename = f"is_emri_excel_{work_order_name}{fire_suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

            logger.info(f"✅ Excel raporu oluşturuldu (Fire dahil): {filename}")

            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=filename
            )

    except Exception as e:
        logger.error(f"❌ Excel report error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# toplu iş emirleri fonksiyonu
@app.route('/admin/api/work_orders/bulk', methods=['POST'])
@login_required
@admin_required
def bulk_work_order_operations():
    """Admin: Toplu iş emri işlemleri"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'delete', 'change_status', 'export'
        work_order_ids = data.get('work_order_ids', [])

        if not work_order_ids:
            return jsonify({'success': False, 'error': 'İş emri seçilmedi'}), 400

        with get_db() as conn:
            if action == 'delete':
                # Toplu silme
                placeholders = ','.join(['?'] * len(work_order_ids))

                # Silinecek iş emirlerini al (log için)
                work_orders = conn.execute(f'''
                    SELECT wo.is_emri_no, d.cihaz_adi 
                    FROM work_orders wo
                    LEFT JOIN devices d ON wo.cihaz_id = d.cihaz_id
                    WHERE wo.id IN ({placeholders})
                ''', work_order_ids).fetchall()

                # Sil
                cursor = conn.execute(f'DELETE FROM work_orders WHERE id IN ({placeholders})', work_order_ids)
                deleted_count = cursor.rowcount

                # Aktivite logu
                work_order_names = [wo['is_emri_no'] for wo in work_orders]
                log_user_activity(
                    user_id=session.get('user_id', 1),
                    activity_type='bulk_work_order_delete',
                    description=f"Toplu iş emri silme: {deleted_count} adet - {', '.join(work_order_names)}",
                    conn=conn
                )

                conn.commit()
                return jsonify({
                    'success': True,
                    'message': f'{deleted_count} iş emri başarıyla silindi'
                })

            elif action == 'change_status':
                # Toplu durum değiştirme
                new_status = data.get('new_status')
                if new_status not in [0, 1, 2, 3]:
                    return jsonify({'success': False, 'error': 'Geçersiz durum değeri'}), 400

                placeholders = ','.join(['?'] * len(work_order_ids))
                params = [new_status] + work_order_ids

                cursor = conn.execute(f'''
                    UPDATE work_orders 
                    SET is_emri_durum = ?
                    WHERE id IN ({placeholders})
                ''', params)
                updated_count = cursor.rowcount

                status_names = {0: 'Bekliyor', 1: 'Aktif', 2: 'Tamamlandı', 3: 'İptal'}

                # Aktivite logu
                log_user_activity(
                    user_id=session.get('user_id', 1),
                    activity_type='bulk_work_order_status_change',
                    description=f"Toplu durum değiştirme: {updated_count} iş emri → {status_names.get(new_status)}",
                    conn=conn
                )

                conn.commit()
                return jsonify({
                    'success': True,
                    'message': f'{updated_count} iş emrinin durumu değiştirildi'
                })

            else:
                return jsonify({'success': False, 'error': 'Geçersiz işlem'}), 400

    except Exception as e:
        logger.error(f"❌ Bulk work order operations error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# iş emri özeti fonksiyonu
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

        # Bu ay ortalama OEE - SENSOR_DATA tablosundan al (work_orders'da oee kolonu yok!)
        avg_oee = conn.execute('''
            SELECT AVG(sensor_value) as avg_oee FROM sensor_data 
            WHERE cihaz_id = ? AND sensor_id = 'OEE'
            AND timestamp >= (strftime('%s', datetime('now', 'start of month')) * 1000)
        ''', (cihaz_id,)).fetchone()

        return jsonify({
            'active_work_order': dict(active) if active else None,
            'completed_last_30_days': completed['count'],
            'average_oee': round(avg_oee['avg_oee'] or 0, 1)
        })


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


@app.route('/')
@login_required
def index():
    user_factory = session.get('factory_access')
    is_admin = session.get('is_admin', False)
    with get_db() as conn:
        current_time_ms = int(time.time() * 1000)
        threshold = current_time_ms - 120000  # 2 dakika

        # ✅ DOĞRU sütun adını kullan
        if is_admin or not user_factory:
            # Admin - tüm cihazlar
            cihazlar_raw = conn.execute('''
                SELECT *,
                    CASE 
                        WHEN CAST(last_seen AS INTEGER) >= ? AND last_seen > 0 THEN 1 
                        ELSE 0 
                    END as real_online_status
                FROM devices 
                ORDER BY cihaz_adi ASC
            ''', (threshold,)).fetchall()
        else:
            # Normal kullanıcı - sadece kendi fabrikası
            cihazlar_raw = conn.execute('''
                SELECT *,
                    CASE 
                        WHEN CAST(last_seen AS INTEGER) >= ? AND last_seen > 0 THEN 1 
                        ELSE 0 
                    END as real_online_status
                FROM devices 
                WHERE fabrika_adi = ? OR fabrika_adi IS NULL
                ORDER BY cihaz_adi ASC
            ''', (threshold, user_factory)).fetchall()

        cihazlar = []
        for cihaz in cihazlar_raw:
            cihaz_dict = dict(cihaz)

            # ✅ CIHAZ_DETAY.HTML İLE AYNI YÖNTEMİ KULLAN - Her sensörün en son değerini al
            sensor_data = conn.execute('''
                SELECT s1.sensor_id, s1.sensor_value, s1.sensor_unit, s1.timestamp
                FROM sensor_data s1
                JOIN (
                    SELECT sensor_id, MAX(timestamp) as max_timestamp
                    FROM sensor_data
                    WHERE cihaz_id = ?
                    GROUP BY sensor_id
                ) s2 ON s1.sensor_id = s2.sensor_id AND s1.timestamp = s2.max_timestamp
                WHERE s1.cihaz_id = ?
                ORDER BY s1.sensor_id
            ''', (cihaz['cihaz_id'], cihaz['cihaz_id'])).fetchall()

            # En son sensör verilerini işle
            latest_sensors = {}
            for data in sensor_data:
                sensor_id = data['sensor_id']
                latest_sensors[sensor_id] = {
                    'value': data['sensor_value'],
                    'unit': data['sensor_unit'],
                    'timestamp': data['timestamp']
                }

            # OEE ve diğer önemli metrikleri al
            cihaz_dict.update({
                'sensor_oee': latest_sensors.get('OEE', {}).get('value', None),
                'sensor_total_products': latest_sensors.get('toplam_urun', {}).get('value', None),
                'sensor_active_time': latest_sensors.get('aktif_calisma', {}).get('value', None),
                'sensor_total_time': latest_sensors.get('toplam_calisma', {}).get('value', None),
                'sensor_quality': latest_sensors.get('kalite', {}).get('value', None),
                'sensor_performance': latest_sensors.get('performans', {}).get('value', None),
                'sensor_availability': latest_sensors.get('kullanilabilirlik', {}).get('value', None)
            })

            cihazlar.append(cihaz_dict)

        # Debug bilgisi
        app.logger.info(f"📊 Cihaz Durumu Debug:")
        app.logger.info(f"   Şu anki zaman: {current_time_ms}")
        app.logger.info(f"   Threshold (2 dk önce): {threshold}")
        app.logger.info(f"   Toplam cihaz: {len(cihazlar)}")

        online_count = 0
        offline_count = 0

        for cihaz in cihazlar:
            if cihaz['real_online_status']:
                app.logger.info(
                    f"   🟢 {cihaz['cihaz_adi']} - {cihaz['fabrika_adi']}: ONLINE (OEE: {cihaz.get('sensor_oee', 'None')})")
                online_count += 1
            else:
                app.logger.info(f"   🔴 {cihaz['cihaz_adi']} - {cihaz['fabrika_adi']}: OFFLINE")
                offline_count += 1

        app.logger.info(f"   📈 Online: {online_count}, Offline: {offline_count}")

        return render_template('index.html', cihazlar=cihazlar)


def update_device_status():
    """Cihaz durumlarını güncelle - düzeltilmiş versiyon"""
    with app.app_context():
        try:
            current_time_ms = int(time.time() * 1000)
            threshold = current_time_ms - 120000  # 2 dakika

            with get_db() as conn:
                # ✅ DÜZELT: CAST ekle güvenlik için
                cursor = conn.execute('''
                    UPDATE devices 
                    SET online_status = CASE 
                        WHEN CAST(last_seen AS INTEGER) >= ? AND last_seen > 0 THEN 1 
                        ELSE 0 
                    END
                ''', (threshold,))

                updated_count = cursor.rowcount
                conn.commit()

                if updated_count > 0:
                    app.logger.info(f"📊 {updated_count} cihazın durumu güncellendi")

        except Exception as e:
            app.logger.error(f"❌ Cihaz durum güncelleme hatası: {e}")


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
                    WHEN CAST(last_seen AS INTEGER) >= ? AND last_seen > 0 THEN 1 
                    ELSE 0 
                END as calculated_online_status,
                CASE 
                    WHEN last_seen > 0 THEN (? - CAST(last_seen AS INTEGER)) / 1000 
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
            session['factory_access'] = None  # Admin tüm fabrikalara erişir
            session['login_time'] = datetime.now().isoformat()

            clear_login_attempts(client_ip)

            # Güvenlik logu
            logger.info(f"Admin login successful from IP: {client_ip}")

            flash('ADMIN olarak güvenli giriş yapıldı!', 'success')
            return redirect(url_for('index'))

        # Veritabanı kullanıcı kontrolü
        with get_db() as conn:
            user = conn.execute('''
                SELECT id, username, password, name, role, factory_access,
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
                session['factory_access'] = user['factory_access']  # 🎯 FACTORY BİLGİSİ
                session['login_time'] = datetime.now().isoformat()

                # Last login güncelle
                conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                conn.commit()

                clear_login_attempts(client_ip)

                # Güvenlik logu
                factory_info = f" (Fabrika: {user['factory_access']})" if user['factory_access'] else " (Tüm fabrikalar)"
                logger.info(f"User login successful: {username}{factory_info} from IP: {client_ip}")

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


# 1. app.py - gecmis_veriler fonksiyonunu güncelle

@app.route('/gecmis/<cihaz_id>')
@login_required
def gecmis_veriler(cihaz_id):
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        sensor_filter = request.args.get('sensor_id')
        limit = request.args.get('limit', '1000')  # Varsayılan 1000
        page = int(request.args.get('page', 1))  # Sayfa numarası
        per_page = 1000  # Sayfa başına maksimum kayıt

        with get_db() as conn:
            cihaz = conn.execute('SELECT * FROM devices WHERE cihaz_id = ?', (cihaz_id,)).fetchone()
            if not cihaz:
                flash('Cihaz bulunamadı', 'danger')
                return redirect(url_for('index'))

            # Veritabanındaki min/max tarihleri al
            date_range = conn.execute('''
                SELECT 
                    MIN(timestamp) as min_timestamp,
                    MAX(timestamp) as max_timestamp,
                    COUNT(*) as total_records
                FROM sensor_data 
                WHERE cihaz_id = ?
            ''', (cihaz_id,)).fetchone()

            # Varsayılan tarih aralığını belirle
            default_start_date = None
            default_end_date = None
            total_records = 0

            if date_range and date_range['min_timestamp'] and date_range['max_timestamp']:
                min_date = datetime.fromtimestamp(date_range['min_timestamp'] / 1000)
                max_date = datetime.fromtimestamp(date_range['max_timestamp'] / 1000)

                default_start_date = min_date.strftime('%Y-%m-%d')
                default_end_date = max_date.strftime('%Y-%m-%d')
                total_records = date_range['total_records']

            # Eğer tarih parametresi yoksa varsayılanları kullan
            if not start_date and default_start_date:
                start_date = default_start_date
            if not end_date and default_end_date:
                end_date = default_end_date

            # ✅ PERFORMANS İYİLEŞTİRMESİ: Toplam kayıt sayısını hesapla
            count_query = 'SELECT COUNT(*) as total FROM sensor_data WHERE cihaz_id = ?'
            count_params = [cihaz_id]

            # Tarih filtreleri
            if start_date:
                start_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
                count_query += ' AND timestamp >= ?'
                count_params.append(start_timestamp)

            if end_date:
                end_timestamp = int((datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)).timestamp() * 1000)
                count_query += ' AND timestamp < ?'
                count_params.append(end_timestamp)

            # Sensör filtresi
            if sensor_filter:
                count_query += ' AND sensor_id = ?'
                count_params.append(sensor_filter)

            # Toplam kayıt sayısını al
            total_filtered = conn.execute(count_query, count_params).fetchone()['total']

            # ✅ SAYFALAMA HESAPLAMALARI
            # Kullanıcı "tümü" seçtiyse bile maksimum 10000 kayıt göster
            if limit == 'all':
                max_limit = min(total_filtered, 10000)  # Maksimum 10K kayıt
            else:
                max_limit = min(int(limit), total_filtered)

            # Sayfa sayısını hesapla
            total_pages = (max_limit + per_page - 1) // per_page

            # Sayfa sınırlarını kontrol et
            if page < 1:
                page = 1
            elif page > total_pages:
                page = total_pages if total_pages > 0 else 1

            # Offset hesapla
            offset = (page - 1) * per_page

            # ✅ ANA SORGU - SAYFALAMA İLE
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

            # Sıralama ve sayfalama
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([per_page, offset])

            veriler = conn.execute(query, params).fetchall()

            # Tüm mevcut sensörleri al
            sensors = conn.execute('''
                SELECT DISTINCT sensor_id FROM sensor_data 
                WHERE cihaz_id = ? 
                ORDER BY sensor_id
            ''', (cihaz_id,)).fetchall()

            # ✅ SAYFALAMA BİLGİLERİ
            pagination_info = {
                'current_page': page,
                'total_pages': total_pages,
                'per_page': per_page,
                'total_records': total_filtered,
                'showing_from': offset + 1 if veriler else 0,
                'showing_to': min(offset + len(veriler), total_filtered),
                'has_prev': page > 1,
                'has_next': page < total_pages,
                'prev_page': page - 1 if page > 1 else None,
                'next_page': page + 1 if page < total_pages else None,
                'max_limit': max_limit
            }

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
                                   default_end_date=default_end_date,
                                   pagination=pagination_info,
                                   total_db_records=total_records)

    except Exception as e:
        flash(f'Geçmiş veriler alınırken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))


# 2. Excel export fonksiyonunu da güncelle (performans için)
@app.route('/excel/<cihaz_id>')
@login_required
def excel_export(cihaz_id):
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        sensor_filter = request.args.get('sensor_id')
        limit = request.args.get('limit', '5000')  # Excel için maksimum 5K

        # Excel için güvenlik sınırı
        max_excel_limit = 10000
        if limit == 'all':
            limit = max_excel_limit

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

        # Sıralama ve limit
        query += ' ORDER BY timestamp DESC'

        if limit != 'all':
            try:
                limit_num = min(int(limit), max_excel_limit)
                query += f' LIMIT {limit_num}'
            except ValueError:
                query += f' LIMIT {max_excel_limit}'
        else:
            query += f' LIMIT {max_excel_limit}'

        with get_db() as conn:
            veriler = conn.execute(query, params).fetchall()
            cihaz_adi = conn.execute('SELECT cihaz_adi FROM devices WHERE cihaz_id = ?',
                                     (cihaz_id,)).fetchone()['cihaz_adi']

            # Excel verisi çok büyükse uyarı ver
            if len(veriler) >= max_excel_limit:
                logger.warning(f"Excel export limit reached: {len(veriler)} records for {cihaz_id}")

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
            limit_suffix = f"_{len(veriler)}_kayit"
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


# Firmware Management
@app.route('/firmware')
@login_required
@admin_required
def firmware_management():
    with get_db() as conn:
        versions = conn.execute('''
            SELECT version, filename, file_path, signature_path, file_size, 
                   release_notes, is_active, created_at 
            FROM firmware_versions 
            ORDER BY created_at DESC
        ''').fetchall()

        # DEĞİŞTİ: cihazlar → devices
        cihazlar = conn.execute('''
            SELECT cihaz_id, cihaz_adi, firmware_version, target_firmware, 
                   online_status, last_seen 
            FROM devices 
            ORDER BY cihaz_adi
        ''').fetchall()

    return render_template('firmware_management.html',
                           versions=versions,
                           cihazlar=cihazlar)


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

        # Save to database - DÜZELTİLMİŞ SÜTUN İSİMLERİ
        with get_db() as conn:
            try:
                conn.execute('''
                    INSERT INTO firmware_versions 
                    (version, filename, file_path, signature_path, file_size, release_notes, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (version, filename, file_path, sig_path, file_size, final_release_notes, 0))
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


@app.route('/assign_firmware', methods=['POST'])
@login_required
@admin_required
def assign_firmware():
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        version = data.get('version')

        if not device_id or not version:
            return jsonify({
                'error': 'Cihaz ID ve versiyon gerekli',
                'details': f'device_id: {device_id}, version: {version}'
            }), 400

        with get_db() as conn:
            # DEĞİŞTİ: cihazlar → devices
            device = conn.execute(
                'SELECT cihaz_adi, firmware_version FROM devices WHERE cihaz_id = ?',
                (device_id,)
            ).fetchone()

            if not device:
                return jsonify({'error': f'Cihaz bulunamadı: {device_id}'}), 404

            firmware = conn.execute(
                'SELECT version FROM firmware_versions WHERE version = ?',
                (version,)
            ).fetchone()

            if not firmware:
                return jsonify({'error': f'Firmware bulunamadı: v{version}'}), 404

            # DEĞİŞTİ: cihazlar → devices
            conn.execute(
                'UPDATE devices SET target_firmware = ? WHERE cihaz_id = ?',
                (version, device_id)
            )
            conn.commit()

            logger.info(f"✅ Firmware atandı: {device_id} → v{version}")

            return jsonify({
                'success': True,
                'message': f'Firmware başarıyla atandı',
                'device': device['cihaz_adi'],
                'current_version': device['firmware_version'],
                'version': version,
                'device_id': device_id
            })

    except Exception as e:
        logger.error(f"❌ Firmware atama hatası: {str(e)}")
        return jsonify({
            'error': 'Firmware atama sırasında hata oluştu',
            'details': str(e)
        }), 500


@app.route('/firmware/check/<cihaz_id>')
def check_firmware(cihaz_id):
    api_key = request.args.get('api_key')
    if api_key != "GUVENLI_ANAHTAR_123":
        return jsonify({"error": "Yetkisiz erişim"}), 401

    try:
        with get_db() as conn:
            # ✅ DÜZELTİLMİŞ SORGU - doğru timestamp kullanımı
            device = conn.execute('''
                SELECT firmware_version, target_firmware 
                FROM devices 
                WHERE cihaz_id = ?
            ''', (cihaz_id,)).fetchone()

            current_timestamp = int(time.time() * 1000)

            if not device:
                # ✅ Cihaz yoksa ekle - doğru timestamp ile
                conn.execute('''
                    INSERT INTO devices (cihaz_id, cihaz_adi, firmware_version, online_status, last_seen, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (cihaz_id, cihaz_id, '1.0.0', 1, current_timestamp, current_timestamp))

                current_version = '1.0.0'
                target_version = None
                logger.info(f"✅ Yeni cihaz eklendi (firmware check): {cihaz_id}")
            else:
                # ✅ Mevcut cihaz - dict() ile dictionary'ye çevir
                device_dict = dict(device)
                current_version = device_dict['firmware_version']
                target_version = device_dict['target_firmware']

                # ✅ Last seen güncelle - doğru timestamp ile
                conn.execute('''
                    UPDATE devices 
                    SET last_seen = ?, online_status = 1 
                    WHERE cihaz_id = ?
                ''', (current_timestamp, cihaz_id))

            conn.commit()

            # Firmware güncellemesi gerekli mi?
            if target_version and target_version != current_version:
                # Aktif firmware bilgilerini al
                firmware = conn.execute('''
                    SELECT version, file_path, signature_path, release_notes, is_active, file_size
                    FROM firmware_versions 
                    WHERE version = ? AND is_active = 1
                ''', (target_version,)).fetchone()

                if firmware:
                    firmware_dict = dict(firmware)

                    # Tam URL'ler oluştur
                    base_url = f"https://{request.host}"
                    firmware_url = f"{base_url}/firmware/download/{firmware_dict['version']}?api_key=GUVENLI_ANAHTAR_123"
                    signature_url = f"{base_url}/firmware/signature/{firmware_dict['version']}?api_key=GUVENLI_ANAHTAR_123"

                    logger.info(f"📦 Firmware güncellemesi: {cihaz_id} v{current_version} → v{target_version}")

                    return jsonify({
                        "update_available": True,
                        "current_version": current_version,
                        "latest_version": target_version,
                        "firmware_url": firmware_url,
                        "signature_url": signature_url,
                        "release_notes": firmware_dict.get('release_notes', ''),
                        "file_size": firmware_dict.get('file_size', 0)
                    })

            # Güncelleme yok
            return jsonify({
                "update_available": False,
                "current_version": current_version,
                "latest_version": current_version,
                "message": "En güncel firmware kullanılıyor"
            })

    except Exception as e:
        logger.error(f"❌ Firmware check error: {str(e)}")
        return jsonify({
            "error": str(e),
            "update_available": False,
            "debug": f"Exception occurred: {str(e)}"
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

        if not firmware:
            return jsonify({"error": "Firmware bulunamadı"}), 404

        # ✅ DÜZELTİLDİ - dict() kullan
        firmware_dict = dict(firmware)
        file_path = firmware_dict['file_path']

        if not os.path.exists(file_path):
            return jsonify({"error": "Firmware dosyası bulunamadı"}), 404

        logger.info(f"📥 Firmware download: v{version}")
        return send_file(file_path, as_attachment=True)


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

        if not firmware:
            return jsonify({"error": "Signature bulunamadı"}), 404

        # ✅ DÜZELTİLDİ - dict() kullan
        firmware_dict = dict(firmware)
        signature_path = firmware_dict['signature_path']

        if not os.path.exists(signature_path):
            return jsonify({"error": "Signature dosyası bulunamadı"}), 404

        logger.info(f"🔐 Signature download: v{version}")
        return send_file(signature_path, as_attachment=True)


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


@app.route('/firmware/update_success/<cihaz_id>', methods=['POST'])
def firmware_update_success(cihaz_id):
    api_key = request.args.get('api_key')
    if api_key != "GUVENLI_ANAHTAR_123":
        return jsonify({"error": "Yetkisiz erişim"}), 401

    try:
        data = request.get_json()
        new_version = data.get('new_version')

        logger.info(f"📡 Update success notification received: {cihaz_id} -> v{new_version}")

        with get_db() as conn:
            # Mevcut firmware version'ı al
            current_device = conn.execute('''
                SELECT firmware_version, target_firmware 
                FROM devices 
                WHERE cihaz_id = ?
            ''', (cihaz_id,)).fetchone()

            if current_device:
                old_version = current_device['firmware_version']

                # Cihazın firmware'ini güncelle ve hedef firmware'i temizle
                conn.execute('''
                    UPDATE devices 
                    SET firmware_version = ?, 
                        target_firmware = NULL,
                        last_seen = ?,
                        online_status = 1
                    WHERE cihaz_id = ?
                ''', (new_version, int(time.time() * 1000), cihaz_id))

                # Update history'ye kayıt ekle (eğer tablo varsa)
                try:
                    conn.execute('''
                        INSERT INTO update_history 
                        (cihaz_id, old_version, new_version, update_status, completed_at)
                        VALUES (?, ?, ?, 'success', CURRENT_TIMESTAMP)
                    ''', (cihaz_id, old_version, new_version))
                except:
                    pass  # Tablo yoksa görmezden gel

                conn.commit()

                logger.info(f"✅ Firmware update completed: {cihaz_id} v{old_version} -> v{new_version}")

            return jsonify({
                "status": "success",
                "message": "Güncelleme başarısı kaydedildi",
                "device_id": cihaz_id,
                "new_version": new_version
            })

    except Exception as e:
        logger.error(f"❌ Update success notification error: {str(e)}")
        return jsonify({"error": str(e)}), 500


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


# Debug sayfası için:
@app.route('/admin/db_dump')
@login_required
@admin_required
def db_debug():
    with get_db() as conn:
        # DEĞİŞTİ: cihazlar → devices
        cihazlar = conn.execute('''
            SELECT cihaz_id, cihaz_adi, firmware_version, target_firmware, 
                   online_status, last_seen 
            FROM devices 
            ORDER BY last_seen DESC
        ''').fetchall()

        firmwareler = conn.execute('''
            SELECT id, version, file_path, file_size, is_active, created_at 
            FROM firmware_versions 
            ORDER BY created_at DESC
        ''').fetchall()

    return render_template('db_debug.html',
                           cihazlar=cihazlar,
                           firmwareler=firmwareler)


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
    """Kullanıcı listesi API - factory_access dahil"""
    try:
        with get_db() as conn:
            # ✅ DÜZELTİLMİŞ: factory_access sütununu da dahil et
            try:
                users = conn.execute('''
                    SELECT id, username, 
                           COALESCE(name, username) as name,
                           COALESCE(role, 'user') as role,
                           COALESCE(is_active, 1) as is_active,
                           created_at,
                           last_login,
                           factory_access
                    FROM users 
                    ORDER BY id
                ''').fetchall()

                logger.info(f"✅ Retrieved {len(users)} users with factory access")

            except sqlite3.OperationalError as e:
                # Sütun yoksa basit sorgu
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
                    user_dict['factory_access'] = None  # ✅ Null değer ekle
                    user_list.append(user_dict)

                return jsonify({
                    'success': True,
                    'users': user_list,
                    'message': 'Basit veri formatı (bazı sütunlar eksik)'
                })

            # Normal sonuç - factory_access dahil
            user_list = []
            for user in users:
                user_dict = dict(user)
                user_dict.pop('password', None)  # Şifreyi kaldır

                # Debug log
                logger.info(f"👤 User: {user_dict['username']}, Factory: {user_dict.get('factory_access', 'None')}")

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
    """Yeni kullanıcı oluştur - fabrika kontrolü ile - DÜZELTİLMİŞ"""
    try:
        data = request.get_json()

        # Debug log
        logger.info(f"🔧 Create user request data: {data}")

        # Validation
        required_fields = ['username', 'password', 'name', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} alanı gerekli'}), 400

        # ✅ Fabrika kontrolü - admin değilse zorunlu
        role = data['role']
        factory_access = data.get('factory_access')

        logger.info(f"🏭 Role: {role}, Factory: {factory_access}")

        if role != 'admin':
            if not factory_access or factory_access.strip() == '':
                logger.warning(f"❌ Factory access missing for non-admin user")
                return jsonify({
                    'success': False,
                    'error': 'Admin olmayan kullanıcılar için fabrika seçimi zorunludur'
                }), 400
        else:
            factory_access = None  # Admin için null

        with get_db() as conn:
            # Kullanıcı adı benzersizlik kontrolü
            existing = conn.execute('SELECT id FROM users WHERE username = ?', (data['username'],)).fetchone()
            if existing:
                return jsonify({'success': False, 'error': 'Bu kullanıcı adı zaten kullanılıyor'}), 400

            # Email benzersizlik kontrolü (eğer verilmişse)
            email = data.get('email', '').strip()
            if email:
                existing_email = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                if existing_email:
                    return jsonify({'success': False, 'error': 'Bu email adresi zaten kullanılıyor'}), 400

            # ✅ Factory access sütunu var mı kontrol et
            try:
                conn.execute('SELECT factory_access FROM users LIMIT 1')
                has_factory_column = True
                logger.info("✅ factory_access sütunu mevcut")
            except sqlite3.OperationalError:
                # Sütun yoksa ekle
                conn.execute('ALTER TABLE users ADD COLUMN factory_access TEXT DEFAULT NULL')
                has_factory_column = True
                logger.info("✅ factory_access sütunu eklendi")

            # ✅ DÜZELTİLMİŞ: Factory access ile kullanıcı oluştur
            logger.info(f"💾 Inserting user with factory_access: {factory_access}")

            cursor = conn.execute('''
                INSERT INTO users (username, password, name, email, role, is_active, factory_access)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['username'],
                generate_password_hash(data['password']),
                data['name'].strip(),
                email if email else None,
                role,
                data.get('is_active', True),
                factory_access  # ✅ Bu satır önemli
            ))

            new_user_id = cursor.lastrowid
            conn.commit()

            # Kontrol için yeni oluşturulan kullanıcıyı oku
            created_user = conn.execute('''
                SELECT username, factory_access FROM users WHERE id = ?
            ''', (new_user_id,)).fetchone()

            logger.info(f"✅ User created - ID: {new_user_id}, Factory in DB: {created_user['factory_access']}")

            # Aktivite logu
            factory_info = f" (Fabrika: {factory_access})" if factory_access else " (Tüm fabrikalar)"
            log_user_activity(
                user_id=session.get('user_id', 1),
                activity_type='user_created',
                description=f"Yeni kullanıcı oluşturuldu: {data['name']} (@{data['username']}){factory_info}",
                conn=conn
            )

            return jsonify({
                'success': True,
                'message': f'Kullanıcı başarıyla oluşturuldu{factory_info}',
                'user_id': new_user_id,
                'debug_factory': factory_access  # Debug için
            })

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Kullanıcı adı zaten kullanılıyor'}), 400
    except Exception as e:
        logger.error(f"❌ Create user with factory error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user_api(user_id):
    """Kullanıcı güncelle API - fabrika kontrolü ile"""
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
                # Rol değiştiğinde factory access kontrolü
                new_role = data['role']
                if new_role != 'admin':
                    # Admin değilse factory zorunlu
                    factory_access = data.get('factory_access')
                    if not factory_access:
                        return jsonify({
                            'success': False,
                            'error': 'Admin olmayan kullanıcılar için fabrika seçimi zorunludur'
                        }), 400
                    update_fields.append('factory_access = ?')
                    params.append(factory_access)
                else:
                    # Admin ise factory null
                    update_fields.append('factory_access = ?')
                    params.append(None)

                update_fields.append('role = ?')
                params.append(new_role)

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


# Fabrika listesi API
@app.route('/api/factories')
@login_required
@admin_required
def get_factories_api():
    """Mevcut fabrikaları getir - admin için"""
    try:
        with get_db() as conn:
            factories = conn.execute('''
                SELECT DISTINCT fabrika_adi 
                FROM devices 
                WHERE fabrika_adi IS NOT NULL AND fabrika_adi != ''
                ORDER BY fabrika_adi
            ''').fetchall()

            factory_list = [f['fabrika_adi'] for f in factories]

            return jsonify({
                'success': True,
                'factories': factory_list
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500



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
    # ✅ DATABASE BAŞLATMA VE MİGRATİON
    try:
        logger.info("🔄 Database initialization başlıyor...")
        init_db()  # Tabloları oluştur
        logger.info("✅ Database hazır!")
    except Exception as e:
        logger.error(f"❌ Database initialization hatası: {e}")

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
