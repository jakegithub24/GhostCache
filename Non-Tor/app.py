# GhostCache — surface-web (non-Tor) variant for local/testing use.
# No Tor or stem dependency; runs as a normal Flask app.

from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, session, jsonify, url_for, redirect, render_template, flash, send_file
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import string
import random
import os

# --- Flask App Setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)  # In production, set a fixed secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# limit uploads to 50MB by default
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# perform housekeeping on every request
@app.before_request
def cleanup():
    now = datetime.utcnow()
    # remove expired files
    expired = File.query.filter(File.expiry < now).all()
    for f in expired:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f.stored_name))
        except Exception:
            pass
        db.session.delete(f)
    db.session.commit()

# --- Database Models ---


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)  # Argon2 hash
    dpass_hash = db.Column(db.String(200), nullable=False)
    keys_database_key = db.Column(
        db.String(200), nullable=False)  # Fernet key (base64)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)

    sent_connections = db.relationship('Connection',
                                       foreign_keys='Connection.sender_id',
                                       cascade='all, delete-orphan')
    received_connections = db.relationship('Connection',
                                           foreign_keys='Connection.receiver_id',
                                           cascade='all, delete-orphan')
    sent_messages = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    cascade='all, delete-orphan')
    received_messages = db.relationship('Message',
                                        foreign_keys='Message.receiver_id',
                                        cascade='all, delete-orphan')
    files = db.relationship('File', backref='owner',
                            cascade='all, delete-orphan')
    blacklist_out = db.relationship('Blacklist',
                                    foreign_keys='Blacklist.blocker_id',
                                    cascade='all, delete-orphan')
    blacklist_in = db.relationship('Blacklist',
                                   foreign_keys='Blacklist.blocked_id',
                                   cascade='all, delete-orphan')
    accessible_files = db.relationship('FileAccess',
                                       foreign_keys='FileAccess.user_id',
                                       cascade='all, delete-orphan')


class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender_privkey_enc = db.Column(db.Text, nullable=True)
    sender_pubkey_enc = db.Column(db.Text, nullable=True)
    receiver_privkey_enc = db.Column(db.Text, nullable=True)
    receiver_pubkey_enc = db.Column(db.Text, nullable=True)
    chat_key_enc_sender = db.Column(db.Text, nullable=True)
    chat_key_enc_receiver = db.Column(db.Text, nullable=True)


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    connection_id = db.Column(db.Integer, db.ForeignKey(
        'connection.id'), nullable=False)
    public_key_enc = db.Column(db.Text, nullable=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    stored_name = db.Column(db.String(200), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_list = db.relationship(
        'FileAccess', backref='file', cascade='all, delete-orphan')


class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)


class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    blocked_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    delivered = db.Column(db.Boolean, default=False)

# --- Utility Functions ---

ph = PasswordHasher()


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(hash_str: str, password: str) -> bool:
    try:
        return ph.verify(hash_str, password)
    except VerifyMismatchError:
        return False


def generate_salt(length=16):
    return os.urandom(length)


def generate_fernet_key():
    return Fernet.generate_key().decode('utf-8')


def encrypt_with_user_key(user, plaintext):
    key = user.keys_database_key.encode('utf-8')
    f = Fernet(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return f.encrypt(plaintext).decode('utf-8')


def decrypt_with_user_key(user, ciphertext):
    key = user.keys_database_key.encode('utf-8')
    f = Fernet(key)
    return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

# --- Flask Routes ---


@app.route('/')
def index():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)


@app.context_processor
def inject_user():
    return {'session': session}


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')
    d_pass = data.get('d_pass')

    if not username or not password or not d_pass:
        flash('All fields are required', 'error')
        return redirect(url_for('register'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('register'))

    pwd_hash = hash_password(password)
    dpass_hash = hash_password(d_pass)
    keys_db_key = generate_fernet_key()

    user = User(
        username=username,
        password_hash=pwd_hash,
        dpass_hash=dpass_hash,
        keys_database_key=keys_db_key,
        last_login=datetime.utcnow()
    )
    db.session.add(user)
    db.session.commit()

    flash('Account created, please log in', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        flash('Please provide both username and password', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))

    if user.last_login and datetime.utcnow() - user.last_login > timedelta(days=30):
        db.session.delete(user)
        db.session.commit()
        flash('Account expired due to inactivity; it has been removed', 'info')
        return redirect(url_for('register'))

    if verify_password(user.password_hash, password):
        session['user_id'] = user.id
        session['username'] = user.username
        user.last_login = datetime.utcnow()
        db.session.commit()
        flash('Login successful', 'success')
        return redirect(url_for('index'))

    if verify_password(user.dpass_hash, password):
        db.session.delete(user)
        db.session.commit()
        flash('Account deleted (destruction password used)', 'success')
        return redirect(url_for('index'))

    flash('Invalid username or password', 'error')
    return redirect(url_for('login'))


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash('You must be logged in to delete your account', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found', 'error')
        return redirect(url_for('index'))

    for f in user.files:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f.stored_name))
        except Exception:
            pass
    db.session.delete(user)
    db.session.commit()
    session.clear()
    flash('Your account has been deleted', 'info')
    return redirect(url_for('index'))


@app.route('/connect', methods=['GET', 'POST'])
def send_connection_request():
    if 'user_id' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('connect.html')

    target = request.form.get('username')
    if not target:
        flash('Target username required', 'error')
        return redirect(url_for('send_connection_request'))

    if target == session.get('username'):
        flash('Cannot connect to yourself', 'error')
        return redirect(url_for('send_connection_request'))

    receiver = User.query.filter_by(username=target).first()
    if not receiver:
        flash('No such user', 'error')
        return redirect(url_for('send_connection_request'))

    if Blacklist.query.filter_by(blocker_id=receiver.id, blocked_id=session['user_id']).first():
        flash('Cannot send request; you are blocked by that user', 'error')
        return redirect(url_for('send_connection_request'))

    existing = Connection.query.filter(
        ((Connection.sender_id == session['user_id']) & (Connection.receiver_id == receiver.id)) |
        ((Connection.sender_id == receiver.id) &
         (Connection.receiver_id == session['user_id']))
    ).first()
    if existing:
        flash('Connection already exists or pending', 'info')
        return redirect(url_for('index'))

    conn = Connection(sender_id=session['user_id'], receiver_id=receiver.id)
    db.session.add(conn)
    db.session.commit()
    flash('Request sent', 'success')
    return redirect(url_for('index'))


@app.route('/connections')
def list_connections():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    pending_sent = Connection.query.filter_by(
        sender_id=uid, status='pending').all()
    pending_recv = Connection.query.filter_by(
        receiver_id=uid, status='pending').all()
    accepted = Connection.query.filter(
        ((Connection.sender_id == uid) | (Connection.receiver_id == uid)) &
        (Connection.status == 'accepted')
    ).all()

    def other_info(conn):
        if conn.sender_id == uid:
            other = User.query.get(conn.receiver_id)
        else:
            other = User.query.get(conn.sender_id)
        return {'conn': conn, 'other': other}

    pending_sent = [other_info(c) for c in pending_sent]
    pending_recv = [other_info(c) for c in pending_recv]
    accepted = [other_info(c) for c in accepted]

    return render_template('connections.html', pending_sent=pending_sent,
                           pending_recv=pending_recv, accepted=accepted)


@app.route('/connect/deny/<int:conn_id>', methods=['POST'])
def deny_connection(conn_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = Connection.query.get(conn_id)
    if not conn or conn.receiver_id != session['user_id']:
        flash('Invalid connection', 'error')
        return redirect(url_for('list_connections'))
    blk = Blacklist(blocker_id=conn.receiver_id, blocked_id=conn.sender_id)
    db.session.add(blk)
    conn.status = 'denied'
    db.session.commit()
    flash('Connection denied and sender blocked', 'info')
    return redirect(url_for('list_connections'))


@app.route('/connect/accept/<int:conn_id>', methods=['POST'])
def accept_connection(conn_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = Connection.query.get(conn_id)
    if not conn or conn.receiver_id != session['user_id']:
        flash('Invalid connection', 'error')
        return redirect(url_for('list_connections'))

    def make_and_store_keys(user, priv_attr, pub_attr):
        priv, pub = generate_rsa_keypair()
        setattr(conn, priv_attr, encrypt_with_user_key(user, priv))
        setattr(conn, pub_attr, encrypt_with_user_key(user, pub))

    sender = User.query.get(conn.sender_id)
    receiver = User.query.get(conn.receiver_id)

    if sender and receiver:
        make_and_store_keys(sender, 'sender_privkey_enc', 'sender_pubkey_enc')
        make_and_store_keys(receiver, 'receiver_privkey_enc',
                            'receiver_pubkey_enc')

        c1 = Contact(user_id=sender.id, contact_id=receiver.id,
                     connection_id=conn.id,
                     public_key_enc=conn.receiver_pubkey_enc)
        c2 = Contact(user_id=receiver.id, contact_id=sender.id,
                     connection_id=conn.id,
                     public_key_enc=conn.sender_pubkey_enc)
        db.session.add_all([c1, c2])

        chat_key = generate_fernet_key()
        conn.chat_key_enc_sender = encrypt_with_user_key(sender, chat_key)
        conn.chat_key_enc_receiver = encrypt_with_user_key(receiver, chat_key)

    conn.status = 'accepted'
    db.session.commit()
    flash('Connection accepted', 'success')
    return redirect(url_for('list_connections'))


@app.route('/chat/send', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    sender = session['user_id']
    receiver = request.form.get(
        'receiver_id') or request.json.get('receiver_id')
    text = request.form.get('message') or request.json.get('message')
    if not receiver or not text:
        return jsonify({'error': 'Missing parameters'}), 400
    try:
        receiver = int(receiver)
    except ValueError:
        return jsonify({'error': 'Bad receiver id'}), 400
    conn = Connection.query.filter(
        ((Connection.sender_id == sender) & (Connection.receiver_id == receiver)) |
        ((Connection.sender_id == receiver) & (Connection.receiver_id == sender)), Connection.status == 'accepted').first()
    if not conn:
        return jsonify({'error': 'No accepted connection'}), 403
    if conn.sender_id == sender:
        enc_key = conn.chat_key_enc_sender
    else:
        enc_key = conn.chat_key_enc_receiver
    chat_key = decrypt_with_user_key(User.query.get(sender), enc_key)
    token = Fernet(chat_key.encode()).encrypt(
        text.encode('utf-8')).decode('utf-8')
    msg = Message(sender_id=sender, receiver_id=receiver, content=token)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'status': 'queued'}), 201


@app.route('/chat/poll', methods=['GET'])
def poll_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    uid = session['user_id']
    msgs = Message.query.filter_by(
        receiver_id=uid, delivered=False).order_by(Message.timestamp).all()
    out = []
    for m in msgs:
        conn = Connection.query.filter(
            ((Connection.sender_id == m.sender_id) & (Connection.receiver_id == uid)) |
            ((Connection.sender_id == uid) & (Connection.receiver_id == m.sender_id)), Connection.status == 'accepted').first()
        if conn:
            if conn.receiver_id == uid:
                enc_key = conn.chat_key_enc_receiver
            else:
                enc_key = conn.chat_key_enc_sender
            chat_key = decrypt_with_user_key(User.query.get(uid), enc_key)
            try:
                plain = Fernet(chat_key.encode()).decrypt(
                    m.content.encode('utf-8')).decode('utf-8')
            except Exception:
                plain = ''
        else:
            plain = ''
        out.append({
            'id': m.id,
            'sender_id': m.sender_id,
            'content': plain,
            'timestamp': m.timestamp.isoformat()
        })
        m.delivered = True
    db.session.commit()
    return jsonify(out)


@app.route('/chat/<int:other_id>', methods=['GET', 'POST'])
def chat_page(other_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    conn = Connection.query.filter(
        ((Connection.sender_id == uid) & (Connection.receiver_id == other_id)) |
        ((Connection.sender_id == other_id) & (Connection.receiver_id == uid)), Connection.status == 'accepted').first()
    if not conn:
        flash('No chat available', 'error')
        return redirect(url_for('list_connections'))

    if conn.sender_id == uid:
        enc_key = conn.chat_key_enc_sender
    else:
        enc_key = conn.chat_key_enc_receiver
    chat_key = decrypt_with_user_key(User.query.get(uid), enc_key)

    if request.method == 'POST':
        text = request.form.get('message')
        if text:
            token = Fernet(chat_key.encode()).encrypt(
                text.encode('utf-8')).decode('utf-8')
            msg = Message(sender_id=uid, receiver_id=other_id, content=token)
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('chat_page', other_id=other_id))

    msgs = Message.query.filter(
        ((Message.sender_id == uid) & (Message.receiver_id == other_id)) |
        ((Message.sender_id == other_id) & (Message.receiver_id == uid))
    ).order_by(Message.timestamp).limit(50).all()

    for m in msgs:
        try:
            m.content = Fernet(chat_key.encode()).decrypt(
                m.content.encode('utf-8')).decode('utf-8')
        except Exception:
            m.content = ''

    return render_template('chat.html', messages=msgs, other_id=other_id)


@app.route('/search')
def search_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    q = request.args.get('q', '').strip()
    results = []
    if q:
        blocked_by = [b.blocker_id for b in Blacklist.query.filter_by(blocked_id=session['user_id']).all()]
        blocked_out = [b.blocked_id for b in Blacklist.query.filter_by(blocker_id=session['user_id']).all()]
        excluded = set(blocked_by) | set(blocked_out) | {session['user_id']}
        results = User.query.filter(User.username.contains(q), ~User.id.in_(excluded)).all()
    return render_template('search.html', results=results, query=q)


@app.route('/files')
def list_files():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    mine = File.query.filter_by(owner_id=uid).all()
    shared = [fa.file for fa in FileAccess.query.filter_by(user_id=uid).all()]
    return render_template('files.html', mine=mine, shared=shared)


@app.route('/file/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('upload.html')
    f = request.files.get('file')
    expiry_days = int(request.form.get('expiry_days', '365'))
    if not f:
        flash('No file selected', 'error')
        return redirect(url_for('upload_file'))
    if expiry_days > 365:
        expiry_days = 365
    f.filename = secure_filename(f.filename)
    key = Fernet.generate_key().decode('utf-8')
    data = f.read()
    token = Fernet(key.encode('utf-8')).encrypt(data)
    stored = ''.join(random.choices(string.ascii_letters+string.digits, k=32))
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    with open(path, 'wb') as out:
        out.write(token)
    file_record = File(owner_id=session['user_id'], filename=f.filename,
                       stored_name=stored,
                       expiry=datetime.utcnow()+timedelta(days=expiry_days))
    db.session.add(file_record)
    db.session.commit()
    flash('File uploaded; keep the key safe: ' + key, 'info')
    return redirect(url_for('list_files'))


@app.route('/file/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    fi = File.query.get(file_id)
    if not fi:
        flash('File not found', 'error')
        return redirect(url_for('list_files'))
    if fi.owner_id != session['user_id'] and not FileAccess.query.filter_by(file_id=file_id, user_id=session['user_id']).first():
        flash('Not authorized', 'error')
        return redirect(url_for('list_files'))
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], fi.stored_name), as_attachment=True, download_name=fi.filename)


@app.route('/file/<int:file_id>/delete', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    fi = File.query.get(file_id)
    if not fi or fi.owner_id != session['user_id']:
        flash('File not found', 'error')
        return redirect(url_for('list_files'))
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fi.stored_name))
    except Exception:
        pass
    db.session.delete(fi)
    db.session.commit()
    flash('File deleted', 'info')
    return redirect(url_for('list_files'))


@app.route('/file/<int:file_id>/share', methods=['POST'])
def share_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('list_files'))
    fi = File.query.get(file_id)
    if not fi or fi.owner_id != session['user_id']:
        flash('File not found', 'error')
        return redirect(url_for('list_files'))
    if FileAccess.query.filter_by(file_id=file_id, user_id=user.id).first():
        flash('Already shared', 'info')
        return redirect(url_for('list_files'))
    fa = FileAccess(file_id=file_id, user_id=user.id)
    db.session.add(fa)
    db.session.commit()
    flash('File shared with '+username, 'success')
    return redirect(url_for('list_files'))


# --- Main (no Tor) ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("GhostCache (surface web) running at http://127.0.0.1:5000/")
    app.run(host='0.0.0.0', port=5000, debug=True)
