"""
GhostCache — surface-web (non-Tor) variant for local/testing use.

Core goals from Requirements.md:
- Strict username/password/destruction-password validation.
- Admin approval and account visibility (Visible/Hidden).
- Logical deletion via destruction password; admin view-only access via master_key.
- Encrypted messaging + file sharing (details added further below).
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import re
import string
from datetime import datetime, timedelta
from typing import Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename


# --- Flask App Setup ---

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///test.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

db = SQLAlchemy(app)

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def _derive_app_kek() -> bytes:
    """
    Derive a stable 32-byte key-encryption-key from SECRET_KEY.
    This key never leaves the app process; it is used only to
    wrap/unwrap per-user encryption keys stored in the database.
    """
    secret = app.secret_key
    if not isinstance(secret, (bytes, bytearray)):
        secret = str(secret).encode("utf-8")
    digest = hashlib.sha256(secret).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)


_APP_KEK = Fernet(_derive_app_kek())


def utcnow() -> datetime:
    return datetime.utcnow()


# perform housekeeping on every request
@app.before_request
def cleanup():
    now = utcnow()
    expired = File.query.filter(File.expiry < now).all()
    for f in expired:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], f.stored_name))
        except Exception:
            pass
        db.session.delete(f)
    db.session.commit()


# --- Database Models / core fields (rest of crypto/visibility logic extended below) ---


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)

    # Authentication
    password_hash = db.Column(db.String(200), nullable=False)  # Argon2id hash
    dpass_hash = db.Column(db.String(200), nullable=False)  # destruction password hash

    # Account flags
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    visibility = db.Column(db.String(10), default="visible", nullable=False)  # "visible" | "hidden"

    # Logical deletion
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_original_username = db.Column(db.String(80), nullable=True)

    # Per-user key for encrypting private material (kept as Fernet key for now)
    keys_database_key = db.Column(db.String(200), nullable=False)

    created_at = db.Column(db.DateTime, default=utcnow)
    last_login = db.Column(db.DateTime, default=utcnow)

    sent_connections = db.relationship(
        "Connection", foreign_keys="Connection.sender_id", cascade="all, delete-orphan"
    )
    received_connections = db.relationship(
        "Connection", foreign_keys="Connection.receiver_id", cascade="all, delete-orphan"
    )
    sent_messages = db.relationship(
        "Message", foreign_keys="Message.sender_id", cascade="all, delete-orphan"
    )
    received_messages = db.relationship(
        "Message", foreign_keys="Message.receiver_id", cascade="all, delete-orphan"
    )
    files = db.relationship("File", backref="owner", cascade="all, delete-orphan")
    blacklist_out = db.relationship(
        "Blacklist", foreign_keys="Blacklist.blocker_id", cascade="all, delete-orphan"
    )
    blacklist_in = db.relationship(
        "Blacklist", foreign_keys="Blacklist.blocked_id", cascade="all, delete-orphan"
    )
    accessible_files = db.relationship(
        "FileAccess", foreign_keys="FileAccess.user_id", cascade="all, delete-orphan"
    )


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
    """
    Legacy model kept for compatibility with existing databases.
    The application no longer uses this table, but it is left here so that
    Alembic/SQLAlchemy can still reflect it if present.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    connection_id = db.Column(db.Integer, db.ForeignKey('connection.id'), nullable=False)
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


def _logical_delete_user(user: User, by_admin: bool) -> None:
    """
    Logical delete, as per requirements:
    - Tag account as deleted (no physical delete).
    - Transfer view-only rights to admin via master_key: hash(master_key) copied into password_hash.
    - Username changed to 'deleted_username' for clarity.
    """
    master_key = os.environ.get("MASTER_KEY")
    if not master_key:
        # Fallback: random value, so deleted account cannot be logged in again.
        master_key = os.urandom(32).hex()

    original_username = user.username
    base_deleted = f"deleted_{original_username}"

    # Ensure uniqueness even under concurrency by looping until we find a free name.
    deleted_username = base_deleted
    while User.query.filter_by(username=deleted_username).first():
        suffix = random.randint(1000, 9999)
        deleted_username = f"{base_deleted}_{suffix}"

    user.deleted = True
    user.deleted_at = utcnow()
    user.deleted_original_username = original_username
    user.username = deleted_username
    user.password_hash = hash_password(master_key)
    user.approved = True  # allow master-key login if needed
    db.session.commit()

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,14}$")  # 1–15 chars, starts with letter


def validate_username(username: str) -> Tuple[bool, str]:
    if not username:
        return False, "Username is required."
    if username != username.lower():
        return False, "Username must be lowercase a–z, 0–9, _."
    if not USERNAME_RE.fullmatch(username):
        return (
            False,
            "Username must be 1–15 chars, start with a letter, and contain only a–z, 0–9, _.",
        )
    return True, ""


_COMMON_BAD_PASSWORDS = {
    "12345",
    "123456",
    "password",
    "000",
    "0000",
    "00000",
    "iloveyou",
    "qwerty",
    "letmein",
}


def validate_password(password: str, username: Optional[str] = None) -> Tuple[bool, str]:
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."

    pnorm = password.strip().lower()
    if pnorm in _COMMON_BAD_PASSWORDS:
        return False, "Password is too common/recognizable."

    if username:
        u = username.lower()
        if u and u in pnorm:
            return False, "Password must not contain your username."
        if pnorm in {u, f"{u}123", f"{u}@123"}:
            return False, "Password is too recognizable."

    return True, ""


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
    # keys_database_key is stored wrapped with the app-level KEK
    raw_key_str = _APP_KEK.decrypt(user.keys_database_key.encode("utf-8")).decode("utf-8")
    f = Fernet(raw_key_str.encode("utf-8"))
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return f.encrypt(plaintext).decode('utf-8')


def decrypt_with_user_key(user, ciphertext):
    raw_key_str = _APP_KEK.decrypt(user.keys_database_key.encode("utf-8")).decode("utf-8")
    f = Fernet(raw_key_str.encode("utf-8"))
    return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')


def generate_rsa_keypair():
    """
    Deprecated: RSA keys are no longer generated or used by the application.
    Left here only to avoid import-time errors in case of stale references.
    """
    raise RuntimeError("generate_rsa_keypair() is deprecated and should not be called.")

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

    j = request.get_json(silent=True)
    data = j or request.form
    username_raw = (data.get('username') or '').strip()
    password = data.get('password') or ''
    d_pass = data.get('d_pass') or ''

    username = username_raw.lower()

    ok_u, msg_u = validate_username(username)
    if not ok_u:
        flash(msg_u, 'error')
        return redirect(url_for('register'))

    ok_p, msg_p = validate_password(password, username=username)
    if not ok_p:
        flash(msg_p, 'error')
        return redirect(url_for('register'))

    ok_d, msg_d = validate_password(d_pass, username=username)
    if not ok_d:
        flash(f"Destruction password: {msg_d}", 'error')
        return redirect(url_for('register'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('register'))

    pwd_hash = hash_password(password)
    dpass_hash = hash_password(d_pass)
    # Store per-user Fernet key wrapped with app-level KEK so the raw key
    # is never present in the database.
    raw_user_key = generate_fernet_key()
    keys_db_key = _APP_KEK.encrypt(raw_user_key.encode("utf-8")).decode("utf-8")

    user = User(
        username=username,
        password_hash=pwd_hash,
        dpass_hash=dpass_hash,
        keys_database_key=keys_db_key,
        approved=False,          # requires admin approval
        visibility='visible',    # default visibility
        created_at=utcnow(),
        last_login=utcnow()
    )
    db.session.add(user)
    db.session.commit()

    flash('Registration submitted. Your account must be approved by admin.', 'info')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    j = request.get_json(silent=True)
    data = j or request.form
    username_raw = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username_raw or not password:
        flash('Please provide both username and password', 'error')
        return redirect(url_for('login'))

    username = username_raw.lower()
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))

    # First, try normal password
    if verify_password(user.password_hash, password):
        if user.deleted:
            # Deleted accounts are view-only, typically accessed via master key.
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            flash('View-only access to deleted account granted.', 'info')
            return redirect(url_for('index'))

        if not user.approved:
            flash('Account is pending admin approval.', 'error')
            return redirect(url_for('login'))

        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        user.last_login = utcnow()
        db.session.commit()
        flash('Login successful', 'success')
        return redirect(url_for('index'))

    # Destruction password: logical delete instead of physical delete
    if verify_password(user.dpass_hash, password) and not user.deleted:
        _logical_delete_user(user, by_admin=False)
        session.clear()
        flash('Account deleted (destruction password used).', 'success')
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

    d_pass = request.form.get('d_pass') or ''
    if not d_pass:
        flash('Destruction password is required to delete your account.', 'error')
        return redirect(url_for('index'))
    if not verify_password(user.dpass_hash, d_pass):
        flash('Invalid destruction password.', 'error')
        return redirect(url_for('index'))

    _logical_delete_user(user, by_admin=False)
    session.clear()
    flash('Your account has been deleted.', 'info')
    return redirect(url_for('index'))


@app.route('/connect', methods=['GET', 'POST'])
def send_connection_request():
    if 'user_id' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('connect.html')

    target_raw = request.form.get('username') or ''
    target = target_raw.strip().lower()
    if not target:
        flash('Target username required', 'error')
        return redirect(url_for('send_connection_request'))

    if target == session.get('username'):
        flash('Cannot connect to yourself', 'error')
        return redirect(url_for('send_connection_request'))

    receiver = User.query.filter_by(username=target).first()
    if not receiver or receiver.deleted or not receiver.approved:
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

    # Only allow accepting a pending connection once.
    if conn.status != 'pending':
        flash('Connection is not pending.', 'error')
        return redirect(url_for('list_connections'))

    sender = User.query.get(conn.sender_id)
    receiver = User.query.get(conn.receiver_id)

    if sender and receiver:
        # Single symmetric chat key per connection, wrapped separately for each user.
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
    j = request.get_json(silent=True)
    receiver = request.form.get('receiver_id') or (j.get('receiver_id') if j else None)
    text = request.form.get('message') or (j.get('message') if j else None)
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
    q = request.args.get('q', '').strip().lower()
    results = []
    if q:
        blocked_by = [b.blocker_id for b in Blacklist.query.filter_by(blocked_id=session['user_id']).all()]
        blocked_out = [b.blocked_id for b in Blacklist.query.filter_by(blocker_id=session['user_id']).all()]
        excluded = set(blocked_by) | set(blocked_out) | {session['user_id']}
        # Only list approved, non-deleted, visible users in search results.
        results = User.query.filter(
            User.username.contains(q),
            ~User.id.in_(excluded),
            User.approved.is_(True),
            User.deleted.is_(False),
            User.visibility == 'visible',
        ).all()
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
