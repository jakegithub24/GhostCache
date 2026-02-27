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
import io
import os
import random
import re
import string
from datetime import datetime, timedelta
from typing import Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from werkzeug.utils import secure_filename


# Lightweight .env loader: support files with lines like `export KEY="value"`
def _load_dotenv_if_present(path: str = ".env") -> None:
    try:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                # support `export KEY=VALUE` or `KEY=VALUE`
                if ln.startswith("export "):
                    ln = ln[len("export "):]
                if "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                k = k.strip()
                v = v.strip()
                # Remove surrounding quotes if present
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                # Only set if not already present in environment
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        # Best-effort loader — silent on failure.
        pass


# Load .env early so environment variables (ADMIN_*, DATABASE_URL, etc.) are available
_load_dotenv_if_present()


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


def _get_session_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_globals():
    return {"session": session, "csrf_token": _get_session_csrf_token}


def _csrf_protect() -> Optional[Tuple[str, int]]:
    """
    Very small CSRF protection without extra dependencies.
    All HTML form POSTs should include `csrf_token` hidden input.

    During testing we disable enforcement so the unit tests can perform
    POST requests without having to extract the token from forms.
    """
    if app.config.get("TESTING"):
        return None
    if request.method != "POST":
        return None
    # Allow logging in/registering without token, avoids UI CSRF failures
    if request.endpoint in ("login", "register", "admin_register"):
        return None
    # Skip for JSON requests (we're removing JS endpoints anyway)
    if request.is_json:
        return None
    sent = request.form.get("csrf_token") or ""
    if not sent or sent != session.get("csrf_token"):
        return "CSRF validation failed.", 400
    return None


# perform housekeeping on every request
@app.before_request
def cleanup():
    _init_db()
    now = utcnow()
    try:
        expired = File.query.filter(File.expiry < now).all()
        for f in expired:
            try:
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], f.stored_name))
            except Exception:
                pass
            db.session.delete(f)
        db.session.commit()
    except OperationalError:
        # Likely schema mismatch during upgrades; init and continue.
        db.session.rollback()
        _init_db(force=True)
        return


_RATE_BUCKET = {}  # (ip, key) -> [count, window_start_ts]


def _rate_limit(key: str, limit: int, window_seconds: int) -> Optional[Tuple[str, int]]:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    now = int(datetime.utcnow().timestamp())
    bucket_key = (ip, key)
    count, start = _RATE_BUCKET.get(bucket_key, (0, now))
    if now - start >= window_seconds:
        count, start = 0, now
    count += 1
    _RATE_BUCKET[bucket_key] = (count, start)
    if count > limit:
        return "Too many requests, slow down.", 429
    return None


def _ensure_admin_account() -> None:
    """
    Bootstrap an initial admin from env:
    - ADMIN_USERNAME (default: admin)
    - ADMIN_PASSWORD (required to bootstrap)
    - ADMIN_DPASS (optional; else random)

    This is used when the database is empty and the deployer has supplied
    credentials through environment variables.  If no ADMIN_PASSWORD is
    provided nothing happens; the web UI will later prompt for the same
    information.
    """
    if User.query.filter_by(is_admin=True).first():
        return
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        # nothing to do, UI will create one instead
        return
    admin_username = (os.environ.get("ADMIN_USERNAME") or "admin").strip().lower()
    ok_u, _ = validate_username(admin_username)
    if not ok_u:
        return
    ok_p, _ = validate_password(admin_password, username=admin_username)
    if not ok_p:
        return
    admin_dpass = os.environ.get("ADMIN_DPASS") or base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8")
    ok_d, _ = validate_password(admin_dpass, username=admin_username)
    if not ok_d:
        admin_dpass = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8") + "Aa1!"

    if User.query.filter_by(username=admin_username).first():
        return

    raw_user_key = generate_fernet_key()
    keys_db_key = _APP_KEK.encrypt(raw_user_key.encode("utf-8")).decode("utf-8")

    # ed25519 signing keys
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    try:
        priv_raw = priv.private_bytes_raw()
        pub_raw = pub.public_bytes_raw()
    except Exception:
        # Fallback for older cryptography versions
        from cryptography.hazmat.primitives import serialization

        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    admin = User(
        username=admin_username,
        password_hash=hash_password(admin_password),
        dpass_hash=hash_password(admin_dpass),
        keys_database_key=keys_db_key,
        approved=True,
        visibility="visible",
        is_admin=True,
        force_password_change=False,
        ed25519_pub_b64=base64.urlsafe_b64encode(pub_raw).decode("utf-8"),
        ed25519_priv_enc=Fernet(raw_user_key.encode("utf-8")).encrypt(priv_raw).decode("utf-8"),
        created_at=utcnow(),
        last_login=utcnow(),
    )
    db.session.add(admin)
    db.session.commit()


@app.before_request
def security_checks():
    # Ensure an admin account exists or is bootstrapped from environment.
    # If none exists after that, force the user to the registration page so
    # the first admin may be created interactively.
    _ensure_admin_account()

    # Guard: DB schema may not include master_key_hash yet on existing databases
    # (migration runs in cleanup/before_request — catch both cases)
    try:
        admin = User.query.filter_by(is_admin=True).first()
        has_master = admin.master_key_hash if admin else None
    except Exception:
        # Schema not migrated yet — let the request through so _init_db() can run
        return None

    if not admin:
        if request.endpoint not in ("admin_register", "static"):
            return redirect(url_for("admin_register"))
        # let the register handler deal with creation

    elif not has_master:
        if request.endpoint not in ("admin_register", "static"):
            return redirect(url_for("admin_register"))

    csrf_err = _csrf_protect()
    if csrf_err:
        msg, code = csrf_err
        return msg, code


_DB_INITIALIZED = False


def _sqlite_column_names(table_name: str) -> set[str]:
    rows = db.session.execute(text(f"PRAGMA table_info({table_name})")).all()
    return {r[1] for r in rows}


def _sqlite_add_column(table: str, col_def_sql: str) -> None:
    db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}"))


def _ensure_sqlite_schema() -> None:
    """
    Best-effort schema upgrade for existing sqlite databases.
    Adds missing columns required by current models.
    """
    if db.engine.dialect.name != "sqlite":
        return

    # user table
    cols = _sqlite_column_names("user")
    if "is_admin" not in cols:
        _sqlite_add_column("user", "is_admin BOOLEAN NOT NULL DEFAULT 0")
    if "approved" not in cols:
        _sqlite_add_column("user", "approved BOOLEAN NOT NULL DEFAULT 0")
    if "visibility" not in cols:
        _sqlite_add_column("user", "visibility VARCHAR(10) NOT NULL DEFAULT 'visible'")
    if "force_password_change" not in cols:
        _sqlite_add_column("user", "force_password_change BOOLEAN NOT NULL DEFAULT 0")
    if "deleted" not in cols:
        _sqlite_add_column("user", "deleted BOOLEAN NOT NULL DEFAULT 0")
    if "deleted_at" not in cols:
        _sqlite_add_column("user", "deleted_at DATETIME")
    if "deleted_original_username" not in cols:
        _sqlite_add_column("user", "deleted_original_username VARCHAR(80)")
    if "ed25519_pub_b64" not in cols:
        _sqlite_add_column("user", "ed25519_pub_b64 TEXT")
    if "ed25519_priv_enc" not in cols:
        _sqlite_add_column("user", "ed25519_priv_enc TEXT")
    if "master_key_hash" not in cols:
        _sqlite_add_column("user", "master_key_hash VARCHAR(200)")

    # connection table
    cols = _sqlite_column_names("connection")
    if "chat_key_enc_sender" not in cols:
        _sqlite_add_column("connection", "chat_key_enc_sender TEXT")
    if "chat_key_enc_receiver" not in cols:
        _sqlite_add_column("connection", "chat_key_enc_receiver TEXT")

    # message table
    cols = _sqlite_column_names("message")
    if "signature" not in cols:
        _sqlite_add_column("message", "signature TEXT")
    if "sha256_hash" not in cols:
        _sqlite_add_column("message", "sha256_hash TEXT")

    # file table
    cols = _sqlite_column_names("file")
    if "owner_key_enc" not in cols:
        _sqlite_add_column("file", "owner_key_enc TEXT")
    if "nonce_b64" not in cols:
        _sqlite_add_column("file", "nonce_b64 TEXT")

    # file_access table
    cols = _sqlite_column_names("file_access")
    if "user_key_enc" not in cols:
        _sqlite_add_column("file_access", "user_key_enc TEXT")

    db.session.commit()


def _normalize_existing_users() -> None:
    """
    - Wrap legacy plaintext `keys_database_key` with _APP_KEK (if needed)
    - Ensure each user has ed25519 keys
    """
    try:
        users = User.query.all()
    except OperationalError:
        db.session.rollback()
        return

    changed = False
    for u in users:
        # Wrap keys_database_key if it looks like plaintext
        raw_key: Optional[bytes] = None
        try:
            raw_key = _APP_KEK.decrypt((u.keys_database_key or "").encode("utf-8"))
        except Exception:
            # If it's a valid Fernet key, wrap it.
            try:
                candidate = (u.keys_database_key or "").encode("utf-8")
                Fernet(candidate)
                raw_key = candidate
                u.keys_database_key = _APP_KEK.encrypt(candidate).decode("utf-8")
                changed = True
            except Exception:
                raw_key = None

        # Ensure ed25519 keys exist (generate if missing)
        if raw_key and (not getattr(u, "ed25519_pub_b64", None) or not getattr(u, "ed25519_priv_enc", None)):
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            try:
                priv_raw = priv.private_bytes_raw()
                pub_raw = pub.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization

                priv_raw = priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_raw = pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            u.ed25519_pub_b64 = base64.urlsafe_b64encode(pub_raw).decode("utf-8")
            u.ed25519_priv_enc = Fernet(raw_key).encrypt(priv_raw).decode("utf-8")
            changed = True

    if changed:
        db.session.commit()


def _init_db(force: bool = False) -> None:
    global _DB_INITIALIZED
    if _DB_INITIALIZED and not force:
        return
    try:
        db.create_all()
        _ensure_sqlite_schema()
        _normalize_existing_users()
        _DB_INITIALIZED = True
    except OperationalError:
        db.session.rollback()
        # Don't block requests entirely; we'll retry later.
        _DB_INITIALIZED = False


# --- Database Models / core fields (rest of crypto/visibility logic extended below) ---


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)

    # Authentication
    password_hash = db.Column(db.String(200), nullable=False)  # Argon2id hash
    dpass_hash = db.Column(db.String(200), nullable=False)  # destruction password hash
    master_key_hash = db.Column(db.String(200), nullable=True)  # for admin authentication

    # Account flags
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    visibility = db.Column(db.String(10), default="visible", nullable=False)  # "visible" | "hidden"
    force_password_change = db.Column(db.Boolean, default=False, nullable=False)

    # Logical deletion
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_original_username = db.Column(db.String(80), nullable=True)

    # Per-user key for encrypting private material (kept as Fernet key, wrapped with app KEK)
    keys_database_key = db.Column(db.String(200), nullable=False)
    # ed25519 keypair for signing / verifying messages (nullable for legacy DB upgrades)
    ed25519_pub_b64 = db.Column(db.Text, nullable=True)
    ed25519_priv_enc = db.Column(db.Text, nullable=True)

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


class AdminNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    read = db.Column(db.Boolean, default=False, nullable=False)


class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Per-connection symmetric key derived via x25519 + HKDF and wrapped
    # separately for each user with their per-user Fernet key.
    chat_key_enc_sender = db.Column(db.Text, nullable=True)
    chat_key_enc_receiver = db.Column(db.Text, nullable=True)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    stored_name = db.Column(db.String(200), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # File encryption key, encrypted for the owner with their per-user key
    owner_key_enc = db.Column(db.Text, nullable=True)
    # Nonce used for AES-GCM when encrypting the on-disk blob (base64)
    nonce_b64 = db.Column(db.Text, nullable=True)
    access_list = db.relationship(
        'FileAccess', backref='file', cascade='all, delete-orphan')


class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    # File encryption key, encrypted for this user with their per-user key
    user_key_enc = db.Column(db.Text, nullable=True)


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
    # Encrypted payload (nonce + ciphertext, base64-encoded)
    content = db.Column(db.Text, nullable=False)
    # ed25519 signature over SHA-256 hash of ciphertext
    signature = db.Column(db.Text, nullable=True)
    # Stored SHA-256 hash (base64) for explicit tamper detection
    sha256_hash = db.Column(db.Text, nullable=True)
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


def _raw_user_fernet_key(user: User) -> bytes:
    """
    Returns the user's Fernet key bytes. The DB stores this key wrapped by _APP_KEK.
    """
    return _APP_KEK.decrypt(user.keys_database_key.encode("utf-8"))


def encrypt_with_user_key_bytes(user: User, plaintext: bytes) -> str:
    f = Fernet(_raw_user_fernet_key(user))
    return f.encrypt(plaintext).decode("utf-8")


def decrypt_with_user_key_bytes(user: User, ciphertext_token: str) -> bytes:
    f = Fernet(_raw_user_fernet_key(user))
    return f.decrypt(ciphertext_token.encode("utf-8"))


def encrypt_with_user_key(user: User, plaintext: str) -> str:
    return encrypt_with_user_key_bytes(user, plaintext.encode("utf-8"))


def decrypt_with_user_key(user: User, ciphertext_token: str) -> str:
    return decrypt_with_user_key_bytes(user, ciphertext_token).decode("utf-8")


def encrypt_message(chat_key: bytes, plaintext: str, signer: ed25519.Ed25519PrivateKey) -> Tuple[str, str, str]:
    """
    Encrypt a chat message using AES-GCM and sign it with the sender's
    ed25519 key. The caller is responsible for providing the signing key.
    Returns (content_b64, sha256_b64, signature_b64).
    """
    aes = AESGCM(chat_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = base64.urlsafe_b64encode(nonce + ct).decode("utf-8")
    digest = hashlib.sha256(blob.encode("utf-8")).digest()
    sha256_b64 = base64.urlsafe_b64encode(digest).decode("utf-8")
    signature = signer.sign(digest)
    sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8")
    return blob, sha256_b64, sig_b64


def decrypt_message(chat_key: bytes, content_b64: str, sha256_b64: str, sig_b64: str, sender_pub: ed25519.Ed25519PublicKey) -> Optional[str]:
    """
    Verify signature + sha256, then decrypt AES-GCM payload.
    Returns plaintext string on success, else None.
    """
    try:
        digest = hashlib.sha256(content_b64.encode("utf-8")).digest()
        expected_sha = base64.urlsafe_b64encode(digest).decode("utf-8")
        if expected_sha != sha256_b64:
            return None
        sender_pub.verify(base64.urlsafe_b64decode(sig_b64.encode("utf-8")), digest)

        blob = base64.urlsafe_b64decode(content_b64.encode("utf-8"))
        nonce = blob[:12]
        ct = blob[12:]
        pt = AESGCM(chat_key).decrypt(nonce, ct, None)
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None


def _user_signer(user: User) -> ed25519.Ed25519PrivateKey:
    # ensure user has an ed25519 keypair; some older accounts (notably
    # initial admins created before key-generation was added) may lack
    # these fields.  If missing, generate and persist keys on first use.
    if not user.ed25519_priv_enc or not user.ed25519_pub_b64:
        # compute raw per-user Fernet key to wrap the private key
        raw_key = _raw_user_fernet_key(user)
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        try:
            priv_raw = priv.private_bytes_raw()
            pub_raw = pub.public_bytes_raw()
        except Exception:
            from cryptography.hazmat.primitives import serialization

            priv_raw = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_raw = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        user.ed25519_priv_enc = Fernet(raw_key).encrypt(priv_raw).decode("utf-8")
        user.ed25519_pub_b64 = base64.urlsafe_b64encode(pub_raw).decode("utf-8")
        db.session.commit()

    priv_raw = decrypt_with_user_key_bytes(user, user.ed25519_priv_enc)
    return ed25519.Ed25519PrivateKey.from_private_bytes(priv_raw)


def _user_verifier(user: User) -> ed25519.Ed25519PublicKey:
    # if the public key is missing we may need to generate a fresh pair
    # (this would also populate the private key via _user_signer).
    if not user.ed25519_pub_b64:
        # prime both fields via signer helper
        signer = _user_signer(user)
        return signer.public_key()
    return ed25519.Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(user.ed25519_pub_b64.encode("utf-8"))
    )


def _connection_keys(conn: Connection, user: User) -> tuple[bytes, Optional[bytes]]:
    """
    Returns (aes_key_32, legacy_fernet_key_or_none).

    - New connections store a raw 32-byte AES key.
    - Legacy connections stored a Fernet key string; we derive an AES key via SHA-256.
    - NULL keys (connections made before key-exchange code existed) are auto-healed.
    """
    # Determine which encrypted key belongs to the current user
    user_enc = conn.chat_key_enc_sender if conn.sender_id == user.id else conn.chat_key_enc_receiver
    other_enc = conn.chat_key_enc_receiver if conn.sender_id == user.id else conn.chat_key_enc_sender

    # Try to decrypt user's key
    raw = None
    if user_enc:
        try:
            raw = decrypt_with_user_key_bytes(user, user_enc)
        except Exception:
            # Decryption failed; treat as missing
            user_enc = None

    if raw is not None:
        # Successfully decrypted
        if len(raw) == 32:
            return raw, None
        else:
            return hashlib.sha256(raw).digest(), raw

    # If we get here, user's key is missing or corrupt. Try to use the other user's key to recover.
    if other_enc:
        # Need the other user object
        other_id = conn.receiver_id if conn.sender_id == user.id else conn.sender_id
        other = User.query.get(other_id)
        if other:
            try:
                other_raw = decrypt_with_user_key_bytes(other, other_enc)
                # Determine if it's raw or legacy
                if len(other_raw) == 32:
                    chat_key = other_raw
                else:
                    chat_key = hashlib.sha256(other_raw).digest()
                # Encrypt the recovered key for the current user and update the DB
                if conn.sender_id == user.id:
                    conn.chat_key_enc_sender = encrypt_with_user_key_bytes(user, chat_key)
                else:
                    conn.chat_key_enc_receiver = encrypt_with_user_key_bytes(user, chat_key)
                db.session.commit()
                return chat_key, None
            except Exception:
                pass  # fall through to generate new

    # If all else fails, generate a new chat key
    sender = User.query.get(conn.sender_id)
    receiver = User.query.get(conn.receiver_id)
    if not sender or not receiver:
        raise ValueError("missing connection key and users not found")

    chat_key = os.urandom(32)
    conn.chat_key_enc_sender = encrypt_with_user_key_bytes(sender, chat_key)
    conn.chat_key_enc_receiver = encrypt_with_user_key_bytes(receiver, chat_key)
    db.session.commit()
    return chat_key, None


# --- Flask Routes ---


def _current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)


def _require_login():
    if "user_id" not in session:
        flash("Please log in first", "error")
        return redirect(url_for("login"))
    return None


def _deny_view_only():
    if session.get("view_only"):
        flash("This account is view-only; actions are disabled.", "error")
        return redirect(url_for("index"))
    return None


@app.route('/')
def index():
    user = None
    active_connections = []
    pending_connections = []
    recent_files = []

    if 'user_id' in session:
        user = User.query.get(session['user_id'])

    if user and not session.get('view_only'):
        uid = user.id

        # Accepted connections with the other user object
        accepted = Connection.query.filter(
            ((Connection.sender_id == uid) | (Connection.receiver_id == uid)),
            Connection.status == 'accepted'
        ).order_by(Connection.created_at.desc()).all()

        for conn in accepted:
            other_id = conn.receiver_id if conn.sender_id == uid else conn.sender_id
            other = User.query.get(other_id)
            if other and not other.deleted:
                active_connections.append({'conn': conn, 'other': other})

        # Pending incoming requests
        pending = Connection.query.filter_by(
            receiver_id=uid, status='pending'
        ).order_by(Connection.created_at.desc()).all()

        for conn in pending:
            other = User.query.get(conn.sender_id)
            if other and not other.deleted:
                pending_connections.append({'conn': conn, 'other': other})

        # 3 most recent owned files
        recent_files = File.query.filter_by(owner_id=uid)\
            .order_by(File.created_at.desc()).limit(3).all()

    return render_template(
        'index.html',
        user=user,
        active_connections=active_connections,
        pending_connections=pending_connections,
        recent_files=recent_files,
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    rl = _rate_limit("register", limit=10, window_seconds=60)
    if rl:
        msg, code = rl
        return msg, code

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

    # ed25519 signing keys (private encrypted with user's key)
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    try:
        priv_raw = priv.private_bytes_raw()
        pub_raw = pub.public_bytes_raw()
    except Exception:
        from cryptography.hazmat.primitives import serialization

        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ed_priv_enc = Fernet(raw_user_key.encode("utf-8")).encrypt(priv_raw).decode("utf-8")
    ed_pub_b64 = base64.urlsafe_b64encode(pub_raw).decode("utf-8")

    user = User(
        username=username,
        password_hash=pwd_hash,
        dpass_hash=dpass_hash,
        keys_database_key=keys_db_key,
        approved=False,          # requires admin approval
        visibility='visible',    # default visibility
        force_password_change=False,
        ed25519_pub_b64=ed_pub_b64,
        ed25519_priv_enc=ed_priv_enc,
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

    rl = _rate_limit("login", limit=20, window_seconds=60)
    if rl:
        msg, code = rl
        return msg, code

    # First, try normal password
    if verify_password(user.password_hash, password):
        if user.deleted:
            # Deleted accounts are view-only, typically accessed via master key.
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['view_only'] = True
            flash('View-only access to deleted account granted.', 'info')
            return redirect(url_for('index'))

        if not user.approved:
            # Allow user to authenticate and see a temporary informational page
            session.clear()
            session['pending_user'] = user.username
            return render_template('pending_approval.html', username=user.username)

        # Normal approved user login
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session['view_only'] = False
        user.last_login = utcnow()
        db.session.commit()
        if user.force_password_change:
            flash('You must change your password before continuing.', 'info')
            return redirect(url_for('password_change'))
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


@app.route('/password_change', methods=['GET', 'POST'])
def password_change():
    need = _require_login()
    if need:
        return need

    user = _current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template('password_change.html', force=user.force_password_change)

    deny = _deny_view_only()
    if deny:
        return deny

    old_password = request.form.get("old_password") or ""
    new_password = request.form.get("password") or ""
    new_dpass    = request.form.get("d_pass") or ""

    if not verify_password(user.password_hash, old_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("password_change"))

    ok_p, msg_p = validate_password(new_password, username=user.username)
    if not ok_p:
        flash(msg_p, "error")
        return redirect(url_for("password_change"))

    ok_d, msg_d = validate_password(new_dpass, username=user.username)
    if not ok_d:
        flash(f"Destruction password: {msg_d}", "error")
        return redirect(url_for("password_change"))

    user.password_hash = hash_password(new_password)
    user.dpass_hash    = hash_password(new_dpass)
    user.force_password_change = False
    db.session.commit()
    flash("Password updated.", "success")
    return redirect(url_for("index"))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash('You must be logged in to delete your account', 'error')
        return redirect(url_for('login'))
    deny = _deny_view_only()
    if deny:
        return deny

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

    deny = _deny_view_only()
    if deny:
        return deny
    rl = _rate_limit("connect", limit=60, window_seconds=60)
    if rl:
        msg, code = rl
        return msg, code

    target_raw = request.form.get('username') or ''
    target = target_raw.strip().lower()
    if not target:
        flash('Target username required', 'error')
        return redirect(url_for('send_connection_request'))

    if target == session.get('username'):
        flash('Cannot connect to yourself', 'error')
        return redirect(url_for('send_connection_request'))

    receiver = User.query.filter_by(username=target).first()
    # don't allow connections to non-existent, deleted, unapproved, or hidden accounts
    if not receiver or receiver.deleted or not receiver.approved or receiver.visibility != 'visible':
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

    sender = User.query.get(session["user_id"])
    if sender and (sender.visibility == "hidden" or receiver.visibility == "hidden"):
        db.session.add(AdminNotification(
            message=f"Hidden-user connection request from '{sender.username}' to '{receiver.username}'.",
            created_at=utcnow(),
            read=False,
        ))
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
    deny = _deny_view_only()
    if deny:
        return deny
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
    deny = _deny_view_only()
    if deny:
        return deny
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
        # x25519 ECDH + HKDF to derive a 256-bit chat key
        a_priv = x25519.X25519PrivateKey.generate()
        b_priv = x25519.X25519PrivateKey.generate()
        shared = a_priv.exchange(b_priv.public_key())
        chat_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b"ghostcache-chat-key-v1",
        ).derive(shared)

        # Store derived key wrapped separately for each user
        conn.chat_key_enc_sender = encrypt_with_user_key_bytes(sender, chat_key)
        conn.chat_key_enc_receiver = encrypt_with_user_key_bytes(receiver, chat_key)

        # Notify admin if hidden user involved
        if sender.visibility == "hidden" or receiver.visibility == "hidden":
            db.session.add(AdminNotification(
                message=f"Hidden-user connection accepted between '{sender.username}' and '{receiver.username}'.",
                created_at=utcnow(),
                read=False,
            ))

    conn.status = 'accepted'
    db.session.commit()
    flash('Connection accepted', 'success')
    return redirect(url_for('list_connections'))


@app.route('/chat/<int:other_id>', methods=['GET', 'POST'])
def chat_page(other_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    user = User.query.get(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))
    conn = Connection.query.filter(
        ((Connection.sender_id == uid) & (Connection.receiver_id == other_id)) |
        ((Connection.sender_id == other_id) & (Connection.receiver_id == uid)), Connection.status == 'accepted').first()
    if not conn:
        flash('No chat available', 'error')
        return redirect(url_for('list_connections'))

    try:
        chat_key, legacy_chat_key = _connection_keys(conn, user)
    except Exception as e:
        flash(f"Chat key unavailable: {str(e)}", "error")
        return redirect(url_for("list_connections"))

    if request.method == 'POST':
        deny = _deny_view_only()
        if deny:
            return deny
        text = request.form.get('message')
        if text:
            blob, sha_b64, sig_b64 = encrypt_message(chat_key, text, signer=_user_signer(user))
            msg = Message(
                sender_id=uid,
                receiver_id=other_id,
                content=blob,
                sha256_hash=sha_b64,
                signature=sig_b64,
            )
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('chat_page', other_id=other_id))

    msgs = Message.query.filter(
        ((Message.sender_id == uid) & (Message.receiver_id == other_id)) |
        ((Message.sender_id == other_id) & (Message.receiver_id == uid))
    ).order_by(Message.timestamp).limit(50).all()

    for m in msgs:
        sender_u = User.query.get(m.sender_id)
        if not sender_u:
            m.content = ''  # type: ignore[attr-defined]
            continue
        if not m.sha256_hash or not m.signature:
            # Legacy message: Fernet token stored in m.content
            if legacy_chat_key:
                try:
                    plain = Fernet(legacy_chat_key).decrypt(m.content.encode("utf-8")).decode("utf-8")
                except Exception:
                    plain = None
            else:
                plain = None
        else:
            plain = decrypt_message(
                chat_key,
                m.content,
                m.sha256_hash,
                m.signature,
                sender_pub=_user_verifier(sender_u),
            )
        m.content = plain or ''  # type: ignore[attr-defined]

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


def _require_admin():
    need = _require_login()
    if need:
        return need
    u = _current_user()
    if not u or not u.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("index"))
    return None


@app.route("/admin", methods=["GET"])
def admin_index():
    need = _require_admin()
    if need:
        return need
    return render_template('admin/index.html')


@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    need = _require_admin()
    if need:
        return need
    users = User.query.filter_by(approved=False).filter(User.deleted.is_(False)).all()
    return render_template('admin/pending.html', users=users)


@app.route("/admin/approve/<int:user_id>", methods=["POST"])
def admin_approve(user_id: int):
    need = _require_admin()
    if need:
        return need
    u = User.query.get(user_id)
    if not u or u.deleted:
        flash("User not found.", "error")
        return redirect(url_for("admin_pending"))
    u.approved = True
    db.session.commit()
    flash(f"Approved {u.username}.", "success")
    return redirect(url_for("admin_pending"))


@app.route("/admin/create_user", methods=["GET", "POST"])
def admin_create_user():
    need = _require_admin()
    if need:
        return need
    if request.method == "GET":
        return render_template('admin/create_user.html')

    username = (request.form.get("username") or "").strip().lower()
    visibility = (request.form.get("visibility") or "visible").strip().lower()
    if visibility not in {"visible", "hidden"}:
        visibility = "visible"
    ok_u, msg_u = validate_username(username)
    if not ok_u:
        return f"<p>Error: {msg_u}</p><p><a href='/admin/create_user'>Back</a></p>", 400
    if User.query.filter_by(username=username).first():
        return "<p>Error: username already exists.</p><p><a href='/admin/create_user'>Back</a></p>", 400

    # Generate temporary single-use password; user must change on first login.
    temp_password = base64.urlsafe_b64encode(os.urandom(12)).decode("utf-8") + "Aa1!"
    temp_dpass = base64.urlsafe_b64encode(os.urandom(12)).decode("utf-8") + "Aa1!"

    raw_user_key = generate_fernet_key()
    keys_db_key = _APP_KEK.encrypt(raw_user_key.encode("utf-8")).decode("utf-8")

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    try:
        priv_raw = priv.private_bytes_raw()
        pub_raw = pub.public_bytes_raw()
    except Exception:
        from cryptography.hazmat.primitives import serialization

        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    u = User(
        username=username,
        password_hash=hash_password(temp_password),
        dpass_hash=hash_password(temp_dpass),
        keys_database_key=keys_db_key,
        approved=True,
        visibility=visibility,
        is_admin=False,
        force_password_change=True,
        ed25519_pub_b64=base64.urlsafe_b64encode(pub_raw).decode("utf-8"),
        ed25519_priv_enc=Fernet(raw_user_key.encode("utf-8")).encrypt(priv_raw).decode("utf-8"),
        created_at=utcnow(),
        last_login=utcnow(),
    )
    db.session.add(u)
    db.session.commit()

    return render_template(
        'admin/user_created.html',
        username=username,
        temp_password=temp_password,
        temp_dpass=temp_dpass,
    )


@app.route("/admin/notifications", methods=["GET"])
def admin_notifications():
    need = _require_admin()
    if need:
        return need
    notes = AdminNotification.query.order_by(AdminNotification.created_at.desc()).limit(200).all()
    return render_template('admin/notifications.html', notes=notes)


@app.route("/admin/notifications/<int:note_id>/read", methods=["POST"])
def admin_mark_notification_read(note_id: int):
    need = _require_admin()
    if need:
        return need
    n = AdminNotification.query.get(note_id)
    if n:
        n.read = True
        db.session.commit()
    return redirect(url_for("admin_notifications"))


@app.route("/admin/manage_users", methods=["GET"])
def admin_manage_users():
    need = _require_admin()
    if need:
        return need
    # show two lists: visible and hidden (non-deleted) users
    visible = User.query.filter_by(deleted=False, visibility="visible").all()
    hidden = User.query.filter_by(deleted=False, visibility="hidden").all()
    return render_template("admin/manage_users.html", visible=visible, hidden=hidden)


@app.route("/admin/user/<int:user_id>", methods=["GET", "POST"])
def admin_user_edit(user_id: int):
    need = _require_admin()
    if need:
        return need
    u = User.query.get(user_id)
    if not u:
        return render_template('admin/user_not_found.html'), 404
    if request.method == "GET":
        return render_template('admin/user_edit.html', u=u)
    u.visibility = (request.form.get("visibility") or "visible").strip().lower()
    if u.visibility not in {"visible", "hidden"}:
        u.visibility = "visible"
    u.approved = bool(request.form.get("approved"))
    db.session.commit()
    return redirect(url_for("admin_user_edit", user_id=user_id))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id: int):
    need = _require_admin()
    if need:
        return need
    confirm = (request.form.get("confirm") or "").strip()
    if confirm != "DELETE":
        flash("Confirmation word mismatch.", "error")
        return redirect(url_for("admin_user_edit", user_id=user_id))
    auth = request.form.get("auth") or ""
    admin = _current_user()
    if not admin:
        return redirect(url_for("index"))
    master_ok = bool(admin.master_key_hash and verify_password(admin.master_key_hash, auth))
    if not verify_password(admin.password_hash, auth) and not master_ok:
        flash("Admin authentication failed.", "error")
        return redirect(url_for("admin_user_edit", user_id=user_id))

    target = User.query.get(user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_index"))

    # Remove owned files from disk
    for f in File.query.filter_by(owner_id=target.id).all():
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], f.stored_name))
        except Exception:
            pass

    db.session.delete(target)
    db.session.commit()
    flash("User physically deleted.", "success")
    return redirect(url_for("admin_index"))


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
    deny = _deny_view_only()
    if deny:
        return deny
    f = request.files.get('file')
    try:
        expiry_days = int(request.form.get('expiry_days', '365'))
    except ValueError:
        expiry_days = 30
    if not f:
        flash('No file selected', 'error')
        return redirect(url_for('upload_file'))
    if expiry_days < 1:
        expiry_days = 1
    if expiry_days > 365:
        expiry_days = 365
    f.filename = secure_filename(f.filename)
    data = f.read()
    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    file_key = os.urandom(32)
    nonce = os.urandom(12)
    token = AESGCM(file_key).encrypt(nonce, data, None)
    stored = ''.join(random.choices(string.ascii_letters+string.digits, k=32))
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    with open(path, 'wb') as out:
        out.write(token)
    file_record = File(owner_id=session['user_id'], filename=f.filename,
                       stored_name=stored,
                       expiry=datetime.utcnow()+timedelta(days=expiry_days),
                       owner_key_enc=encrypt_with_user_key_bytes(user, file_key),
                       nonce_b64=base64.urlsafe_b64encode(nonce).decode("utf-8"))
    db.session.add(file_record)
    db.session.commit()
    flash('File uploaded and encrypted.', 'success')
    return redirect(url_for('list_files'))


@app.route('/file/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    fi = File.query.get(file_id)
    if not fi:
        flash('File not found', 'error')
        return redirect(url_for('list_files'))
    access = None
    if fi.owner_id != session['user_id']:
        access = FileAccess.query.filter_by(file_id=file_id, user_id=session['user_id']).first()
    if fi.owner_id != session['user_id'] and not access:
        flash('Not authorized', 'error')
        return redirect(url_for('list_files'))

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # Backward compatibility: if key metadata is missing, return raw encrypted blob.
    if not fi.nonce_b64 or not fi.owner_key_enc:
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], fi.stored_name),
            as_attachment=True,
            download_name=fi.filename,
        )

    if fi.owner_id == user.id:
        key_token = fi.owner_key_enc
    else:
        key_token = access.user_key_enc if access else None

    if not key_token:
        flash("Missing file key for this user.", "error")
        return redirect(url_for("list_files"))

    try:
        file_key = decrypt_with_user_key_bytes(user, key_token)
        nonce = base64.urlsafe_b64decode(fi.nonce_b64.encode("utf-8"))
        with open(os.path.join(app.config["UPLOAD_FOLDER"], fi.stored_name), "rb") as inp:
            ciphertext = inp.read()
        plain = AESGCM(file_key).decrypt(nonce, ciphertext, None)
    except Exception:
        flash("Failed to decrypt file.", "error")
        return redirect(url_for("list_files"))

    return send_file(
        io.BytesIO(plain),
        as_attachment=True,
        download_name=fi.filename,
        mimetype="application/octet-stream",
    )


@app.route('/file/<int:file_id>/delete', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    deny = _deny_view_only()
    if deny:
        return deny
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
    deny = _deny_view_only()
    if deny:
        return deny
    username = (request.form.get('username') or '').strip().lower()
    user = User.query.filter_by(username=username).first()
    if not user or user.deleted or not user.approved:
        flash('User not found', 'error')
        return redirect(url_for('list_files'))
    fi = File.query.get(file_id)
    if not fi or fi.owner_id != session['user_id']:
        flash('File not found', 'error')
        return redirect(url_for('list_files'))
    if FileAccess.query.filter_by(file_id=file_id, user_id=user.id).first():
        flash('Already shared', 'info')
        return redirect(url_for('list_files'))

    owner = User.query.get(session["user_id"])
    if not owner or not fi.owner_key_enc:
        flash("File key not available for sharing.", "error")
        return redirect(url_for("list_files"))
    try:
        raw_file_key = decrypt_with_user_key_bytes(owner, fi.owner_key_enc)
        recipient_key_enc = encrypt_with_user_key_bytes(user, raw_file_key)
    except Exception:
        flash("Failed to prepare share key.", "error")
        return redirect(url_for("list_files"))

    fa = FileAccess(file_id=file_id, user_id=user.id, user_key_enc=recipient_key_enc)
    db.session.add(fa)
    db.session.commit()
    flash('File shared with '+username, 'success')
    return redirect(url_for('list_files'))


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    """
    If there is no admin account present, the first visit allows full
    registration: username/password/destruction password and the initial
    master key.  If an admin already exists but has not yet set their master
    key, this page simply collects the master key value.
    """
    admin = User.query.filter_by(is_admin=True).first()

    # helper to render the form
    def show_form(msg=None):
        if msg:
            flash(msg, "info")
        return render_template('admin/register.html')

    if not admin:
        # creating the very first admin
        if request.method == 'GET':
            return show_form()
        # POST: gather fields
        username = (request.form.get('username') or '').strip().lower()
        password = request.form.get('password')
        dpass = request.form.get('d_password') or request.form.get('dpassword')
        master_key = request.form.get('master_key')
        # basic validation
        if not username or not password or not dpass or not master_key:
            flash("All fields are required.", "error")
            return redirect(url_for('admin_register'))
        ok_u, msg = validate_username(username)
        if not ok_u:
            flash(f"Invalid username: {msg}", "error")
            return redirect(url_for('admin_register'))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for('admin_register'))
        ok_p, msg = validate_password(password, username=username)
        if not ok_p:
            flash(f"Invalid password: {msg}", "error")
            return redirect(url_for('admin_register'))
        ok_d, msg = validate_password(dpass, username=username)
        if not ok_d:
            flash(f"Invalid destruction password: {msg}", "error")
            return redirect(url_for('admin_register'))

        # create user record with encryption keys and signing keys
        raw_user_key = generate_fernet_key()
        keys_db_key = _APP_KEK.encrypt(raw_user_key.encode("utf-8")).decode("utf-8")

        # generate ed25519 signing keypair for admin
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        try:
            priv_raw = priv.private_bytes_raw()
            pub_raw = pub.public_bytes_raw()
        except Exception:
            from cryptography.hazmat.primitives import serialization

            priv_raw = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_raw = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

        admin = User(
            username=username,
            password_hash=hash_password(password),
            dpass_hash=hash_password(dpass),
            keys_database_key=keys_db_key,
            approved=True,
            visibility="visible",
            is_admin=True,
            force_password_change=False,
            master_key_hash=hash_password(master_key),
            ed25519_pub_b64=base64.urlsafe_b64encode(pub_raw).decode("utf-8"),
            ed25519_priv_enc=Fernet(raw_user_key.encode("utf-8")).encrypt(priv_raw).decode("utf-8"),
            created_at=utcnow(),
            last_login=utcnow(),
        )
        db.session.add(admin)
        db.session.commit()
        flash("Admin account created. You can now log in.", "success")
        return redirect(url_for('login'))

    # at this point an admin exists
    if admin.master_key_hash:
        flash("Master key already configured.", "info")
        return redirect(url_for('index'))

    # admin exists but master key not set
    if request.method == 'GET':
        return show_form()

    master_key = request.form.get('master_key')
    if not master_key:
        flash("Master key is required.", "error")
        return redirect(url_for('admin_register'))

    admin.master_key_hash = hash_password(master_key)
    db.session.commit()
    flash("Master key configured. You can now log in with your admin password or master key.", "success")
    return redirect(url_for('login'))


# --- Main (no Tor) ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # pre‑create any admin account from environment variables before
        # the first request arrives
        _ensure_admin_account()
    print("GhostCache (surface web) running at http://127.0.0.1:5000/")
    debug = bool(os.environ.get("FLASK_DEBUG"))
    app.run(host='0.0.0.0', port=5000, debug=debug)