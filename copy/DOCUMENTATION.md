# GhostCache — Detailed Documentation

This document describes the GhostCache Flask application in depth: purpose, design, data model, routes, configuration, security considerations, testing, deployment, and recommended improvements.

Table of contents
- Project overview
- Getting started (requirements & run)
- Architecture and components
- Database models (schema)
- Route reference (detailed)
- Authentication & session handling
- File storage and upload flow
- Messaging / connection flow
- Configuration and environment
- Testing
- Security considerations
- Troubleshooting
- Development notes and extension ideas

---

Project overview
----------------
GhostCache is a local/testing Flask application that provides user accounts, peer-to-peer style connections, encrypted chat between connected users, and file upload/share capabilities. It is intentionally a non-production, surface-web variant intended for local testing and experimentation.

Primary goals
- Provide a minimal, self-contained system demonstrating: user registration/login, ephemeral file uploads (with expiry), connection requests and acceptance, symmetric-key encrypted chat using Fernet, and simple sharing controls.
- Keep the code and dependencies small and direct so it is easy to inspect, run, and modify.

Getting started
---------------
Prerequisites
- Python 3.10+ (project was developed and tested with a local venv present at `myvenv`).
- System packages that may be required for cryptography (follow OS-specific install instructions if pip install fails).

Install and run
1. Activate virtual environment (PowerShell example):

```powershell
.\myvenv\Scripts\Activate.ps1
```

2. Install dependencies (if not already installed):

```powershell
pip install -r requirements.txt
```

3. Run the app:

```powershell
python app.py
```

Notes: on first run the app creates the SQLite database (default: `test.db`) and the `uploads/` folder.

Architecture and components
---------------------------
Files of interest
- `app.py` — single-file Flask application; contains models, utils, routes, and startup logic.
- `test.py` — unit tests that exercise main routes using Flask's test client and an in-memory SQLite DB.
- `uploads/` — runtime directory used to store uploaded binary blobs.
- `how_to_use.md`, `how_to_use_laymans.md` — user-facing usage instructions.

High-level flow
- Web UI and API endpoints are provided via Flask routes.
- User registration creates a User record with Argon2-hashed passwords and a per-user Fernet key (`keys_database_key`) used to encrypt user-specific private values stored in the DB (for demo purposes).
- Connections are represented by `Connection` records; acceptance triggers generation of RSA key pairs and a shared chat key encrypted for each participant.
- Chat messages are stored encrypted (Fernet) in `Message.content` and delivered via `/chat/poll` for the recipient.
- File uploads are encrypted with a generated Fernet key per upload; the blob written to disk is the encrypted payload and the key is shown to the uploader (keep safe).

Database models (schema)
------------------------
All models are SQLAlchemy ORM classes defined in `app.py`.

- User
  - `id` (Integer PK)
  - `username` (String, unique)
  - `password_hash` (String) — Argon2 hash of login password
  - `dpass_hash` (String) — Argon2 hash of destruction password
  - `keys_database_key` (String) — base64 Fernet key used to symmetrically encrypt user-private values
  - `created_at`, `last_login` (DateTime)
  - relationships: connections, messages, files, blacklist, accessible_files

- Connection
  - `id`, `sender_id`, `receiver_id` (FKs to User)
  - `status` (pending/accepted/denied)
  - `sender_privkey_enc`, `sender_pubkey_enc`, `receiver_privkey_enc`, `receiver_pubkey_enc` (Text) — encrypted PEMs for keys
  - `chat_key_enc_sender`, `chat_key_enc_receiver` (Text) — chat symmetric key encrypted per user

- Contact (mirror mapping created on accept)
- File
  - `id`, `owner_id`, `filename`, `stored_name` (unique random filename on disk), `expiry` (DateTime), `created_at`
  - `access_list` relationship (FileAccess)

- FileAccess (grants)
  - `file_id`, `user_id`, `granted_at`

- Blacklist
  - `blocker_id`, `blocked_id`, `created_at`

- Message
  - `id`, `sender_id`, `receiver_id`, `content` (encrypted token), `timestamp`, `delivered`

Route reference (detailed)
--------------------------
All input endpoints accept form-encoded data from HTML forms; JSON is also supported where reasonable (handlers use `request.get_json(silent=True)` and fallback to `request.form`). Below is the route-by-route behavior and expected parameters.

- `GET /`
  - Description: index page; injects `session` (if logged in) to template.
  - Template: `index.html`.

- `GET /register`
  - Show registration form.

- `POST /register`
  - Accepts form or JSON with keys: `username`, `password`, `d_pass` (destruction password).
  - Validation: all fields required; username must be unique.
  - On success: creates `User`, sets `last_login` and redirects to `/login`.

- `GET /login`
  - Show login form.

- `POST /login`
  - Accepts `username`, `password` via form or JSON.
  - If password matches `password_hash`: sets `session['user_id']` and `session['username']`, updates `last_login`.
  - If password matches `dpass_hash` (destruction password): deletes the account and redirects.
  - If `last_login` is older than 30 days: account is removed (in this app behavior).

- `GET /logout`
  - Clears session and redirects to `/`.

- `POST /delete_account`
  - Requires login. Deletes user record and associated files (attempts to remove stored file blobs from disk).

- `GET /connect` and `POST /connect`
  - GET: render connect UI.
  - POST: form field `username` — target username to request connection. Validations: cannot connect to self; target must exist; not allowed if blocked; duplicate connections prevented.
  - Creates a `Connection` with `status='pending'`.

- `GET /connections`
  - Lists pending sent, pending received, and accepted connections for the logged-in user.

- `POST /connect/accept/<int:conn_id>`
  - Must be receiver. Generates RSA keypairs for both sides (server-side function `generate_rsa_keypair()`), encrypts keys with each user's `keys_database_key` using Fernet, stores them in the Connection record, constructs `Contact` rows, generates a chat key (Fernet) encrypted for both users, sets `status='accepted'`.

- `POST /connect/deny/<int:conn_id>`
  - Must be receiver. Adds a `Blacklist` entry (blocker=receiver, blocked=sender) and sets connection status to `denied`.

- `POST /chat/send`
  - Requires authenticated session.
  - Accepts either form or JSON with `receiver_id` and `message`.
  - Validates there is an accepted `Connection` between sender and receiver. Uses the appropriate encrypted chat key stored in the connection (`chat_key_enc_sender` or `chat_key_enc_receiver`), decrypts it using `decrypt_with_user_key(user, ciphertext)`, then encrypts the message payload using Fernet and stores as `Message.content`.
  - Returns JSON status `queued` and HTTP 201 on success.

- `GET /chat/poll`
  - Requires session. Returns JSON array of undelivered messages for the logged-in user (messages where `receiver_id == uid` and `delivered == False`). Decrypts each message using that user's copy of the chat key and marks messages delivered.

- `GET/POST /chat/<int:other_id>`
  - GET: checks for an accepted connection; decrypts chat key and renders `chat.html` with decrypted messages.
  - POST: sends message via same process as `/chat/send` (form-based in that handler path) and redirects back to chat page.

- `GET /search?q=...`
  - Requires session. Returns template `search.html` with results of username substring match excluding users blocked by or blocking the current user.

- `GET /files`
  - Lists files owned by and shared with logged-in user.

- `GET/POST /file/upload`
  - GET: return upload form.
  - POST: form file field `file` and optional `expiry_days` (defaults to 365, capped at 365). The uploaded file's bytes are encrypted with a newly generated Fernet key. The encrypted blob is stored in `uploads/<stored_name>` (random 32-char filename). A `File` row is created with `expiry` set to now + expiry_days.
  - The page flashes the generated Fernet key to the uploader — this key is required to decrypt the stored blob offline.

- `GET /file/<int:file_id>`
  - Requires session. Only the owner or a `FileAccess` grantee may download. Uses Flask `send_file` to return the stored encrypted blob as an attachment using the original filename.

- `POST /file/<int:file_id>/delete`
  - Requires login and ownership. Deletes the DB record and tries to remove the stored file from disk.

- `POST /file/<int:file_id>/share`
  - Requires login and ownership. Form field `username`. Creates `FileAccess` if user exists and not already granted.

Authentication & session handling
------------------------------
- The app uses Flask sessions (`app.secret_key` set at start). For local/testing, `app.secret_key` uses `os.urandom(24)` — meaning sessions are reset on each restart. In production, set a stable, secure `SECRET_KEY`.
- Session keys used: `user_id` and `username`.

File storage and upload flow (detailed)
------------------------------------
1. User posts a file via `/file/upload`.
2. Server generates a new Fernet key (string), reads the file bytes, encrypts with that key, and writes the encrypted bytes to `uploads/<stored_name>`.
3. A `File` DB record is created with metadata incl. `stored_name` and `expiry`.
4. The user is shown (flashed) the key — this key is not stored in plain text in the DB, only the uploader receives it.
5. Downloaders must be the owner or have an access grant via `FileAccess`.

Messaging / connection flow (detailed)
-------------------------------------
1. A sends a connection request to B by creating a `Connection` (pending).
2. B accepts through `/connect/accept/<id>`: server generates RSA keypairs for both sides and encrypts them with each user's `keys_database_key`.
3. Server generates a symmetric chat key (Fernet) used to encrypt messages between A and B. The chat key is encrypted separately for A and for B and stored in the `Connection` record.
4. When A sends a message to B, server picks the correct encrypted chat key for A to decrypt it (using A's `keys_database_key`) then uses the raw chat key to encrypt the message (Fernet) and saves the ciphertext in `Message.content`.
5. When B polls with `/chat/poll`, server uses B's encrypted chat key to decrypt to raw key then decrypts stored messages for B and returns plaintext in JSON.

Configuration and environment
-----------------------------
Main configuration values live in `app.py`:
- `SQLALCHEMY_DATABASE_URI` — default `sqlite:///test.db`; override via environment or by editing before app startup.
- `MAX_CONTENT_LENGTH` — default 50 * 1024 * 1024 (50 MB)
- `UPLOAD_FOLDER` — default `uploads` (created automatically)

For production readiness you should:
- Use a proper database (Postgres, MySQL) and set `SQLALCHEMY_DATABASE_URI` accordingly.
- Set a fixed `app.secret_key` or `SECRET_KEY` via environment.
- Run behind a WSGI server (gunicorn/uwsgi) and configure TLS at the reverse proxy.

Testing
-------
- `test.py` contains unit tests that exercise routes using Flask's test client. The test suite uses an in-memory SQLite DB (`sqlite:///:memory:`) so it does not modify `test.db`.
- Run tests with the project's venv python: `D:/Flask/myvenv/Scripts/python.exe test.py`.

Security considerations
-----------------------
- Password hashing: Argon2 is used via `argon2.PasswordHasher()`.
- Encryption: Fernet (symmetric) is used for file blobs and chat keys. RSA keypairs are generated for connection participants, but for simplicity private keys are stored encrypted with the user's `keys_database_key` which itself is created and stored in the DB (this is for demo; in production, user secrets should not be stored in the DB unprotected or should be protected using a server-side KMS).
- Session secrets: `app.secret_key` is random on each run — set a fixed, secure value in production.
- CSRF: Not implemented; add Flask-WTF or other CSRF protection for all state-changing POST routes if exposing to the public internet.
- Input handling: handlers accept JSON and form-encoded payloads; `request.get_json(silent=True)` is used to avoid 415 errors when `Content-Type` isn't set.

Encryption & Key Management (detailed)
-------------------------------------
This section explains precisely what keys the app uses, when they are generated, how they are stored, whether they change over time, and how the key exchange is performed.

Key types used by the application
- `keys_database_key` (per-user Fernet key): generated once when a user registers. This is a base64-encoded Fernet symmetric key stored in the `User.keys_database_key` column. It is used to symmetrically encrypt other secrets that the server stores on behalf of the user (for example, RSA private keys and encrypted chat keys). In the current implementation this key is generated server-side and stored in the DB.

- RSA keypairs (per-connection): when a connection is accepted the server generates an RSA keypair for each participant via `generate_rsa_keypair()`. PEM-encoded private keys are encrypted with the recipient's `keys_database_key` and stored in the `Connection` record fields such as `sender_privkey_enc` and `receiver_privkey_enc`. Public keys are likewise stored encrypted.

- Chat symmetric key (per-connection): when a connection is accepted the server generates a fresh Fernet chat key for the connection. The raw chat key is encrypted separately for each participant using that participant's `keys_database_key` and stored in the connection fields `chat_key_enc_sender` and `chat_key_enc_receiver`. The chat key is used to encrypt message payloads saved in `Message.content`.

- File upload key (per-file): when a file is uploaded the server generates a fresh Fernet key for that upload only. The uploaded bytes are encrypted with that key and the encrypted blob is stored on disk at `uploads/<stored_name>`. The generated per-file key is shown to the uploader (flashed on the web UI) but the server does not persist the raw key (only the encrypted blob). The uploader is therefore responsible for keeping the file key if they need to decrypt the blob offline.

When keys are generated
- `keys_database_key`: generated at user registration and saved to the `User` record.
- RSA keypairs and chat key: generated when a `Connection` is accepted (via `/connect/accept/<conn_id>`).
- File key: generated when a file is uploaded (via `/file/upload`).

Key persistence and lifecycle
- `keys_database_key` (per-user): persistent in the DB for as long as the `User` record exists. In this app the server deletes users in some workflows (e.g., if `last_login` is older than 30 days, or when the destruction password is used) — that will permanently remove their stored `keys_database_key` and any encrypted secrets that depend on it.

- RSA keypairs and chat key: stored in the `Connection` record encrypted with the participants' `keys_database_key`. They persist until the connection or user is deleted.

- File keys (per-file): only shown to the uploader and not stored plaintext on the server. If the uploader loses the key, the encrypted blob on disk cannot be decrypted.

Are keys permanent or rotated?
- In this implementation keys are generated and remain static unless the application is modified to rotate them.
  - The `keys_database_key` is generated once at registration and remains the same until the user is deleted (no rotation mechanism built-in).
  - RSA keypairs and chat keys are generated on connection acceptance and kept until the connection or account deletion.
  - File keys are generated per-upload and only communicated to the uploader; the server does not rotate or keep them in plaintext.

Security model and key exchange
- How key exchange is performed in this app:
  - The server performs all key generation and encryption operations. For example, when a connection is accepted the server generates RSA pairs and a chat symmetric key. The server then encrypts those private values with each user's `keys_database_key` and stores the ciphertext in the DB.
  - To use the chat key, the server decrypts the stored encrypted chat key with the user's `keys_database_key` (server-side) and obtains the raw chat key to encrypt/decrypt messages.

- Security implications:
  - The server-side generation and storage of all keys means the server operator (or anyone who can access the database and server secrets) can obtain the raw chat keys, RSA private keys, and user `keys_database_key` values. That makes this design server-trust-heavy: confidentiality is protected from outside attackers only while the server and DB remain trusted and secured.
  - Messages are encrypted at rest in the database using Fernet with the connection chat key, but the server can decrypt them because it has access to the encrypted chat key and the user's encryption keys. This is not true end-to-end encryption where the server is unable to decrypt messages.

- Recommendations to improve security (production-grade):
  1. Use client-side key generation and exchange (true end-to-end encryption): generate user keys in the browser or client, perform an authenticated key exchange (e.g., X25519/ECDH with signatures), and never send raw private keys or chat keys to the server. This prevents the server from reading messages.
 2. Use a key management system (KMS) or Hardware Security Module (HSM) to store or wrap critical secrets (`keys_database_key` or a server master-wrapping key) instead of storing them raw in the DB.
 3. Use TLS for all client-server traffic (deploy behind HTTPS) to secure keys in transit.
 4. Implement key-rotation and re-encryption flows: allow users to rotate `keys_database_key` and re-wrap stored secrets, or provide a controlled revocation flow for compromised keys.
 5. Consider deriving per-user key material from a user-known secret that is not stored server-side (e.g., a passphrase with Argon2 key derivation) and then using that to decrypt stored secrets; this increases user-responsibility but reduces server-trust.

FAQs (detailed answers)
-----------------------
Q: How are messages encrypted?
A: When a connection is accepted the server generates a fresh symmetric chat key (Fernet). That key is encrypted for each participant with the participant's `keys_database_key` and stored in the connection record. When a message is sent, the server decrypts the encrypted chat key (using the sender's `keys_database_key`), uses the revealed raw chat key to encrypt the message with Fernet, and stores the ciphertext in the `Message.content` field. When the recipient polls, the server decrypts the recipient's encrypted chat key and uses it to decrypt the stored ciphertext for delivery.

Q: Who can decrypt messages?
A: In the current design, the server can decrypt stored messages because it manages keys and stores encrypted chat keys and `keys_database_key` values. Any party with server and DB access can therefore access raw messages. If you need guarantees that the server cannot read messages, implement client-side key generation and a direct end-to-end key exchange so the server never sees raw keys.

Q: What happens if the server or database is compromised?
A: If an attacker gains access to the server and database, they may be able to obtain `User.keys_database_key` values and the encrypted RSA/chat keys, allowing them to decrypt chat and some private data. To mitigate this risk, a production deployment should use a KMS for wrapping keys, and avoid storing raw per-user keys in the DB where possible.

Q: Are file upload keys stored on the server?
A: No — the per-file Fernet key generated at upload time is presented to the uploader (flashed to the UI) and is not stored plaintext on the server. The encrypted blob on disk cannot be decrypted without that key. Keep it safe. If the uploader loses it, the file cannot be recovered (unless the server is modified to persist the key securely).

Q: What is the "destruction password" and how does it work?
A: During registration users supply a normal login password and a separate destruction password (`d_pass`). If a user later authenticates with the destruction password instead of the login password, the server interprets that as a request to delete the account: it deletes the `User` record and associated records (including files) immediately. This is a deliberate destructive action and cannot be undone.

Q: Can keys be rotated or revoked?
A: Not by default. Keys such as `keys_database_key` and per-connection chat keys are generated and kept until account or connection deletion. For production, implement rotation: create new keys, re-encrypt stored secrets with the new wrapping keys, and publish revocation notices to peers.

Q: Is this end-to-end encrypted?
A: Not in its present form. The server generates and stores the necessary keys to encrypt and decrypt messages, so it acts as a trusted party. To achieve end-to-end encryption (E2EE), move key generation to the client, perform authenticated key exchange between clients, and avoid storing raw wrapping keys or private keys server-side.

Q: How can we make this secure for production quickly?
A: Short roadmap for improving security:
  - Add TLS to the deployment (HTTPS).
  - Replace server-side persistent storage of `keys_database_key` with a KMS / envelope encryption approach.
  - Implement client-side key generation and E2EE for chat.
  - Add CSRF protection, input validation and rate-limiting.

---
Additional notes
----------------
This documentation aims to describe the current implementation choices and their implications. If you want, I can produce a migration plan to convert this design to a client-side E2EE model or sketch API changes for key rotation and KMS integration.


Troubleshooting
---------------
- Unsupported Media Type / JSON errors: ensure clients set `Content-Type: application/json` for JSON payloads, or send form-encoded data. The server now attempts to handle both.
- Database/ORM errors: if you see schema mismatch or integrity errors, remove `test.db` and restart (development only). For production, run migrations (this project does not include Alembic migrations).
- File missing: check `uploads/` and verify `File.stored_name` value.

Development notes and extension ideas
-----------------------------------
- Add Alembic migrations to track schema changes for non-trivial upgrades.
- Replace per-user stored `keys_database_key` with a proper secret management solution or derive per-user encryption keys from a server-side master key (or user password via SRP/Argon2 with secure key derivation and not persistent storage of plaintext keys).
- Implement CSRF protection and rate limiting for spam protection.
- Add WebSocket or Server-Sent Events for real-time chat instead of polling.
- Add a management UI for expired file cleanup, manual DB inspection, and administration.

Appendix: developer shortcuts
----------------------------
- Activate venv (PowerShell): `.\myvenv\Scripts\Activate.ps1`
- Run app: `python app.py`
- Run tests: `D:/Flask/myvenv/Scripts/python.exe test.py` (or `python test.py` with venv activated)

File: DOCUMENTATION.md — comprehensive reference for developers and maintainers.
