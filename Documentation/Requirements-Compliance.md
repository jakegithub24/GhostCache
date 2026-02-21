# Requirements Compliance Report

This document checks the GhostCache Flask application against **Documentation/Requirements.md**.

---

## User related

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | User creates account with **username**, **password**, and **destruction_password**. No other verification. | ✅ Met | `register()` uses `username`, `password`, `d_pass` (form label: "Destruction password"). No email or other verification. |
| 2 | Login with username + password; entering **destruction_password** deletes account immediately. | ✅ Met | `login()`: normal password → login; matching `dpass_hash` → account deleted and redirect to index. |
| 3 | User must log in at least once per month; otherwise account is deleted. | ✅ Met | In `login()`, if `datetime.utcnow() - user.last_login > timedelta(days=30)` the user is deleted and redirected to register. |
| 4 | Account deletion removes chat, contact info, hosted files, and generated keys (PGP and file encryption). | ✅ Met | `User` model uses SQLAlchemy `cascade='all, delete-orphan'` on: `sent_connections`, `received_connections`, `sent_messages`, `received_messages`, `files`, `blacklist_*`, `accessible_files`. `delete_account()` also deletes owned files from disk before deleting the user. |

---

## File hosting related

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | User can host a file encrypted with **Fernet** (32-byte/256-bit key generated for decryption). | ✅ Met | `upload_file()` uses `Fernet.generate_key()` and `Fernet(key).encrypt(data)`; files are stored encrypted on disk. |
| 2 | User must keep the generated key safe; **key is not stored on server**. | ✅ Met | Key is only shown once in a flash message: "keep the key safe: " + key. Not stored in DB or on disk. |
| 3 | Max hosting duration **1 year**; after that file is deleted automatically. **No way to extend** expiry. | ✅ Met | `expiry_days` is capped at 365; `cleanup()` in `@app.before_request` deletes files where `File.expiry < now`. No extend endpoint or logic. |
| 4 | User can set **desired expiry** (≤ 1 year) and **delete the file** whenever they want. | ✅ Met | Upload form has `expiry_days` (min 1, max 365). `delete_file()` allows owner to delete; file is removed from disk and DB. |
| 5 | **Access list** per file; users in that list can see the file (e.g. under host’s profile). | ✅ Met | `FileAccess` model; `share_file()` adds entries; `list_files()` shows "Files shared with you"; `download_file()` allows access for owner or users in `FileAccess`. (Files appear in the recipient’s "Files" as shared, not on a separate "host profile" page.) |

---

## Connection related

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | User can **search** other users by **username**. | ✅ Met | `search_users()` at `/search` with query param `q`; filters by `User.username.contains(q)` and excludes blocked/blocking. |
| 2a | User can send **one connection request**. If **accepted**, public keys are exchanged and stored in DB. | ✅ Met | `send_connection_request()` creates one `Connection`; `accept_connection()` generates RSA keypairs, encrypts with user keys, stores on `Connection` and in `Contact.public_key_enc`. |
| 2b | If **denied**, request sender cannot find that profile again. | ✅ Met | `deny_connection()` creates a `Blacklist` entry (blocker = receiver, blocked = sender); `search_users()` excludes users in `blocked_by` / `blocked_out`, so the denied sender won’t see the denier in search. |
| 3 | On accept, **PGP (private & public) keys** [generated/stored]. | ✅ Met | `accept_connection()` calls `generate_rsa_keypair()` per user; private/public stored encrypted per user in `Connection` (`sender_*_enc`, `receiver_*_enc`). (Doc says "PGP"; app uses RSA 2048, which is in line with key exchange.) |
| 4 | On accept, encrypted **message queue** is created and stored in DB. | ✅ Met | `accept_connection()` creates a symmetric `chat_key`, encrypts it for each user (`chat_key_enc_sender`, `chat_key_enc_receiver`). Messages are stored encrypted in `Message` and decrypted using this key. |

---

## Chat related

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | **Each connection is unique**; breaching one should not compromise others. | ✅ Met | Per-connection RSA keypairs and a per-connection Fernet chat key; no reuse across connections. |
| 2 | **New PGP key pairs** for every connection. | ✅ Met | `accept_connection()` calls `make_and_store_keys()` for both sender and receiver per connection. |
| 3 | **Encryption** for every connection. | ✅ Met | Chat uses Fernet with the per-connection key; message content is encrypted before storage and decrypted when read. |

---

## Server related

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | Application receives web requests via **WSGI** (e.g. NGINX in front), then to Flask app. | ⚠️ Partial | App is a standard Flask app and can be run behind any WSGI server (e.g. Gunicorn). No NGINX or Gunicorn config is included in the repo; deployment is left to the operator. |
| 2 | Flask app routes **all app traffic through Tor**. | ⚠️ Partial | `connect_to_tor()` creates an ephemeral Tor hidden service (stem) mapping onion:80 → localhost:5000. If Tor/stem is unavailable, the app still runs in "non-Tor" mode. Full "route every request through Tor" would typically be done at network/proxy level (e.g. only binding to Tor or using Tor as outbound proxy); current code only exposes the app via a Tor hidden service. |

---

## Resources (stack alignment)

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | **Frontend:** Jinja (SSR) | ✅ Met | Templates in `templates/` use Jinja2 (Flask default). |
| 2 | **Backend:** Flask → WSGI → NGINX | ⚠️ Partial | Flask is used; WSGI/NGINX are deployment choices, not implemented in code. |
| 3 | **Encryption:** AES256, RSA, Argon2id, Fernet | ✅ Met | Argon2 (argon2-cffi) for passwords; RSA 2048 for connection keys; Fernet (AES in CBC + HMAC) for chat and file encryption. |
| 4 | **Web server:** Gunicorn WSGI | ⚠️ Partial | Not in repo; app runs with `app.run(port=5000)`; Gunicorn would be used in production. |
| 5 | **Router:** NGINX | ⚠️ Partial | No NGINX config in repo. |
| 6 | **Proxy:** torsocks, socks5 | ⚠️ Partial | Tor integration is via stem (hidden service); no torsocks/socks5 proxy config in app. |

---

## Summary

- **User, file hosting, connection, and chat** requirements are **fulfilled** in the application logic and data model.
- **Server / resources** items that depend on deployment (WSGI server, NGINX, Tor routing, torsocks/socks5) are **partially met**: the app is built to be run behind WSGI and can register a Tor hidden service, but actual WSGI, NGINX, and proxy setup are not part of the codebase.

## Minor note

- Requirements.md uses **"desctruction_password"** (typo); the app and UI use **"destruction password"** / **`d_pass`** consistently.
