# How to use GhostCache (surface-web)

This document explains how to set up, run, test, and interact with the Flask app in this repository.

## Requirements
- Python 3.10+ (a virtualenv is recommended)
- Install dependencies:

```powershell
.\myvenv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run the application
1. Activate your virtual environment (PowerShell):

```powershell
.\myvenv\Scripts\Activate.ps1
```

2. Start the app (development):

```powershell
python app.py
```

The app will create the SQLite DB and the `uploads` folder automatically.

## Run the test suite

```powershell
D:/Flask/myvenv/Scripts/python.exe test.py
# or, if venv is activated
python test.py
```

## Web UI flows
- Open http://127.0.0.1:5000/ in your browser.
- Register an account via the `/register` page, then login via `/login`.
- Upload files at `/file/upload` (max 50MB default). Uploaded blobs are stored in the `uploads/` folder and a database record is created.
- Manage connections at `/connect` and `/connections`. Accepting a connection generates keys for encrypted chat.
- Chat is available at `/chat/<other_id>` and `/chat/send` (API) and polled at `/chat/poll`.

## Important API notes
- Routes accept either traditional form-encoded requests (HTML forms) or JSON POST bodies.
- If sending JSON, make sure to set the `Content-Type: application/json` header. Example (curl):

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"alice","password":"pass","d_pass":"del"}' http://127.0.0.1:5000/register
```

- The app uses `request.get_json(silent=True)` and falls back to `request.form`. If you still see an "Unsupported Media Type" error from a client, ensure the `Content-Type` matches the payload.

## Key endpoints (summary)
- `GET /` — index page
- `GET,POST /register` — register new user; params: `username`, `password`, `d_pass`
- `GET,POST /login` — login; params: `username`, `password`
- `GET /logout` — logout
- `GET,POST /connect` — send connection request (form: `username`)
- `GET /connections` — list pending/accepted connections
- `POST /connect/accept/<conn_id>` — accept connection (server side keys generated)
- `POST /connect/deny/<conn_id>` — deny and block sender
- `POST /chat/send` — send message via form or JSON (`receiver_id`, `message`)
- `GET /chat/poll` — get queued messages for logged-in user
- `GET,POST /chat/<int:other_id>` — chat page (GET) and send (POST)
- `GET /search?q=...` — user search
- `GET /files` — list files for user
- `GET /file/<file_id>` — download file (requires permission)
- `GET,POST /file/upload` — upload file (form file input plus `expiry_days`)
- `POST /file/<file_id>/delete` — delete file
- `POST /file/<file_id>/share` — share with username (`username` form field)
- `POST /delete_account` — delete logged-in account

## Uploads and storage
- Uploads saved to the `uploads/` directory (created automatically).
- Default maximum upload size: 50MB (see `app.config['MAX_CONTENT_LENGTH']`).

## Troubleshooting
- Unsupported Media Type / missing JSON: ensure `Content-Type: application/json` when posting JSON. Alternatively use form-encoded requests.
- If you get DB errors, remove `test.db` (if present) and restart; the app will recreate the database schema.
- For permission/file-not-found problems with downloads, check that the uploaded file exists under `uploads/` and that the `File` DB record has the correct `stored_name` and `owner_id`.

## Security notes
- This app uses Argon2 for password hashing and Fernet for symmetric encryption in local/test mode. Do not expose the development secret key in production.
- `app.secret_key` is randomized on each start for local testing. For a persistent deployment, set a fixed secure secret key.

## Next steps / extensions
- Add automated API tests that send JSON without a Content-Type header to verify robustness.
- Consider adding CSRF protection for form endpoints in a production deployment.

---
File: how_to_use.md — created to help developers run and test the project.
