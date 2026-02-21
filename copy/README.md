# GhostCache (Surface Web / Non-Tor)

This folder is a **Tor-free** copy of GhostCache for testing on the surface web (e.g. `http://127.0.0.1:5000` or your LAN). No Tor or stem dependency.

## Run locally

```bash
cd Non-Tor
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000/** (or **http://\<your-ip\>:5000/** from another device on the same network). The app binds to `0.0.0.0` so it is reachable from other machines.

## Differences from main project

- **No Tor:** No stem, no hidden service. Plain Flask on port 5000.
- **Debug mode:** `app.run(..., debug=True)` for easier development.
- **Same features:** Registration, login, destruction password, connections, E2E chat, encrypted file upload/sharing, search, blacklist.

Use this only for local or trusted network testing. For anonymity, use the main GhostCache project with Tor.
