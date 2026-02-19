# Project requirements

## User Related :
  1. User is gonna create an account using 'username', 'password' and 'desctruction_password'. No other verification is needed.
  2. User can log into account using 'username' and 'password'. If user enters 'destruction_password', then their account gets deleted immediately.
  3. User must login once in a month, otherwiser their account gets deleted.
  4. Deletion of an account of particular user will result into deletion of chat, contact info, hosted files and generated keys (PGP and file encryption keys).

## File Hosting Related :
  1. User can host a file, encrypted with 'Fernet' encryption (32byte/256bits key will be generated for decryption).
  2. User has to keep generated/entered key safe, it will not be stored on server.
  3. User can host a file max for '1 year'. After 1 year file will get deleted automatically. There will not be any way to extend the 'expiry time'.
  4. User can set 'desired expiry time' (less than 1 year) and 'delete the file' whenever they want.
  5. User will have 'access specifier list' for every file. Users from that list will be able to see that file under host's profile.

## Connection Related :
  1. User will be able to search other users with the 'username'.
  2. User can send one 'connection request'.
      a. If user 'accepts' the connection request, public keys of both users are gets exchanged and stored in DB for future communication.
      b. If user 'denies' the connection request, request sender will not be able to find that profile again.
  3. Once user 'accepts' the connection request, PGP (private & public) key. 
  4. Once user 'accepts' the connection request, encrypted 'message queue' will get generated and stored on DB.

## Chat Related :
  1. Every connection request will be unique. If one connection gets breached, attacker shouldn't be able to compromise it.
  2. New PGP key pairs will get generated for every connection request.
  3. Every connection request must secured using encryption layer.

## Server Related :
  1. Application will get web requests from internet using 'WSGI' (not confirm if NGINX is required) and then to 'Flask App'.
  2. Flask App is gonna route every app traffic through TOR nodes. 

## Resources :
  1. **Frontend :** Jinja (SSR)
  2. **Backend :** Flask => WSGI (Web Server Gateway Interface) => NGINX.
  3. **Encryption Algo :** AES256, RSA, Bcrypt/Argon2id (Argon2id is more secure), Fernet.
  4. **Web Server :** Gunicorn WSGI (Web Server Gateway Interface).
  5. **Router :** NGINX.
  6. **Proxy :** torsocks, socks5.
