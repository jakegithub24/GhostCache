# Project Requirements (new flow)

**Application Description** : This application is about a secure anonymous communication with encrypted file sharing.

**Features** :
- Self Hosted
- Quick registration - username, password, d_password (destruction_password).
  - 'username' should consist 'a-z, 0-9, _' only. It should always start with characters. username must be max '<=15' charaters long.
  - User's 'password' and 'd_password', admin's 'password' and 'master_key' should be salted before storing to DB.
  - Usage of 'rainbow table' is recommended for salt randomization.
- Admin's approval to user's account registration request is mandatory. Also admin can create anonymous accounts that should be only provided to highly confidential people.
  - If admin creates an account of a person, there should be first login password set by admin. Once user logins using that temporary single use password, user has to set new password for that account.
- User can delete their account using 'destruction password', from settings or Admin can delete user's account.
  - User account should be logical delete, not pysical delete. User should be tagged as deleted, account's view only rights should be transfered to admin automatically.
  - Admin can only access and view the account, chats, shared files. Admin can't initiate new connections, can't share new files, can't accept new connection requests.
  - Logic is simple, there must be 'master_key' (password specifically set for accessing delted user accounts by the admin). Hash of 'master_key' will be copied to deleted user's login password's hash feild.
  - Deleted user's username should be like 'deleted_username'. So that other user's can know that this particular user have deleted their account.
- User can connect with another user which is already save in the system,he can message,file sharing also done with encrypted data.
  - He can search their name ,when seraching there will be a list of users.
- Admin can remove any user anytime for imergency purpose, deletion must follow same procedure as user deletion. Physical delete should be there instead of logical delete.

**Cryptographics Algorithms To Use** :
- 'argon2id' for user's 'password' and 'd_password'.
- 'x25519' (ECDH, Hellman's key exchange algorithm) is to be used for secure key exchange while initiating a connection after receiver accepts the sender's connection request.
- 'HKDF' key algoritm (AES + HMAC) is to be used for message encryption at sender's side and decryption at receiver's side.
- Mixture of randomly generated 'nounce' (Psudo random value used to prevent replay attacks) also can be considered as a security addon.
- 'ed25519' for signature verification of message sent by sender. Message should be stored encrypted in database. No once can see it apart from 'sender', 'reciever' and 'admin'.

**Things To Consider (IMPORTANT)** :
- Sensitive info such as 'passwords', 'messages', 'connection keys', 'file encryption' keys should not be stored as plain text in DB. This is gonna prevent access to data if someone takes physical hold on server (database).
- There should be authentication layer for messages, tamper detection. SHA-256 can be used to generate hash, store that has in DB. Hash should be verified by the receiver on receiving a message.
- TLS v1.3 should be used for handshake encryption.
- No javascript at all, since future plans to host this application on TOR network.

**Tech To Use**
- Frontend :
  - HTML (jinja templating)
  - CSS (styling)
- Backend :
  - Flask (python micro-framework)
- Request Handling :
  - NGINX
- Python Web Server
  - Gunicorn (WSGI - Web Server Gateway Interface)

**Basic Traffic Flow** :
  - Client (clearnet for now, TOR in the future) → NGINX → Gunicorn → Flask
