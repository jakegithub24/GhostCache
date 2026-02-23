# New Flow

**Issue** :
1. Private kay is being stored in DB as a plain text.
2. No forward secracy.
3. If private key is compromised, past messages can be decrypted.
4. RSA is slow, not realtime friendly => [EDCH + AES-GCM].
5. No auth layer for messages, no tamper detedction.
6. For key exchange connection [X25519 => ECDH].
7. For message encryption => AES-256-GCM.
8. Message auth => Built into GCM.
9. For signature verification => [ED25519]
10. Transparent TSL v1.3
11. Key derivation => [HKDF]

**Implementation** :
- Each user has indentity key pairs => [ED25519]
- Hellman key exchange algorithm for secure key exchange => [X25519]
- Connection request logic
```
if connection == accept:
  ECDH key exchange
  Derive shared secret (HKDF = AES + HMAC)
``` 
- Send message logic
```
send message:
  Generate random nounce (nounce = 128bit psudo random value used to prevent replay attacks)
  Encrypt message using AES-GCM
  Store cypher text + nounce together
```
- Receive message logic
```
We have to derive same shared key
We have to decrypt message using AES-GCM
(No storing of key in DB in plain text)
```