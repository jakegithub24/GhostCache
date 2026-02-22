import sys
from cryptography.fernet import Fernet

if len(sys.argv) != 3:
    print("Usage: python decrypt_ghostcache.py <encrypted_file> <fernet_key>")
    sys.exit(1)

file_path = sys.argv[1]
key = sys.argv[2].encode()  # key must be bytes

try:
    fernet = Fernet(key)
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)

    # Save the decrypted file (you can change the output name)
    output_path = file_path + '.decrypted'
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"✅ File decrypted successfully: {output_path}")
except Exception as e:
    print(f"❌ Decryption failed: {e}")
