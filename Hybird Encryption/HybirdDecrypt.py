from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import sys
import base64

def load_rsa_keys():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Adjust or securely handle the password
            backend=default_backend()
        )
    return private_key

def decrypt_data(encrypted_aes_key, iv, encrypted_data, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def read_encrypted_file(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        encrypted_aes_key = base64.b64decode(file.readline().strip())
        iv = base64.b64decode(file.readline().strip())
        encrypted_data = base64.b64decode(file.readline().strip())
    return encrypted_aes_key, iv, encrypted_data

def overwrite_encrypted_file(filepath, decrypted_data):
    with open(filepath, "wb") as file:
        file.write(decrypted_data)

def main():
    if len(sys.argv) != 2:
        print("Usage: python decrypt_file.py <path_to_encrypted_file>")
        sys.exit(1)

    encrypted_file_path = sys.argv[1]
    private_key = load_rsa_keys()
    encrypted_aes_key, iv, encrypted_data = read_encrypted_file(encrypted_file_path)
    decrypted_data = decrypt_data(encrypted_aes_key, iv, encrypted_data, private_key)
    overwrite_encrypted_file(encrypted_file_path, decrypted_data)
    print("Decryption complete. Original file has been restored.")

if __name__ == "__main__":
    main()
