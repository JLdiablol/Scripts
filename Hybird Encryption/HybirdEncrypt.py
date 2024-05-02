from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import sys
import base64

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(data, public_key):
    aes_key = urandom(16)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key, iv, encrypted_data

def read_file_data(filepath):
    with open(filepath, "rb") as file:
        data = file.read()
    return data

def overwrite_original_file(filepath, encrypted_aes_key, iv, encrypted_data):
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(base64.b64encode(encrypted_aes_key).decode('utf-8') + '\n')
        file.write(base64.b64encode(iv).decode('utf-8') + '\n')
        file.write(base64.b64encode(encrypted_data).decode('utf-8'))

def export_private_key(private_key, filename="private_key.pem"):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def main():
    if len(sys.argv) != 2:
        print("Usage: python encrypt_file.py <path_to_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    data = read_file_data(file_path)
    private_key, public_key = generate_rsa_keys()
    encrypted_aes_key, iv, encrypted_data = encrypt_data(data, public_key)
    overwrite_original_file(file_path, encrypted_aes_key, iv, encrypted_data)
    export_private_key(private_key)
    print("Encryption complete. Original file has been overwritten.")
    print("Save your decrypt key carefully!.")

if __name__ == "__main__":
    main()
