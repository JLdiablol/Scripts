from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

# Simulate loading the client's public RSA key
with open("path/to/client_public_key.pem", "r") as key_file:
    client_public_key = RSA.import_key(key_file.read())

def encrypt_with_aes(session_key, data):
    """Encrypt data using AES-256 ECB."""
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    return cipher_aes.encrypt(data)

def decrypt_with_aes(session_key, data):
    """Decrypt data using AES-256 ECB."""
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    return cipher_aes.decrypt(data)

def encrypt_with_rsa(public_key, data):
    """Encrypt data using RSA."""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

@app.route('/challenge', methods=['GET'])
def generate_challenge():
    # Generate a session key (AES-256 key) and a challenge
    session_key = get_random_bytes(32)  # AES-256 requires a 32-byte key
    challenge = get_random_bytes(16)  # Let's assume a 16-byte challenge

    # Encrypt the challenge with the session key using AES-256 in ECB mode
    encrypted_challenge = encrypt_with_aes(session_key, challenge)

    # Encrypt the session key using the client's public RSA key
    encrypted_session_key = encrypt_with_rsa(client_public_key, session_key)

    # Encode the encrypted challenge and session key in Base64
    base64_encrypted_challenge = base64.b64encode(encrypted_challenge).decode('utf-8')
    base64_encrypted_session_key = base64.b64encode(encrypted_session_key).decode('utf-8')

    # Simulate storing session_key and challenge for later verification
    app.session_key = session_key
    app.challenge = challenge

    return jsonify({"challenge_encrypted": base64_encrypted_challenge, "sessionkey_encrypted": base64_encrypted_session_key})

@app.route('/verify', methods=['POST'])
def verify_challenge():
    data = request.json
    received_encrypted_challenge_plus_one_base64 = data.get("challenge_plus_one")

    # Decode and decrypt received challenge+1
    received_encrypted_challenge_plus_one = base64.b64decode(received_encrypted_challenge_plus_one_base64)
    decrypted_challenge_plus_one = decrypt_with_aes(app.session_key, received_encrypted_challenge_plus_one)

    # Verify the challenge+1
    expected_challenge_plus_one = int.from_bytes(app.challenge, byteorder='big') + 1
    received_challenge_plus_one_int = int.from_bytes(decrypted_challenge_plus_one, byteorder='big')

    if received_challenge_plus_one_int == expected_challenge_plus_one:
        return jsonify({"result": "success", "message": "Challenge verified successfully."})
    else:
        return jsonify({"result": "failure", "message": "Challenge verification failed."})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
