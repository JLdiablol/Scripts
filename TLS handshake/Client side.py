#Decode session_key(base64)->s_key_decode
#Decrypt s_key_decode(private_key)->s_key
#Decode challenge(base64)->challenge_decode
#Decrypt challenge_decode(session_key)->challenge
#Convert challenge to interger -> challenge_int
#Add 1 to challenge_int -> challenge_new_int
#Convert challenge_new_int to bytestring of hex characters -> challenge_bh
#Encrypt challenge_bh(session_key)->challenge_bh_encrypted
#Encode challenge_bh_encrypted(base64)->challenge_bh_encrypted_encoded

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64

# Load private key from file
private_key_path = "private_key.pem"
with open(private_key_path, 'r') as f:
    private_key = RSA.import_key(f.read())

# Provided encrypted session key and challenge
sessionkey_encrypted_base64 = "INNPUT SESSION KEY HERE"
challenge_encrypted_base64 = "INNPUT CHALLENGE HERE"
# EXAMPLE: {"sessionkey_encrypted": "xxx", "challenge_encrypted": "xxx"}

# Decode and decrypt the session key
decoded_encrypted_session_key = base64.b64decode(sessionkey_encrypted_base64)
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(decoded_encrypted_session_key)

# Decode and decrypt the challenge
decoded_encrypted_challenge = base64.b64decode(challenge_encrypted_base64)
cipher_aes_decrypt = AES.new(session_key, AES.MODE_ECB)
decrypted_challenge = cipher_aes_decrypt.decrypt(decoded_encrypted_challenge)

# Convert challenge to integer, add 1, and prepare for re-encryption
challenge_int = int.from_bytes(decrypted_challenge, byteorder='big') + 1
challenge_hex_str = format(challenge_int, "x")
challenge_bytes_for_encryption = challenge_hex_str.encode()

# Encrypt the modified challenge and encode in Base64
cipher_aes_encrypt = AES.new(session_key, AES.MODE_ECB)
encrypted_challenge_plus_one = cipher_aes_encrypt.encrypt(challenge_bytes_for_encryption)
base64_encrypted_challenge_plus_one = base64.b64encode(encrypted_challenge_plus_one)

# Convert to string to send to server
challenge_plus_one_str = base64_encrypted_challenge_plus_one.decode('utf-8')

challenge_plus_one_str

