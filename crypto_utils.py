from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import base64


def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key


def generate_ecc_key_pair():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key


def perform_diffie_hellman(private_key, peer_public_key):
    private_key = ECC.import_key(private_key)
    peer_public_key = ECC.import_key(peer_public_key)
    shared_secret = private_key.d * peer_public_key.pointQ
    return shared_secret.x.to_bytes(32, byteorder='big')


def derive_keys(shared_secret):
    salt = b'MTProto v2 salt'
    key_material = HKDF(shared_secret, 80, salt, SHA256, 1)
    return key_material[:32], key_material[32:64], key_material[64:]


def encrypt_message(message, encryption_key, hmac_key):
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    hmac = HMAC.new(hmac_key, cipher.nonce + ciphertext + tag, SHA256).digest()
    return base64.b64encode(cipher.nonce + ciphertext + tag + hmac).decode('utf-8')


def decrypt_message(encrypted_message, encryption_key, hmac_key):
    encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:-48]
    tag = encrypted_data[-48:-32]
    hmac = encrypted_data[-32:]

    # Verify HMAC
    calculated_hmac = HMAC.new(hmac_key, nonce + ciphertext + tag, SHA256).digest()
    if calculated_hmac != hmac:
        raise ValueError("Message authentication failed")

    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')


def ratchet_keys(current_keys):
    salt = b'Ratchet salt'
    new_keys = HKDF(current_keys, 80, salt, SHA256, 1)
    return new_keys[:32], new_keys[32:64], new_keys[64:]