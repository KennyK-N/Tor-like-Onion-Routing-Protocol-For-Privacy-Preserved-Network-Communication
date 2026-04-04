from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import os

# DONT TOUCH THESE or bad things may happen
AES_key_length = 32 # length in bytes 16 24 or 32
iv_key_length = 16

# RSA Signature/Verification Methods
def generate_verification_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# Diffie-Hellman Key Exchange Methods
# Generate private/public key pair
def generate_ecdh_keypair(curve=ec.SECP256R1()):
    """Generate private/public key pair"""
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

# Lets client/relays get shared key using other party's public key
def derive_shared_key(private_key, peer_public_key, salt):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_key_length,
        salt=salt,
        info=b'handshake data',
    ).derive(shared_secret)

    return derived_key


# Key serialization methods
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(public_bytes):
    return serialization.load_pem_public_key(public_bytes)



# Message encryption/decryption AES methods
def create_cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CBC(iv))

def aes_encrypt(cipher, message):
    if isinstance(message, str):
        message = message.encode()
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    encryptor = cipher.encryptor()
    return encryptor.update(padded_message) + encryptor.finalize()

def aes_decrypt(cipher, cipher_text):
    decryptor = cipher.decryptor()
    decrypted_message_with_padding = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_msg = unpadder.update(decrypted_message_with_padding) + unpadder.finalize()
    return decrypted_msg