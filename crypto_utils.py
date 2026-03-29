from enum import Enum
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# DONT TOUCH THESE or bad things may happen
AES_key_length = 32 # length in bytes 16 24 or 32
iv_key_length = 16

class RelayFlag(Enum):
    ENTRY=1
    EXIT=2
    MIDDLE=3
    NONE = 4 # Client or Server Node


class Packet_Type(Enum):
    DATA=1
    EXCHANGE=2 # For exchaning symmetric key

def one_way_key_exchange_encrypt(pub_key):
    secret_key = os.urandom(AES_key_length) #MESSAGE IS IN BYTE FORMAT ALREADY
    iv = os.urandom(iv_key_length)
    encrypted_key = pub_key.encrypt(
        secret_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # i dont know if we need encrypt iv or not but u can check later for me thx :)
    return {"encrypted_key": encrypted_key, "secret_key": secret_key, "iv": iv}

def one_way_key_exchange_decrypt(private_key, encrypted_key):
    secret_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return secret_key

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
    return decrypted_msg.decode()