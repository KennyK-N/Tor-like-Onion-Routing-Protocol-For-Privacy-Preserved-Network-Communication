import json
from enum import Enum
import pickle


class Packet:
    def __init__(self, payload, iv=None, dst_addr= None, dst_port = None):
        self.payload = payload # can either be the actual message or the another packet object, either way this will be encrypted by the client, and decrypted as it traverses
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.iv = iv # IV used for AES encryption/decryption of payload

def to_bytes_rep(packet):
    return pickle.dumps(packet)

def to_obj_rep(packet):
    return pickle.loads(packet)
