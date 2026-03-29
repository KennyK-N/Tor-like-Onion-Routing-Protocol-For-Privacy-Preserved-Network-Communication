from enum import Enum

class RelayFlag(Enum):
    ENTRY=1
    EXIT=2
    MIDDLE=3
    NONE = 4 # Client or Server Node

def diffie_hellmen_exchange(pub_B, priv_A):
    pass