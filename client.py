import random
import os

from cryptography.hazmat.primitives import serialization
import crypto_utils


folder_path = "./relays_PKE_keys"
sub_folder_path = "relay_id_"
def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def discover_proxies():
    proxies = {}

    for folder in os.listdir(folder_path):
        full_folder_path = os.path.join(folder_path, folder)
        for file in os.listdir(full_folder_path):
            if file.endswith("_public.pem"):
                proxy_id = file.replace("_public.pem", "")
                proxies[proxy_id] = file

    return proxies


def choose_circuit(proxies, k=3):
    proxy_ids = list(proxies.keys())

    if len(proxy_ids) < k:
        raise ValueError("Not enough proxies available")

    return random.sample(proxy_ids, k)


def main():
    proxies = discover_proxies()

    print("[Client] Available proxies:", list(proxies.keys()))
    circuit = choose_circuit(proxies, 3)
    print("[Client] Chosen circuit:", circuit)

    # Load selected public keys
    public_keys = {}
    for proxy_id in circuit:
        path = f"{folder_path}/{sub_folder_path}{proxy_id}/{proxies[proxy_id]}"
        public_keys[proxy_id] = load_public_key(path)

    print("[Client] Loaded public keys for circuit")
    
    # Del later Test
    print(public_keys)
    print(public_keys["1"].public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    message = "encrypted data"

    # PUT IN RELAY LATER CUZ WE NEED PRIVATE KEYS
    def load_private_key(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    private_key = {}
    for proxy_id in circuit:
        path = f"{folder_path}/{sub_folder_path}{proxy_id}/{proxy_id}_private.pem"
        private_key[proxy_id] = load_private_key(path)

    # Test
    stuff = crypto_utils.one_way_key_exchange_encrypt(public_keys["1"])
    key= crypto_utils.one_way_key_exchange_decrypt(private_key["1"], stuff["encrypted_key"])

    message = b"Iaaaaa"

    cipher1 = crypto_utils.create_cipher(stuff["secret_key"], stuff["iv"])
    cipher2 = crypto_utils.create_cipher(key, stuff["iv"])

    ct = crypto_utils.aes_encrypt(cipher1, message)
    print(crypto_utils.aes_decrypt(cipher2, ct))
    #TODO: Use public keys to encrypt for one-way key exchange


if __name__ == "__main__":
    main()