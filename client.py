import random
import os

from cryptography.hazmat.primitives import serialization


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def discover_proxies():
    proxies = {}

    for file in os.listdir("."):
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
        path = proxies[proxy_id]
        public_keys[proxy_id] = load_public_key(path)

    print("[Client] Loaded public keys for circuit")

    #TODO: Use public keys to encrypt for one-way key exchange


if __name__ == "__main__":
    main()