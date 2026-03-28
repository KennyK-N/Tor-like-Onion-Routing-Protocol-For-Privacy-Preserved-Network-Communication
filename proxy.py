import sys
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(proxy_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_path = f"{proxy_id}_private.pem"
    public_path = f"{proxy_id}_public.pem"

    # Prevent overwrite
    if os.path.exists(private_path) or os.path.exists(public_path):
        print(f"Proxy {proxy_id} keys already exist. Skipping generation.")
        return

    # Save private key
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            # No encryption for now cuz i don't wanna deal with it :)
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(public_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Proxy {proxy_id} keys generated.")

def main():
    if len(sys.argv) != 2:
        print("Needs proxy_id as argument")
        sys.exit(1)

    proxy_id = sys.argv[1]
    generate_keys(proxy_id)


if __name__ == "__main__":
    main()
  