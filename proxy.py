import uuid
import signal
import sys
import os
import socket

ACTIVE_PROXIES_DIR = "active_proxies"

class Proxy:
    def __init__(self, host):
        self.host = host

        # Unique ID
        self.proxy_id = str(uuid.uuid4())

        # Ensure active_proxies directory exists
        os.makedirs(ACTIVE_PROXIES_DIR, exist_ok=True)

        # Create a TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.host, self.port = self.sock.getsockname()

        # File path for this proxy
        self.file_path = os.path.join(ACTIVE_PROXIES_DIR, f"{self.proxy_id}.txt")

        # Line to store in the file
        self.entry = f"{self.proxy_id},{self.host},{self.port}\n"

    def register(self):
        with open(self.file_path, "w") as f:
            f.write(self.entry)
        print(f"Registered proxy {self.proxy_id} at {self.host}:{self.port}")

    def unregister(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
            print(f"Removed proxy {self.proxy_id} from active_proxies")
            
    def start(self):
        self.sock.listen()
        print(f"Proxy {self.proxy_id} listening on {self.host}:{self.port}")
        try:
            while True:
                client_sock, addr = self.sock.accept()
                print(f"Accepted connection from {addr}")
                # TODO: handle onion/DH payloads here
                client_sock.close()
        finally:
            self.unregister()


# ---- graceful shutdown handling ----
def setup_signal_handlers(proxy):
    def shutdown_handler(signum, frame):
        print("\nShutting down proxy...")
        proxy.unregister()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

def main():
    HOST = "127.0.0.1"

    proxy = Proxy(HOST)
    proxy.register()
    setup_signal_handlers(proxy)
    proxy.start()

# ---- MAIN ----
if __name__ == "__main__":
    main()