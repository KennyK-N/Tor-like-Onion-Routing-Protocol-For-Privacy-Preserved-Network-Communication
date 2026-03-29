import uuid
import signal
import sys
import os
import socket
import threading
import queue
import crypto_utils

ACTIVE_PROXIES_DIR = "active_proxies"

class Proxy:
    def __init__(self, host):
        self.host = host
        self.proxy_id = str(uuid.uuid4())
        os.makedirs(ACTIVE_PROXIES_DIR, exist_ok=True) # make sure directory exists

        # Make DH key pair
        self.ecdh_private, self.ecdh_public = crypto_utils.generate_ecdh_keypair()
        # Serialize public key to save in file
        pub_key_pem_str = crypto_utils.serialize_public_key(self.ecdh_public).decode('utf-8')


        # Socket for incoming connections (from prev node)
        self.prev_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.prev_sock.bind((host, 0))
        self.host, self.port = self.prev_sock.getsockname()

        # Socket for outgoing next node connection
        self.next_sock = None
        self.next_host = None
        self.next_port = None

        # Info file for this proxy
        self.file_path = os.path.join(ACTIVE_PROXIES_DIR, f"{self.proxy_id}.txt")
        self.entry = f"{self.proxy_id},{self.host},{self.port},{pub_key_pem_str}\n" 

        self.running = True

    def register(self):
        with open(self.file_path, "w") as f:
            f.write(self.entry)
        print(f"Registered proxy {self.proxy_id} at {self.host}:{self.port}")

    def unregister(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
            print(f"Removed proxy {self.proxy_id} from active_proxies")

    # Create a socket for the next node in the circuit (or the server)
    def set_next_node(self, host, port):
        self.next_host = host
        self.next_port = port
        self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.next_sock.connect((host, port))
        print(f"Connected to next node at {host}:{port}")

    # Handle client->server communication
    def handle_client_to_server(self):
        print(f"Incoming thread handling connection from prev node")
        try:
            while self.running:
                data = self.prev_sock.recv(4096)
                if not data:
                    break
                print(f"Received {len(data)} bytes from prev node")
                # Echo back for testing (DELETE LATER)
                self.prev_sock.sendall(data)
                # TODO: decrypt layer before checking packet type and forwarding

                # Check the packet type and handle accordingly
                packet_type = None # TODO: get packet type from decrypted packet
                if packet_type == crypto_utils.Packet_Type.REQUEST.value:
                    # TODO: Create next_sock with packet info if not already connected
                    if self.next_sock is None:
                        # Use packet info to connect to next node here
                        # self.set_next_node(next_host, next_port)
                        pass
                    # Forward request packet
                    self.next_sock.sendall(data)
                    print(f"Sent {len(data)} bytes to next node")
                    # If no thread for next node connection, start one
                    if self.next_sock is None:
                        threading.Thread(target=self.handle_server_to_client, daemon=True).start()
                elif packet_type == crypto_utils.Packet_Type.EXCHANGE_DH.value:
                    # Handle Diffie-Hellman exchange packet
                    # Since proxy public key is saved in file, actually don't need to send it back, 
                    # just need to send back the salt to use in crypto_derive_shared_key() 
                    # Although we could also send public key back with salt instead of saving it in file, it's ur choice
                    pass
                
        except Exception as e:
            print(f"Incoming error: {e}")
        finally:
            self.prev_sock.close()
            print(f"Closed connection from prev node")

    # Handle server->client communication
    def handle_server_to_client(self):
        print(f"Outgoing thread started for next node at {self.next_host}:{self.next_port}")
        try:
            while self.running:
                data = self.next_sock.recv(4096)
                if data is None:
                    break
                # TODO: add layer to packet before forwarding it 
 
                # Forward data
                self.prev_sock.sendall(data)
                print(f"Forwarded {len(data)} bytes to prev node")
        except Exception as e:
            print(f"Outgoing error: {e}")
        finally:
            if self.next_sock:
                self.next_sock.close()
                print(f"Closed connection with next node")

    def start(self):
        self.prev_sock.listen()
        print(f"Proxy {self.proxy_id} listening on {self.host}:{self.port}")
        try:
            while self.running:
                self.prev_sock, _ = self.prev_sock.accept()
                self.handle_client_to_server()
                
        finally:
            self.unregister()
            self.running = False


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