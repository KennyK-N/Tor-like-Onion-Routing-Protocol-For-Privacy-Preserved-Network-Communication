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
        self.entry = f"{self.proxy_id},{self.host},{self.port}\n"

        self.running = True

    def register(self):
        with open(self.file_path, "w") as f:
            f.write(self.entry)
        print(f"Registered proxy {self.proxy_id} at {self.host}:{self.port}")

    def unregister(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
            print(f"Removed proxy {self.proxy_id} from active_proxies")

    def set_next_node(self, host, port):
        """Set the next node (proxy/server) to forward messages to"""
        self.next_host = host
        self.next_port = port
        self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.next_sock.connect((host, port))
        print(f"Connected to next node at {host}:{port}")

    def handle_client_to_server(self):
        """Thread: Handle previous node / client data"""
        print(f"Incoming thread handling connection from prev node")
        try:
            while self.running:
                data = self.prev_sock.recv(4096)
                if not data:
                    break
                print(f"Received {len(data)} bytes from prev node")
                # Check the packet type and handle accordingly
                packet_type = crypto_utils.Packet_Type.REQUEST.value # For now just assume it's a request
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
                        threading.Thread(target=self.handle_next_node, daemon=True).start()
                elif packet_type == crypto_utils.Packet_Type.EXCHANGE_DH.value:
                    # Handle Diffie-Hellman exchange packet
                    pass
                
        except Exception as e:
            print(f"Incoming error: {e}")
        finally:
            self.prev_sock.close()
            print(f"Closed connection from prev node")

    def handle_server_to_client(self):
        """Thread: Send data from the queue to the next node"""
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
                prev_sock, addr = self.prev_sock.accept()
                self.handle_prev_node(prev_sock, addr)
                
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