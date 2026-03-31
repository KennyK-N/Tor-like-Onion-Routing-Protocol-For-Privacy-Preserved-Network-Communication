import uuid
import signal
import sys
import os
import socket
import threading
import queue
import crypto_utils
from threading import Lock
import pickle
import packet as PacketFormat

ACTIVE_PROXIES_DIR = "active_proxies"
HOST = "127.0.0.1"
# FOr demo purposes leave it like this for now other wise it will take forever to clean up
RECEIVE_TIMEOUT = 5
RELAY_TIMEOUT = 5

# Only remove the key from when the session is finish
client_sem_key={} #{client_sock.getpeername(), and the key from DF}, KEY LAST FOR ENTIRE SESSION, I.E CLIENT IS CONNECTED TO THE RELAY

class Proxy:
    def __init__(self, host):
        self.host = host
        self.proxy_id = str(uuid.uuid4())
        os.makedirs(ACTIVE_PROXIES_DIR, exist_ok=True) # make sure directory exists

        # Socket for incoming connections (from prev node)
        self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.relay_socket.bind((host, 0))
        self.host, self.port = self.relay_socket.getsockname()

        # Info file for this proxy
        self.file_path = os.path.join(ACTIVE_PROXIES_DIR, f"{self.proxy_id}.txt")
        self.entry = f"{self.proxy_id},{self.host},{self.port}\n" 

        self.running = True
        self.receive_sockets={} # For sockets where the relay is receiving
        self.send_sockets={} # For sockets where the relay is forwarding

        self.thread = None

    def register(self):
        with open(self.file_path, "w") as f:
            f.write(self.entry)
        print(f"Registered proxy {self.proxy_id} at {self.host}:{self.port}")

    def unregister(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
            print(f"Removed proxy {self.proxy_id} from active_proxies")

    def relay_send(self, client_name, data):
        sock = self.send_sockets.get(client_name)
        if not sock:
            print(f"No socket found for {client_name}")
            return False
        try:
            sock.sendall(data) 
            return True
        except Exception as e:
            print(f"Error sending to {client_name}: {e}, closing socket.")
            try:
                sock.close()
            except Exception as close_err:
                print(f"Error closing socket for {client_name}: {close_err}")
            finally:
                self.send_sockets.pop(client_name, None)
                return False

    # Handle Server-> Client Commmunication
    def forward_listener(self, forward_sock, client_sock, symm_key):
        try:
            # forward_sock.settimeout(RECEIVE_TIMEOUT)
            while self.running:
                # try:
                data = forward_sock.recv(4096)
                # except socket.timeout:
                #     break
                if not data:
                    break
                

                #TODO: encrypt data with symm_key before putting in payload
                iv = os.urandom(16) 
                cipher = crypto_utils.create_cipher(symm_key, iv)
                encrypted_data = crypto_utils.aes_encrypt(cipher, data)


                packet = PacketFormat.Packet(iv=iv, payload=encrypted_data)
                client_sock.sendall(PacketFormat.to_bytes_rep(packet))
                print("Forwarded response back")

        except Exception as e:
            _, _, tb = sys.exc_info()

            print(f"Forward Listener error: {e} at line {tb.tb_lineno}")
        finally:
            try:
                forward_sock.close()
            except Exception:
                pass

    # Handle Client -> Server communication
    def relay_logic(self, client_sock, socket_name):
        print(f"Incoming thread handling connection from prev node")
        retry_counter_data = 0
        NUM_ATTEMPTS_DATA = 10
        NUM_ATTEMPTS_TIME_OUT = 2
        retry_counter_timeout = 0
        forward_sock = None 
        symm_key = None # symmetric key from key exchange
        try:
            # client_sock.settimeout(RECEIVE_TIMEOUT)
            while self.running:
                # Time out mechanism to time out recv
                # try:
                data = client_sock.recv(4096)
                print(f"received data from prev node")
                # except socket.timeout:
                #     if retry_counter_timeout > NUM_ATTEMPTS_TIME_OUT:
                #         print("Error: Connection timed out while waiting for data")
                #         break
                #     else:
                #         retry_counter_timeout += 1
                #         continue

                retry_counter_timeout=0

                # DO NOT DELETE THIS, its when the client abrubtly closes the connection, this allows the relay to close the connection as well
                if not data:
                    if retry_counter_data > NUM_ATTEMPTS_DATA:
                        raise Exception("Failed to receive Data from client or relay")
                    else:
                        retry_counter_data += 1
                        continue
                
                retry_counter_data = 0

                # load data using pickle if needed
                if isinstance(data, bytes):
                    packet = PacketFormat.to_obj_rep(data)
                else:
                    continue  

                # Decrypt payload if possible, if symm_key is None, it means this packet is for key exchange, so skip decryption and just do the exchange
                if symm_key is not None:
                    cipher = crypto_utils.create_cipher(symm_key, packet.iv) 
                    payload = crypto_utils.aes_decrypt(cipher, packet.payload)
                else:
                    payload = packet.payload

                try: # Check if payload is a pickled Packet
                    payload = PacketFormat.to_obj_rep(payload)
                except Exception:
                    pass
                if isinstance(payload, PacketFormat.Packet): # If there's an internal packet, it means this should be forwarded
                    # Start a listener thread for the forward if we are forwarding for the first time, 
                    # otherwise we can just use the same forward socket since the listener thread would already be running
                    if forward_sock is None:
                        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        forward_sock.connect((payload.dst_addr, payload.dst_port))
                        
                        # start listener thread so we can receive the response back
                        t = threading.Thread(
                            target=self.forward_listener,
                            # Note that symm_key will not be None, since first packet will be unlayered, for key exchange, so won't enter this if statement
                            args=(forward_sock, client_sock, symm_key),
                            daemon=True
                        )
                        t.start()
                    # Forward the internal packet to the next relay/server
                    forward_sock.sendall(PacketFormat.to_bytes_rep(payload))
                
                else: # If the payload isn't a packet, it is for a key exchange with this relay
                    # Generate key pair and salt for the exchange
                    private, public = crypto_utils.generate_ecdh_keypair()
                    salt = os.urandom(16) # Generate random salt
                    
                    # Get symmetric key using the client's public key and the relay's private key
                    symm_key = crypto_utils.derive_shared_key(private, crypto_utils.load_public_key(payload), salt)
                    packet = PacketFormat.Packet(
                        payload = {
                            "public_key": crypto_utils.serialize_public_key(public),
                            "salt": salt,
                            "test_message": "encryption/decryption successful"
                        }
                    )
                       
                    # Send back public key and salt so client can derive symmetric key
                    print("Sending key exchange")
                    client_sock.sendall(PacketFormat.to_bytes_rep(packet))

        except Exception as e:
            _, _, tb = sys.exc_info()

            print(f"Incoming thread error: {e} at line {tb.tb_lineno}")

        finally:
            print(f"Closed connection for {socket_name}")

            try:
                client_sock.close()
            except Exception:
                pass

            self.receive_sockets.pop(socket_name, None)

    def start_relay(self, server_sock, host, port):
        print(f"Proxy {self.proxy_id} listening on {host}:{port}")
        server_sock.listen()
        # server_sock.settimeout(RELAY_TIMEOUT)

        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                print(f"Accepted connection from {addr}")
                socket_name = client_sock.getpeername()
                self.receive_sockets[socket_name] = client_sock

                t = threading.Thread(
                    target=self.relay_logic,
                    args=(client_sock,socket_name,), daemon=True
                )

                t.start()
            # except socket.timeout:
            #     pass
            except Exception as e:
                print("Error: ", e)
                continue


    def start(self):
        try:
            self.thread = threading.Thread(target=self.start_relay, args=(self.relay_socket, self.host, self.port),
            daemon=True # Maybe delete later
                                           )
            self.thread.start()

            #TODO: Make interactable like list options, e.g 1. do something, 2. do something, 3.exit
            while(True):
                temp = input("For menu or smthing: ")
                if (temp == "exit"): # THIS EXIT IS GOOD
                    break

        finally:
            print("\nShutting down proxy...")
            self.unregister()
            self.running = False

# ---- graceful shutdown handling ----
def setup_signal_handlers(proxy):
    def shutdown_handler(signum, frame):
        print("\nShutting down proxy...")
        proxy.unregister()
        proxy.running=False
        # proxy.thread.join() # PUT THIS BACK IF U DISABLE DAEMON
        proxy.relay_socket.close()
        recv_socket_list = proxy.receive_sockets
        send_socket_list = proxy.send_sockets

        for key in recv_socket_list:
            recv_socket_list[key].close()

        for key in send_socket_list:
            send_socket_list[key].close()

        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

def main():
    proxy = Proxy(HOST)
    proxy.register()
    setup_signal_handlers(proxy)
    proxy.start()
    # proxy.thread.join() # PUT THIS BACK IF U DISABLE DAEMON
    
    # clean up
    recv_socket_list = proxy.receive_sockets
    send_socket_list = proxy.send_sockets

    for key in recv_socket_list:
        recv_socket_list[key].close()

    for key in send_socket_list:
        send_socket_list[key].close()

    proxy.relay_socket.close()

# ---- MAIN ----
if __name__ == "__main__":
    main()