import uuid
import signal
import sys
import os
import socket
import threading
import queue
import crypto_utils
from threading import Lock

ACTIVE_PROXIES_DIR = "active_proxies"
# FOr demo purposes leave it like this for now other wise it will take forever to clean up
RECEIVE_TIMEOUT = 5
RELAY_TIMEOUT = 5
IS_RELAY= crypto_utils.RelayFlag.RELAY.value

mutex = Lock()

# Will need to generate a salt for each client

# Only remove the key from when the session is finish
client_sem_key={} #{client_sock.getpeername(), and the key from DF}, KEY LAST FOR ENTIRE SESSION, I.E CLIENT IS CONNECTED TO THE RELAY
'''
Do this instad save the df key in a file in the relay folder in the active fo;lder, overwrite the file if another key exchange happens and delete the file when the relay folder is deleted

'''
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
        self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.relay_socket.bind((host, 0))
        self.host, self.port = self.relay_socket.getsockname()

        # Info file for this proxy
        self.file_path = os.path.join(ACTIVE_PROXIES_DIR, f"{self.proxy_id}.txt")
        self.entry = f"{self.proxy_id},{self.host},{self.port},{pub_key_pem_str}\n" 

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

    # Handle client->server communication
    def relay_logic(self, client_sock, socket_name):
        print(f"Incoming thread handling connection from prev node")
        retry_counter_data = 0
        NUM_ATTEMPTS_DATA = 10
        NUM_ATTEMPTS_TIME_OUT = 2
        retry_counter_timeout = 0

        try:
            client_sock.settimeout(RECEIVE_TIMEOUT)
            while self.running:
                # Time out mechanism to time out recv
                try:
                    data = client_sock.recv(4096)
                except socket.timeout:
                    if retry_counter_timeout > NUM_ATTEMPTS_TIME_OUT:
                        print("Error: Connection timed out while waiting for data")
                        break;
                    else:
                        retry_counter_timeout += 1
                        continue

                retry_counter_timeout=0

                # DO NOT DELETE THIS, its when the client abrubtly closes the connection, this allows the relay to close the connection as well
                if not data:
                    if retry_counter_data > NUM_ATTEMPTS_DATA:
                        raise Exception("Failed to receive Data from client or relay")
                    else:
                        retry_counter_data += 1
                        continue

                retry_counter_data = 0

                #print(f"Received {len(data)} bytes from prev node")
                # Echo back for testing (DELETE LATER)
                print(f"\nData is {data}")
                client_sock.sendall(data)

                '''
                HERE WE DECRYPT AND BREAK DOWN THE PACKET AND PREPARE IT FOR SENDING
                '''

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

                    # # If no thread for next node connection, start one
                    # if self.next_sock is None:
                    #     threading.Thread(target=self.handle_server_to_client, daemon=True).start()
                elif packet_type == crypto_utils.Packet_Type.EXCHANGE_DH.value:
                    # Handle Diffie-Hellman exchange packet
                    # Since proxy public key is saved in file, actually don't need to send it back, 
                    # just need to send back the salt to use in crypto_derive_shared_key() 
                    # Although we could also send public key back with salt instead of saving it in file, it's ur choice
                    

                    # Create another connection to communicate with the client directly and send the packet here to the client
                    pass
                elif packet_type == crypto_utils.Packet_Type.RESPONSE.value:
                    pass
                
                else:
                    continue
                '''
                I dont know if any thing pass here or resources will be guaranteed to be cleaned up this is because im using daemon for internal threads
                #####HERE WE SEND THE PACKET FINALLY IN THIS AREA, WE USE ANOTHER WHILE LOOP WITH A RETRY COUNTER for send no need to time out since non blocking, and if that fials just kill the connection
                
                # ESSENTIALLY REQUEST AND RESPONSE ONLY HAS THE RELAY SEND ONCE, BUT EXCHANGE_DH HAS THE RELAY SEND TWICE, ONCE TO THE CLIENT FOR THE SALT, AND TO FORWARD THE PACKET TO THE NEXT RELAY
                '''
        except Exception as e:
            print(f"Incoming error: {e}")

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
        server_sock.settimeout(RELAY_TIMEOUT)

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
            except socket.timeout:
                pass
            except Exception as e:
                print("Error: ", e)
                continue


    def start(self):
        try:
            self.thread = threading.Thread(target=self.start_relay, args=(self.relay_socket, self.host, self.port))
            self.thread.start()

            #TODO: possibly want a nother thread so we can interactable relay
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
        proxy.thread.join()
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
    HOST = "127.0.0.1"

    proxy = Proxy(HOST)
    proxy.register()
    setup_signal_handlers(proxy)
    proxy.start()
    proxy.thread.join()
    
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