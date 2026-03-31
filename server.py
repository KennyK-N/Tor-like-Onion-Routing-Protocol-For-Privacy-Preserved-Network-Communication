import queue
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
# Need two-way communication between the server and the client, cuz server is like website server, it's gotta send the website back to the client
# We don't actually have to do the request stuff, we just gotta let the server have the ability to send stuff back
HOST = "127.0.0.1"
RECEIVE_TIMEOUT = 5
SERVER_TIMEOUT = 5

class Server:
    def __init__(self, host):
        self.host = host
        self.running = True
        self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.relay_socket.bind((host, 0))
        self.host, self.port = self.relay_socket.getsockname()
        self.server_id = str(uuid.uuid4())
        self.receive_sockets={}


    def server_logic(self, client_sock, socket_name):
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
                        break
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

                if isinstance(data, bytes):
                    data = pickle.loads(data)
                else:
                    continue

                #TODO Server logic HERE, 
                # pretend to process the receive message, create a new onion packet with self.packet_type = RESPONSE, 
                # with with some response message and then just send packt o client
                
                message = data[-1]
                message["data"] = "RECEV WORKING"
                print(data)

                client_sock.sendall(PacketFormat.to_bytes_rep(data))

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
        print(f"Server {self.server_id} listening on {host}:{port}")
        server_sock.listen()
        server_sock.settimeout(SERVER_TIMEOUT)

        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                print(f"Accepted connection from {addr}")
                socket_name = client_sock.getpeername()
                self.receive_sockets[socket_name] = client_sock

                t = threading.Thread(
                    target=self.server_logic,
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

            #TODO: Make interactable like list options, e.g 1. do something, 2. do something, 3.exit
            while(True):
                temp = input("For menu or smthing: ")
                if (temp == "exit"): # THIS EXIT IS GOOD
                    break

        finally:
            print("\nShutting down server...")
            self.running = False

# ---- graceful shutdown handling ----
def setup_signal_handlers(server):
    def shutdown_handler(signum, frame):
        print("\nShutting down server...")
        server.running=False
        server.thread.join()
        server.relay_socket.close()
        recv_socket_list = server.receive_sockets

        for key in recv_socket_list:
            recv_socket_list[key].close()

        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

def main():
    server = Server(HOST)
    setup_signal_handlers(server)
    server.start()
    server.thread.join()
    
    # clean up
    recv_socket_list = server.receive_sockets

    for key in recv_socket_list:
        recv_socket_list[key].close()

    server.relay_socket.close()
# ---- MAIN ----
if __name__ == "__main__":
    main()