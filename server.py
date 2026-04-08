import uuid
import signal
import sys
import os
import socket
import threading
import crypto_utils
from threading import Lock
import pickle
import packet as PacketFormat
import json

# For demo purposes leave it like this for now other wise it will take forever to clean up
HOST = "127.0.0.1"
SERVER_TIMEOUT = None  # SET TO NONE FOR BLOCKING MODE, ONLY USE WHEN DAEMON IS TRUE
DAEMON_FLAG = True


class Server:
    def __init__(self, host, Random_Port=True, port=None):
        self.host = host
        self.running = True
        self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if Random_Port:
            self.relay_socket.bind((host, 0))
        else:
            self.relay_socket.bind((host, port))

        self.host, self.port = self.relay_socket.getsockname()
        self.server_id = str(uuid.uuid4())
        self.receive_sockets = {}

    def server_logic(self, client_sock, socket_name):
        retry_counter_data = 0
        NUM_ATTEMPTS_DATA = 10
        NUM_ATTEMPTS_TIME_OUT = 2
        retry_counter_timeout = 0
        try:
            client_sock.settimeout(SERVER_TIMEOUT)
            while self.running:
                outer_packet = None
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

                retry_counter_timeout = 0

                if not data:
                    if retry_counter_data > NUM_ATTEMPTS_DATA:
                        raise Exception("Failed to receive Data from client or relay")
                    else:
                        retry_counter_data += 1
                        continue

                if isinstance(data, bytes):
                    outer_packet = PacketFormat.to_obj_rep(data)
                else:
                    continue
                data = PacketFormat.to_obj_rep(outer_packet.payload)

                message = data.payload
                print(
                    f"Got a packet, sending message back to client, data is: {message} from client id: {outer_packet.client_id}"
                )

                try:
                    message = json.loads(message.decode())
                    print(message)
                    host = message["server"]
                    port = int(message["port"])

                    request = (
                        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    )
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    sock.connect((host, port))
                    print(
                        f"Created socket with the following ip address and port: {sock.getsockname()}"
                    )
                    sock.sendall(request.encode())

                    response = b""
                    while True:
                        chunk = sock.recv(256)
                        if not chunk:
                            raise Exception("Non valid Data")
                        response += chunk
                        break
                    sock.close()
                    message = response.decode(errors="ignore")
                except Exception as error:
                    message = "This is from server"

                packet = PacketFormat.Packet(payload=message)
                outer_packet.payload = PacketFormat.to_bytes_rep(packet)
                outer_packet.client_id = self.server_id
                client_sock.sendall(PacketFormat.to_bytes_rep(outer_packet))

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
                    args=(
                        client_sock,
                        socket_name,
                    ),
                    daemon=True,
                )

                t.start()
            except socket.timeout:
                pass
            except Exception as e:
                print("Error: ", e)
                continue

    def start(self):
        try:
            self.thread = threading.Thread(
                target=self.start_relay,
                args=(self.relay_socket, self.host, self.port),
                daemon=DAEMON_FLAG,
            )
            self.thread.start()

            while True:
                temp = input()
                if temp == "exit":
                    break

        finally:
            self.running = False


# ---- graceful shutdown handling ----
def setup_signal_handlers(server):
    def shutdown_handler(signum, frame):
        print("\nShutting down server...")
        server.running = False
        if not DAEMON_FLAG:
            server.thread.join()
        server.relay_socket.close()
        recv_socket_list = server.receive_sockets

        for key in recv_socket_list:
            try:
                recv_socket_list[key].close()
            except:
                continue

        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)


# Basic Testing for Manual Testing
def test():
    port = 50004
    server = Server(HOST, False, port)
    # server = Server(HOST)
    setup_signal_handlers(server)
    server.start()

    if not DAEMON_FLAG:
        server.thread.join()
    print("Server has been successfully shut downed")
    # clean up
    recv_socket_list = server.receive_sockets

    for key in recv_socket_list:
        try:
            recv_socket_list[key].close()
        except:
            continue

    server.relay_socket.close()


if __name__ == "__main__":
    test()
