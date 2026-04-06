import random
import os
import socket
import threading
import sys
import crypto_utils
import packet as PacketFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
import pickle 
import uuid
import datetime
import signal

ACTIVE_PROXIES_DIR = "active_proxies"
MIN_PROXY = 3
NUM_HOP = 3 
MAX_NUM_NON_EXCHANGE_MESSAGE_RECV_PER_SESSION = 1 # NONE = INFINITY

class Client:
    def __init__(self):
        self.CLIENT_ID = str(uuid.uuid4())
        self.dh_key_info = [] # This is an array of dictionaries, {relay #: {}}
        self.exchange_cond = threading.Condition() # condition to synchronize key exchange process
        self.proxy_sock = None
        self.running = True
        self.num_non_exchange_message_recv = 0
        self.key_exchange_time = 0
        self.key_exchange_begin = 0
        self.bytes_received = 0
        self.bytes_send = 0
        self.session_end = 0
        self.session_start = 0

    def discover_proxies(self):
        proxies = {}

        # Ensure the folder exists
        if not os.path.exists(ACTIVE_PROXIES_DIR):
            return proxies

        # Iterate over each proxy file in the folder
        i = 0
        for file in os.listdir(ACTIVE_PROXIES_DIR):
            if file.endswith(".txt"):
                file_path = os.path.join(ACTIVE_PROXIES_DIR, file)
                with open(file_path, "r") as f:
                    line = f.readline().strip()
                    # Each line format: proxy_id,host,port
                    parts = line.split(",")
                    if len(parts) >= 4:
                        proxy_id, host, port = parts[0], parts[1], int(parts[2])
                        verification_key = parts[3].replace("\\n", "\n").encode()
                        proxies[proxy_id] = {
                            "host": host,
                            "port": port,
                            "verification_key": crypto_utils.load_public_key(verification_key)
                        }
                        
            i += 1

        return proxies


    def choose_circuit(self, proxies, k=3):
        proxy_ids = list(proxies.keys())

        if len(proxy_ids) < MIN_PROXY or k > len(proxies):
            raise ValueError("Not enough proxies available")

        return random.sample(proxy_ids, k)

    # Connects to the first proxy in the circuit and starts a listener thread
    def connect_to_circuit(self, proxies, circuit):
        first_proxy_id = circuit[0]
        proxy_info = proxies[first_proxy_id]
        host = proxy_info["host"]
        port = proxy_info["port"]

        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_start = datetime.datetime.now()
        proxy_sock.connect((host, port))
        print(f"Client IP addr and port: {proxy_sock.getsockname()}")
        print(f"Connected to first proxy {first_proxy_id} at {host}:{port}")

        self.proxy_sock = proxy_sock

        # Start listener thread
        listener_thread = threading.Thread(target=self.listen_to_proxy, args=(circuit,proxies,), daemon=True)
        self.listen_thread = listener_thread
        listener_thread.start()


    def listen_to_proxy(self, circuit, proxies):
        """Thread function: listen for incoming packets from the proxy"""
        try:
            key_exchange_num = 0
            while self.running:
                if(self.num_non_exchange_message_recv == MAX_NUM_NON_EXCHANGE_MESSAGE_RECV_PER_SESSION):
                    break

                rtt_end = None
                #TODO: maybe add time out a
                data = self.proxy_sock.recv(4096)
                rtt_end = datetime.datetime.now()
                if not data:    
                    break
                    

                if isinstance(data, bytes):
                    outer_packet = PacketFormat.to_obj_rep(data)
                else:
                    continue 
                
                if rtt_end == None:
                    continue

                self.bytes_received += len(data)
                packet = PacketFormat.to_obj_rep(outer_packet.payload)

                if key_exchange_num < len(circuit): # If this is a key exchange packet, perform key exchange and store the symmetric key
                    relay_num = 0
                    for i in range(key_exchange_num):
                        iv = packet.iv
                        packet = packet.payload 
                        cipher = crypto_utils.create_cipher(self.dh_key_info[i]["symm_key"], iv)
                        decrypted_payload = crypto_utils.aes_decrypt(cipher, packet)
                        if isinstance(decrypted_payload, bytes):
                            packet = PacketFormat.to_obj_rep(decrypted_payload)
                        relay_num = i+1

                    # Get public key and salt from the packet payload
                    public_key = crypto_utils.load_public_key(packet.payload["public_key"])
                    salt = packet.payload["salt"]
                    verification_key = proxies[circuit[relay_num]]["verification_key"]
                    # Verify that signatures on the public key and salt are valid
                    if not crypto_utils.verify_signature(verification_key, packet.payload["public_key"], packet.payload["key_signature"]):
                        raise Exception("Invalid signature on public key from relay {relay_num+1}")
                    if not crypto_utils.verify_signature(verification_key, packet.payload["salt"], packet.payload["salt_signature"]):
                        raise Exception("Invalid signature on salt from relay {relay_num+1}")
                    
                    # Get symmetric key using the client's private key and the relay's public key
                    with self.exchange_cond:
                        symm_key = crypto_utils.derive_shared_key(self.dh_key_info[relay_num]["private_key"], public_key, salt)
                        self.dh_key_info[relay_num]["symm_key"] = symm_key
                        self.exchange_cond.notify()
                    print(f"Derived symmetric key for relay {relay_num+1}")
                    print(f"Got message {packet.payload['test_message']}") # TODO: remove this after testing
                    key_exchange_num += 1
                    
                else: # If this is a response packet, decrypt the packet layer by layer and print the response
                    for i in range(len(circuit)):
                        if(outer_packet.exchange==False):
                            h = hmac.HMAC(self.dh_key_info[i]["symm_key"], hashes.SHA256())
                            message = packet.payload
                            h.update(message)
                            h.verify(packet.HMAC)
                            # print("HMAC SUCCESSFULLY VERIFIED, RESPONSE")#TODO REMOVE POSSIBLY

                        cipher = crypto_utils.create_cipher(self.dh_key_info[i]["symm_key"], packet.iv)
                        decrypted_payload = crypto_utils.aes_decrypt(cipher, packet.payload)

                        if i == len(circuit) - 1: # If this is the last layer, print the response
                            packet = PacketFormat.to_obj_rep(decrypted_payload)
                            rtt = (rtt_end - outer_packet.rtt).total_seconds() * 1000
                            print(f"\nRTT is: {rtt:.2f} ms")
                            # print(f"Num Hop in the circuit is: {outer_packet.hop}") # TODO: DELETE AFTER I GUESS
                            print(f"Server ID is: {outer_packet.client_id}")
                            print(f"Received response from server: {packet.payload}")
                        else: # Get next packet layer
                            #TODO HMAC HERE FOR NON EXCHANGE PACKET
                            packet = PacketFormat.to_obj_rep(decrypted_payload)
                    self.num_non_exchange_message_recv+=1

            
        except Exception as e:
            _, _, tb = sys.exc_info()

            print(f"Listener thread error: {e} at line {tb.tb_lineno}")
        finally:
            self.proxy_sock.close()
            self.running = False
            self.session_end = datetime.datetime.now()
            print("Connection closed.")

    def key_exchange(self, circuit, proxies):
        key_exchange_time_begin = datetime.datetime.now()
        with self.exchange_cond: 
            try:
                if len(self.dh_key_info) == 0:
                    for i in range(len(circuit)):
                        private_key, public_key = crypto_utils.generate_ecdh_keypair()
                        self.dh_key_info.append({"private_key": private_key, "public_key": public_key, "symm_key": None}) # symm_key will be filled after key exchange response is received

                        # Send a exchange packet to relay i with the public key
                        inner_packet = self.create_packet(
                                proxies,
                                circuit,
                                payload=crypto_utils.serialize_public_key(public_key),
                                dst_num=i+1, EXCHANGE=True
                            )
                        outer_packet = PacketFormat.Onion_Packet(payload = inner_packet, 
                                                    rtt = datetime.datetime.now(),
                                                    hop = i+1, client_id=self.CLIENT_ID, exchange=True)
                        packet = PacketFormat.to_bytes_rep(outer_packet)
                        self.proxy_sock.sendall(
                            packet
                        )
                        self.bytes_send += len(packet)
                        # Wait for response before sending next key exchange packet
                        self.exchange_cond.wait_for(lambda: self.dh_key_info[i]["symm_key"] is not None)
                        print(f"Symmetric key for relay {i+1} established.")
            except:
                self.proxy_sock.close()

        key_exchange_time_end = datetime.datetime.now()
        self.key_exchange_time = (key_exchange_time_end - key_exchange_time_begin).total_seconds() * 1000
        self.key_exchange_begin = key_exchange_time_begin

    # Takes input and puts it in a layered packet to send through the circuit
    def send_input_to_proxy(self, circuit, proxies, message, serveraddr, port):
        try:
            if len(self.dh_key_info) == len(circuit): 
                inner_packet = self.create_packet(
                        proxies, 
                        circuit, 
                        payload=message.encode(), 
                        server_addr=serveraddr, 
                        server_port=int(port)
                    )
                outer_packet = PacketFormat.Onion_Packet(payload = inner_packet, 
                            rtt = datetime.datetime.now(),
                            hop = len(circuit),
                            client_id=self.CLIENT_ID)
                # Send a packet containing the message
                packet = PacketFormat.to_bytes_rep(outer_packet)
                self.proxy_sock.sendall(
                    packet
                )
                self.bytes_send += len(packet)
            return True
        
        except KeyboardInterrupt:
            pass      
            return False
        
        except Exception as e:
            _, _, tb = sys.exc_info()

            print(f"Input thread error: {e} at line {tb.tb_lineno}")
            return False

    def create_packet(self, proxies, circuit, payload, server_addr = None, server_port = None,  dst_num = None, EXCHANGE=False):
        #dst_num is the number of hops, using it allows us to send messages to relays for key exchanges
        # If dst_num is None, message is sent to the server
        if dst_num == None:
            dst_num = len(circuit) + 1
        
        # innermost packet has actual payload, others have the inner packet as payload
        cur_payload = payload
        cur_iv = None # innermost layer has an unencrypted payload, so no IV needed
        for i in range(dst_num - 1, -1, -1):
            if i == len(circuit): # If sending to server, innermost packet has server address and port
                packet = PacketFormat.Packet(
                                            payload = cur_payload,
                                            dst_addr= server_addr, 
                                            dst_port= server_port,
                                            iv = cur_iv,
                                            HMAC=None)
            else: # Otherwise, dst is the next relay in the circuit
                digest=None
                
                if not EXCHANGE:
                    message = cur_payload
                    h = hmac.HMAC(self.dh_key_info[i]["symm_key"], hashes.SHA256())
                    h.update(message)
                    digest = h.finalize()

                cur_proxy = proxies[circuit[i]]
                packet = PacketFormat.Packet(
                                            payload = cur_payload,
                                            dst_addr= cur_proxy["host"], 
                                            dst_port= cur_proxy["port"], 
                                            iv = cur_iv,
                                            HMAC=digest)
            
            # Update IV for next iteration
            cur_iv = os.urandom(16) 
            # TODO: encrypt all non-outermost packets with the corresponding symmetric key
            if i != 0: # If this is not the outermost packet, encrypt with the corresponding symmetric key for relay i
                cipher = crypto_utils.create_cipher(self.dh_key_info[i-1]["symm_key"], cur_iv) 
                cur_payload = crypto_utils.aes_encrypt(cipher, PacketFormat.to_bytes_rep(packet))
            else:
                # Update cur_payload for next packet
                cur_payload = PacketFormat.to_bytes_rep(packet) 

        return PacketFormat.to_bytes_rep(packet)
    
# ---- graceful shutdown handling ----
def setup_signal_handlers(client):
    def shutdown_handler(signum, frame):
        print("\nShutting down client...")
        client.running = False
        client.proxy_sock.close()
        print_stat(client)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

def print_stat(client):
    end_session = client.session_end if client.session_end else datetime.datetime.now()
    session_duration_s = (end_session - client.session_start).total_seconds()     
    session_duration_ms = session_duration_s * 1000
    recv_throughput = (client.bytes_received * 8) / session_duration_s         
    send_throughput = (client.bytes_send * 8) / session_duration_s
    
    print(f"Key Exchange Duration: {client.key_exchange_time:.2f} ms")
    print(f"Session Duration: {(session_duration_ms):.2f} ms")
    print(f"Total Bytes Received: {client.bytes_received} bytes")        
    print(f"Total Bytes Sent: {client.bytes_send} bytes")
    
    if session_duration_ms > 0:
        print(f"Recv Throughput: {recv_throughput / 1000:.2f} kbps")
        print(f"Send Throughput: {send_throughput / 1000:.2f} kbps")

def main():
    client = Client()
    proxies = client.discover_proxies()

    print("Available proxies:", list(proxies.keys()))
    circuit = client.choose_circuit(proxies, NUM_HOP)
    print("Chosen circuit:", circuit)
    print(f"Current Client_uid: {client.CLIENT_ID}")
    # print(proxies)

    # Connect to first proxy and start listener
    #UNCOMMENT THIS FOR TESTING PURPOSE
    client.connect_to_circuit(proxies, circuit)
    setup_signal_handlers(client)
    client.key_exchange(circuit, proxies)

    # serveraddr = input("Enter Server IP: ")
    serveraddr = "127.0.0.1"
    port = input("Enter Server Port #: ")

    # status = True
    # try:
    #     while (client.running and status):
    #         message = input("Enter message to send to server (or 'exit' to quit): ")
    #         if message.lower() == "exit":
    #             break
    #         status = client.send_input_to_proxy(circuit, proxies, message, serveraddr, port)
    # except:
    #     pass
    # finally:
    #     client.running=False
    #     client.proxy_sock.close()
    
    status = client.send_input_to_proxy(circuit, proxies, '{"server": "www.google.com", "port": "80"}', serveraddr, port)
    # status = client.send_input_to_proxy(circuit, proxies, '{"server": "example.com", "port": "80"}', serveraddr, port)

    while(client.running):
        pass
    print_stat(client)
if __name__ == "__main__":
    main()
