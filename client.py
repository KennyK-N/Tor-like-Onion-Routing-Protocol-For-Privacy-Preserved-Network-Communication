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

CLIENT_ID = str(uuid.uuid4())
ACTIVE_PROXIES_DIR = "active_proxies"
MIN_PROXY = 3
dh_key_info = [] # This is an array of dictionaries, {relay #: {}}
exchange_cond = threading.Condition() # condition to synchronize key exchange process

def discover_proxies():
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


def choose_circuit(proxies, k=3):
    proxy_ids = list(proxies.keys())

    if len(proxy_ids) < MIN_PROXY or k > len(proxies):
        raise ValueError("Not enough proxies available")

    return random.sample(proxy_ids, k)

# Connects to the first proxy in the circuit and starts a listener thread
def connect_to_circuit(proxies, circuit):
    first_proxy_id = circuit[0]
    proxy_info = proxies[first_proxy_id]
    host = proxy_info["host"]
    port = proxy_info["port"]

    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.connect((host, port))
    print(f"Connected to first proxy {first_proxy_id} at {host}:{port}")

    # Start listener thread
    listener_thread = threading.Thread(target=listen_to_proxy, args=(proxy_sock,circuit,proxies,), daemon=True)
    listener_thread.start()

    return proxy_sock

def listen_to_proxy(proxy_sock, circuit, proxies):
    """Thread function: listen for incoming packets from the proxy"""
    try:
        key_exchange_num = 0
        while True:
            rtt_end = None
            #TODO: maybe add time out a
            data = proxy_sock.recv(4096)
            rtt_end = datetime.datetime.now()
            if not data:    
                break
                

            if isinstance(data, bytes):
                outer_packet = PacketFormat.to_obj_rep(data)
            else:
                continue 
            
            if rtt_end == None:
                continue

            packet = PacketFormat.to_obj_rep(outer_packet.payload)

            if key_exchange_num < len(circuit): # If this is a key exchange packet, perform key exchange and store the symmetric key
                relay_num = 0
                for i in range(key_exchange_num):
                    iv = packet.iv
                    packet = packet.payload 
                    cipher = crypto_utils.create_cipher(dh_key_info[i]["symm_key"], iv)
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
                with exchange_cond:
                    symm_key = crypto_utils.derive_shared_key(dh_key_info[relay_num]["private_key"], public_key, salt)
                    dh_key_info[relay_num]["symm_key"] = symm_key
                    exchange_cond.notify()
                print(f"Derived symmetric key for relay {relay_num+1}")
                print(f"Got message {packet.payload['test_message']}") # TODO: remove this after testing
                key_exchange_num += 1
                
            else: # If this is a response packet, decrypt the packet layer by layer and print the response
                for i in range(len(circuit)):
                    if(outer_packet.exchange==False):
                        h = hmac.HMAC(dh_key_info[i]["symm_key"], hashes.SHA256())
                        message = packet.payload
                        h.update(message)
                        h.verify(packet.HMAC)
                        print("HMAC SUCCESSFULLY VERIFIED, RESPONSE")#TODO REMOVE POSSIBLY

                    cipher = crypto_utils.create_cipher(dh_key_info[i]["symm_key"], packet.iv)
                    decrypted_payload = crypto_utils.aes_decrypt(cipher, packet.payload)

                    if i == len(circuit) - 1: # If this is the last layer, print the response
                        packet = PacketFormat.to_obj_rep(decrypted_payload)
                        print(f"\nRTT is: {rtt_end - outer_packet.rtt}")
                        print(f"Num Hop IS: {outer_packet.hop}") # TODO: DELETE AFTER I GUESS
                        print(f"Server ID is: {outer_packet.client_id}")
                        print(f"Received response from server: {packet.payload}")
                    else: # Get next packet layer
                        #TODO HMAC HERE FOR NON EXCHANGE PACKET
                        packet = PacketFormat.to_obj_rep(decrypted_payload)

        
    except Exception as e:
        _, _, tb = sys.exc_info()

        print(f"Listener thread error: {e} at line {tb.tb_lineno}")
    finally:
        proxy_sock.close()
        print("Connection closed.")


# Takes input and puts it in a layered packet to send through the circuit
def send_input_to_proxy(proxy_sock, circuit, proxies):
    try:
        serveraddr = input("Enter Server IP: ")
        port = input("Enter Server Port #: ")

        with exchange_cond: 
            if len(dh_key_info) == 0:
                for i in range(len(circuit)):
                    private_key, public_key = crypto_utils.generate_ecdh_keypair()
                    dh_key_info.append({"private_key": private_key, "public_key": public_key, "symm_key": None}) # symm_key will be filled after key exchange response is received

                    # Send a exchange packet to relay i with the public key
                    inner_packet = create_packet(
                            proxies,
                            circuit,
                            payload=crypto_utils.serialize_public_key(public_key),
                            dst_num=i+1, EXCHANGE=True
                        )
                    outer_packet = PacketFormat.Onion_Packet(payload = inner_packet, 
                                              rtt = datetime.datetime.now(),
                                              hop = i+1, client_id=CLIENT_ID, exchange=True)
                    proxy_sock.sendall(
                        PacketFormat.to_bytes_rep(outer_packet)
                    )
                    # Wait for response before sending next key exchange packet
                    exchange_cond.wait_for(lambda: dh_key_info[i]["symm_key"] is not None)
                    print(f"Symmetric key for relay {i+1} established.")

            while True:
                message = input("Enter message to send to server (or 'exit' to quit): ")
                if message.lower() == "exit":
                    break
                inner_packet = create_packet(
                        proxies, 
                        circuit, 
                        payload=message.encode(), 
                        server_addr=serveraddr, 
                        server_port=int(port)
                    )
                outer_packet = PacketFormat.Onion_Packet(payload = inner_packet, 
                            rtt = datetime.datetime.now(),
                            hop = len(circuit),
                            client_id=CLIENT_ID)
                # Send a packet containing the message
                proxy_sock.sendall(
                    PacketFormat.to_bytes_rep(outer_packet)
                )
    except KeyboardInterrupt:
        pass      

    except Exception as e:
        _, _, tb = sys.exc_info()

        print(f"Input thread error: {e} at line {tb.tb_lineno}")
    finally:
        proxy_sock.close()
        print("Input thread shutting down.")

def create_packet(proxies, circuit, payload, server_addr = None, server_port = None,  dst_num = None, EXCHANGE=False):
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
                h = hmac.HMAC(dh_key_info[i]["symm_key"], hashes.SHA256())
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
            cipher = crypto_utils.create_cipher(dh_key_info[i-1]["symm_key"], cur_iv) 
            cur_payload = crypto_utils.aes_encrypt(cipher, PacketFormat.to_bytes_rep(packet))
        else:
            # Update cur_payload for next packet
            cur_payload = PacketFormat.to_bytes_rep(packet) 

    return PacketFormat.to_bytes_rep(packet)

def main():
    proxies = discover_proxies()

    print("Available proxies:", list(proxies.keys()))
    circuit = choose_circuit(proxies, len(proxies))
    print("Chosen circuit:", circuit)
    print(f"Current Client_uid: {CLIENT_ID}")
    # print(proxies)

    # Connect to first proxy and start listener
    #UNCOMMENT THIS FOR TESTING PURPOSE
    proxy_sock = connect_to_circuit(proxies, circuit)

    send_input_to_proxy(proxy_sock, circuit, proxies)



if __name__ == "__main__":
    main()
