import random
import os
import socket
import threading
import sys
import crypto_utils
import packet as PacketFormat
from cryptography.hazmat.primitives import serialization
import pickle 

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
                if len(parts) >= 3:
                    proxy_id, host, port = parts[0], parts[1], int(parts[2])
                    proxies[proxy_id] = {
                        "host": host,
                        "port": port,
                        # "verification_key": verification_key, Can be used for verification later if wanted
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
    listener_thread = threading.Thread(target=listen_to_proxy, args=(proxy_sock,circuit,), daemon=True)
    listener_thread.start()

    return proxy_sock

def listen_to_proxy(proxy_sock, circuit):
    """Thread function: listen for incoming packets from the proxy"""
    try:
        key_exchange_num = 0
        while True:
            #TODO: maybe add time out a
            data = proxy_sock.recv(4096)

            if not data:
                break
                

            if isinstance(data, bytes):
                packet = PacketFormat.to_obj_rep(data)
            else:
                continue 

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
                    # TODO: decrypt here using the corresponding symmetric key for relay i
                    cipher = crypto_utils.create_cipher(dh_key_info[i]["symm_key"], packet.iv)
                    decrypted_payload = crypto_utils.aes_decrypt(cipher, packet.payload)

                    if i == len(circuit) - 1: # If this is the last layer, print the response
                        packet = PacketFormat.to_obj_rep(decrypted_payload)
                        print(f"Received response from server: {packet.payload}")
                    else: # Get next packet layer
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
                    proxy_sock.sendall(
                        create_packet(
                            proxies,
                            circuit,
                            payload=crypto_utils.serialize_public_key(public_key),
                            dst_num=i+1
                        )
                    )
                    # Wait for response before sending next key exchange packet
                    exchange_cond.wait_for(lambda: dh_key_info[i]["symm_key"] is not None)
                    print(f"Symmetric key for relay {i+1} established.")

            while True:
                message = input("Enter message to send to server (or 'exit' to quit): ")
                if message.lower() == "exit":
                    break

                # Send a packet containing the message
                proxy_sock.sendall(
                    create_packet(
                        proxies, 
                        circuit, 
                        payload=message.encode(), 
                        server_addr=serveraddr, 
                        server_port=int(port)
                    )
                )
    except KeyboardInterrupt:
        pass      

    except Exception as e:
        _, _, tb = sys.exc_info()

        print(f"Input thread error: {e} at line {tb.tb_lineno}")
    finally:
        proxy_sock.close()
        print("Input thread shutting down.")

def create_packet(proxies, circuit, payload, server_addr = None, server_port = None,  dst_num = None):
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
                                        iv = cur_iv
                                        )
        else: # Otherwise, dst is the next relay in the circuit
            cur_proxy = proxies[circuit[i]]
            packet = PacketFormat.Packet(
                                        payload = cur_payload,
                                        dst_addr= cur_proxy["host"], 
                                        dst_port= cur_proxy["port"], 
                                        iv = cur_iv
                                        )
        
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

    # print(proxies)

    # Connect to first proxy and start listener
    #UNCOMMENT THIS FOR TESTING PURPOSE
    proxy_sock = connect_to_circuit(proxies, circuit)

    send_input_to_proxy(proxy_sock, circuit, proxies)



if __name__ == "__main__":
    main()

#TODO IMPLEMENT GRACEFUL EXIT FOR CLIENT, RTT USING DATE TIME, HOPS AND ID IN OUTERMOST PACKET,
# HMAC, AND MAKE IT MORE THREAD SAFE????, ALSO FOR PROXIES STORE KEY IN DICTIONARY NOT LOCAL