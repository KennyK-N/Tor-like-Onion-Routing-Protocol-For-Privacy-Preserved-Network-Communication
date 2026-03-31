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
"""
Only do DH exchange if key None 
"""
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
                        "symmetric_key": None # This will be filled after key exchange
                    }
                    
        i += 1

    return proxies


def choose_circuit(proxies, k=3):
    proxy_ids = list(proxies.keys())

    if len(proxy_ids) < MIN_PROXY:
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
        is_first_packet = True
        key_exchange_done = False
        while True:
            #TODO: maybe add time out a
            data = proxy_sock.recv(4096)

            if not data:
                break
                
            # TODO: If this is not the first packet, need to decrypt before converting to an object
            if not is_first_packet:
                # TODO: Decrypt here
                pass

            if isinstance(data, bytes):
                packet = PacketFormat.to_obj_rep(data)
                print(f"{isinstance(packet, PacketFormat.Packet)}")
            else:
                continue 

            if not key_exchange_done:
                is_first_packet = False
                i = 0
                while isinstance(packet.payload, bytes):
                    packet = packet.payload
                    # TODO: decrypt here
                    decrypted_payload = packet # replace this with the decrypted payload after decryption

                    if isinstance(decrypted_payload, bytes):
                        packet = PacketFormat.to_obj_rep(decrypted_payload)
                    i += 1

                # Get public key and salt from the packet payload
                public_key = crypto_utils.load_public_key(packet.payload["public_key"])
                salt = packet.payload["salt"]
                # Get symmetric key using the client's private key and the relay's public key
                with exchange_cond:
                    symm_key = crypto_utils.derive_shared_key(dh_key_info[0]["private_key"], public_key, salt)
                    dh_key_info[i]["symm_key"] = symm_key
                    exchange_cond.notify()
                print(f"Derived symmetric key for relay {i+1}")

            else:
                for i in range(len(circuit)):
                    # Decrypt the packet layer by layer using the corresponding symmetric key starting from the outermost layer
                    payload = packet.payload
                    # TODO: decrypt here using the corresponding symmetric key for relay i
                    decrypted_payload = payload # replace this with the decrypted payload after decryption

                    if i == len(circuit) - 1: # If this is the last layer, print the response
                        print(f"Received response from server: {decrypted_payload}")
                    else: # Get next packet layer
                        packet = PacketFormat.to_obj_rep(decrypted_payload)
                    
                while isinstance(packet.payload, PacketFormat.Packet):
                    packet = packet.payload
                    # TODO: decrypt here
                    if isinstance(packet.payload, bytes):
                        packet = pickle.loads(packet.payload)
                    i += 1
                print(f"Received response from server: {packet.payload}")

            #TODO:
            """
            IF packet_type == crypto_utils.Packet_Type.EXCHANGE_DH.value:
                
                if CLIENT_DH_KEY == NONE: CREATE A DICTIONARY

                ITTERATE OVER THE PAYLOAD UNTIL, THERE IS NO MORE PACKET (USE IF isinstance) 
                AND YOU GET THE SALT
                AND THE RELAY PUBLIC KEY

                PEFORM DH KEY EXCHANGE

                STORE THE KEY WITH THE CORRESPONDING RELAY

                WAKE UP THE SENDER PROB DONT NEED MUTEX IF WE USE SYNCHRONIZATON AND MUTAL EXCLUSION 

                AND EXIT THIS BRANCH

            ELIF packet_type == crypto_utils.Packet_Type.RESPONSE.value:

                DECRYPT PAYLOAD STARTING WITH THE ENTRY RELAY KEY TO OUTER RELAY KEY, VERIFY THIS
                THEN PRINT IT
            """



            print(f"Received {len(data)} bytes from proxy: {data[:50]}...")
            """ ------------TEST CODE------------"""
            print(PacketFormat.to_obj_rep(data)) 
    except Exception as e:
        _, _, tb = sys.exc_info()

        print(f"Listener thread error: {e} at line {tb.tb_lineno}")
    finally:
        proxy_sock.close()
        print("Connection closed.")


# Takes input and puts it in a layered packet to send through the circuit
def send_input_to_proxy(proxy_sock, circuit, proxies):
    try:
        while True:
            serveraddr = input("Enter Server Ip")
            port = input("Enter Server Port")

            # TODO:
            # perform key exchange
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
                        exchange_cond.wait_for(lambda: dh_key_info[i]["symm_key"] is not None)
                        print(f"Symmetric key for relay {i+1} established.")
                        # TODO
                        # cond.wait() # wait for a key exchange response
                        # When response is received, cond.notify() is called in the listener thread to wake this up for it to send the next packet
                    
                """
                custom_lst
                for i in range(len(circuit)):
                    send the EXCHANGE packet to each hop invidually and wait for a response, 
                    e.g  
                    Itt1: Req: client -> hop1, send-thread goes into wait/sleep, Res :client <- hop1, receive threads recieves packet wakes up send thread
                    Itt2: Req: client -> hop1 -> hop2, send-thread goes into wait/sleep, Res :client <- hop1 <- hop2, receive threads recieves packet wakes up send thread
                    Itt3: Req: client -> hop1 -> hop2 -> hop3, send-thread goes into wait/sleep, Res :client <- hop1 <- hop2 <- hop3, receive threads recieves packet wakes up send thread 
                    Itt4, etc. repeat similarly to above process
                    use cond.wait() Thread goes into waiting mode till it receives a response, times out after certain time limit
                    
                    pseudo code for constructing the packet
                    custom_lst.append(circuit[i])
                    for i in range(len(custom_lst) - 1, -1, -1):
                        construct the packet starting from inner to outer, NOTE: no idea if this is correct so verify this :)
                    
                    Then send and wait, i.e do the thing above
                """

            #TODO
            #NOTE: LOGIC MAY NOT 100 PERCENT BE CORRECT MAKE SURE TO VERIFY
            """
            FIRST CREATE A PACKET THAT CONTAINS THE SERVER AND THE ORIGINAL MESSAGE
            
            THEN IN THIS LOOP:
            for i in range(len(circuit) - 1, -1, -1):
                CREATE A NEW PACKET, STORE THE ORIGINAL PAYLOAD IN THE NEW PACKET, ENCRYPT THE PAYLOAD WITH THE CORRESPONDING KEY

            AFTER YOU HAVE THE PACKET CONSTRUCT THE ONION PACKET SEND IT OVER
            """ 
            # proxy_sock.sendall(pickle.dumps(test))
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
    for i in range(dst_num - 1, -1, -1):
        if i == len(circuit): # If sending to server, innermost packet has server address and port
            packet = PacketFormat.Packet(
                                        payload = cur_payload,
                                        dst_addr= server_addr, 
                                        dst_port= server_port,
                                        )
        else: # Otherwise, dst is the next relay in the circuit
            cur_proxy = proxies[circuit[i]]
            packet = PacketFormat.Packet(
                                        payload = cur_payload,
                                        dst_addr= cur_proxy["host"], 
                                        dst_port= cur_proxy["port"] 
                                        )
        # TODO: Encrypt the packet with the corresponding symmetric key if its not the innermost packet (i.e. the server packet)


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