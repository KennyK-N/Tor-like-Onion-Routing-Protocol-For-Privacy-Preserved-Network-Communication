import random
import os
import socket
import threading

import crypto_utils
import packet as PacketFormat
from cryptography.hazmat.primitives import serialization
import queue
import pickle 
ACTIVE_PROXIES_DIR = "active_proxies"
CLIENT_DH_KEY = None # This is dictionary, {relay id: Se key}
MIN_PROXY = 3
"""
Only do DH exchange if key None 
"""
def discover_proxies():
    proxies = {}

    # Ensure the folder exists
    if not os.path.exists(ACTIVE_PROXIES_DIR):
        return proxies

    # Iterate over each proxy file in the folder
    for file in os.listdir(ACTIVE_PROXIES_DIR):
        if file.endswith(".txt"):
            file_path = os.path.join(ACTIVE_PROXIES_DIR, file)
            with open(file_path, "r") as f:
                line = f.readline().strip()
                # Each line format: proxy_id,host,port
                parts = line.split(",")
                if len(parts) >= 4:
                    proxy_id, host, port, public_key = parts[0], parts[1], int(parts[2]), parts[3]
                    proxies[proxy_id] = {
                        "host": host,
                        "port": port,
                        "public_key": public_key
                    }

    return proxies


def choose_circuit(proxies, k=3):
    proxy_ids = list(proxies.keys())

    if len(proxy_ids) < MIN_PROXY:
        raise ValueError("Not enough proxies available")

    return random.sample(proxy_ids, k)


def listen_to_proxy(proxy_sock):
    """Thread function: listen for incoming packets from the proxy"""
    try:
        while True:
            #TODO: MAYBE ADD TIME OUT JUST STEAL FROM PROXY CODE, IDK IM TOO TIRED IM TYPING THIS RN
            data = proxy_sock.recv(4096)

            if not data:
                break

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
            print(pickle.loads(data)) 
    except Exception as e:
        print(f"Listener thread error: {e}")
    finally:
        proxy_sock.close()
        print("Connection closed.")

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
    listener_thread = threading.Thread(target=listen_to_proxy, args=(proxy_sock,), daemon=True)
    listener_thread.start()

    return proxy_sock

# Takes input and puts it in a layered packet to send through the circuit
def send_input_to_proxy(proxy_sock, circuit, proxies):
    try:
        custom_circuit = None
        while True:
            serveraddr = input("Enter Server Ip")
            port = input("Enter Server Port")

            #TODO
            #NOTE: LOGIC MAY NOT 100 PERCENT BE CORRECT MAKE SURE TO VERIFY
            # PERFORM KEY EXCHANGE HERE Iteratively
            if CLIENT_DH_KEY == None:
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

            # Send a test message to first proxy (Delete later)
            """ ------------TEST CODE IN HERE------------"""
            msg = input("Enter message: ")
            if msg.lower() in ("exit", "quit"):
                break

            # TODO: put msg in layered packet encrypted with symmetric keys before sending
            test = []
            #NOTE: ALways make sure that the server is the innerpacket in layered/nested packet, and make sure the first entry is the outerpacket
            test.append({"host": serveraddr, "port": int(port), "id": "server"})
            
            for i in range(len(circuit) - 1, -1, -1):
                test.append({"host": proxies[circuit[i]]["host"], "port": proxies[circuit[i]]["port"], "id": circuit[i]})
            
            # count becomes len if theres a server
            test.append({"type":"decrement", "count": len(circuit), "data": "works", "source": proxy_sock.getsockname()})
            
            #Count becomes len-1 if no server and only hops
            #test.append({"type":"decrement", "count": len(circuit)-1, "data": "works", "source": proxy_sock.getsockname()})
            """--------TEST CODE IN HERE ------------"""

            #TODO
            #NOTE: LOGIC MAY NOT 100 PERCENT BE CORRECT MAKE SURE TO VERIFY
            """
            FIRST CREATE A PACKET THAT CONTAINS THE SERVER AND THE ORIGINAL MESSAGE
            
            THEN IN THIS LOOP:
            for i in range(len(circuit) - 1, -1, -1):
                CREATE A NEW PACKET, STORE THE ORIGINAL PAYLOAD IN THE NEW PACKET, ENCRYPT THE PAYLOAD WITH THE CORRESPONDING KEY

            AFTER YOU HAVE THE PACKET CONSTRUCT THE ONION PACKET SEND IT OVER
            """ 
            proxy_sock.sendall(pickle.dumps(test))
    except Exception as e:
        print(f"Input thread error: {e}")
    finally:
        proxy_sock.close()
        print("Input thread shutting down.")

#NOTE: HAVENT TESTED IT YET so idk if this works properly, should work tho cuz that for loop works
def create_exchange_packet(proxies, client_addr, client_port, circuit):
    packet = PacketFormat.Onion_Packet(None,
                                       None,
                                       len(proxies),
                                       crypto_utils.Packet_Type.EXCHANGE_DH.value)
    
    for i in range(len(circuit) - 1, -1, -1):
        proxy = proxies[circuit[i]]
        inner = PacketFormat.Request_Packet(src_addr= client_addr, 
                                            src_port= client_port, 
                                            dest_addr= proxy["host"], 
                                            dst_port= proxy["port"], 
                                            payload = None,
                                            relay_type= crypto_utils.RelayFlag.RELAY.value)
        if i == 0:
            packet.Request_Packet = PacketFormat.to_bytes_rep(inner)
        else:
            inner.payload = packet.Request_Packet
            packet.Request_Packet = PacketFormat.to_bytes_rep(inner)
    
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