import json
import pickle
from crypto_utils import RelayFlag, Packet_Type, Packet_Type

# class Respond_Packet:
#     def __init__(self, src_addr, src_port, dest_addr, dst_port, payload, relay_type):
#         self.relay_type = relay_type
#         self.src_addr = src_addr
#         self.src_port = src_port
#         '''
#         As the packet moves from the client towards the server during its request process, 
#         we will stamp each previous hop’s address and port into the response packet and encrypt it with the current relay’s symmetric key generated from diffile hellmen. 
#         If the previous hop is the client, we encrypt it with the first hop’s key. 
#         This will continues until the packet reaches the server. Doing so, will allow us to backtrack the connection while keeping the identity or addresses of the other relay
#         hidden from the server, the address is only revealed as we strip layer by layer through traversing the hops starting from the server to the client.
#         '''
#         self.dest_addr = dest_addr # NEED TO BE ENCRYPTED
#         self.dst_port = dst_port # NEED TO BE ENCRYPTED
#         self.payload = payload # THIS IS ENCRYPTED AS IT TRAVELS FROM THE SERVER TO THE CLIENT AND DECRYPTED AT THE CLIENT

class Data_packet:
    def __init__(self, src_addr, src_port, dest_addr, dst_port, payload, relay_type, relay_id):
        self.relay_type = relay_type
        self.src_addr = src_addr
        self.src_port = src_port
        self.dest_addr = dest_addr
        self.dst_port = dst_port
        self.payload = payload # can either be the actual message or the another packet object, either way this will be encrypted by the client, and decrypted as it traverses
        self.relay_id = relay_id

class Onion_Packet:
    def __init__(self, Data_packet, num_layer, packet_type, Respond_packet=None):
        self.packet_type = packet_type
        self.num_layer = num_layer #Basically a counter, decrement every time a layer is removed, increment when we add a layer
        self.Data_packet = Data_packet # Add the corresponding packet from the corresponding decryption or encryption
        self.Respond_Packet = Respond_packet

def to_bytes_rep(packet):
    return pickle.dumps(packet)

def to_obj_rep(packet):
    return pickle.loads(packet)
    
def test():
    inner = Data_packet(
        src_addr="relay2",
        src_port=5001,
        dest_addr="server",
        dst_port=8080,
        payload= "test message",
        relay_type= RelayFlag.RELAY.name,
        relay_id=None
    )
    middle = Data_packet(
        src_addr="relay1",
        src_port=4000,
        dest_addr="relay2",
        dst_port=5000,
        payload=to_bytes_rep(inner),
        relay_type=RelayFlag.RELAY.name,
        relay_id=None
    )
    outer = Data_packet (
        src_addr="client",
        src_port=4000,
        dest_addr="relay1",
        dst_port=5000,
        payload=to_bytes_rep(middle),
        relay_type= RelayFlag.NONE.name,
        relay_id=None
    )

    outer = to_bytes_rep(outer)
    print(outer)
    print(to_obj_rep(to_obj_rep(outer).payload))
    
if __name__ == "__main__":
    test()