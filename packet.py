import json
import pickle
from crypto_utils import RelayFlag

class Packet:
    def __init__(self, src_addr, src_port, dest_addr, dst_port, payload, relay_type):
        self.relay_type = relay_type
        self.src_addr = src_addr
        self.src_port = src_port
        self.dest_addr = dest_addr
        self.dst_port = dst_port
        self.payload = payload # can either be the actual message or the another packet object
    
    def to_json(self):
        dict_ = {
            'src_addr': self.src_addr,
            'src_port': self.src_port,
            'dest_addr': self.dest_addr,
            'dst_port': self.dst_port,
            'relay_type': self.relay_type,
            'payload': self.payload #TODO: LATER ENCRYPT THE PAYLOAD AT using the key (CLIENT DOES THIS)
        }
        return json.dumps(dict_)
    
def from_json_to_packet(packet_json):
    dict_ = json.loads(packet_json)
    payload = dict_['payload']

    return Packet(
        src_addr=dict_['src_addr'],
        src_port=dict_['src_port'],
        dest_addr=dict_['dest_addr'],
        dst_port=dict_['dst_port'],
        relay_type = dict_['relay_type'],
        payload=payload #TODO LATER DECRYPT THE PAYLOAD at the current relay
    )

class Onion_Packet:
    def __init__(self, packet, num_layer):
        self.num_layer = num_layer #decrement every time a layer is removed, increment when we add a layer
        packet = packet # Add the corresponding packet from the corresponding decryption or encryption


def test():
    inner = Packet(
        src_addr="relay2",
        src_port=5001,
        dest_addr="server",
        dst_port=8080,
        payload="test message",
        relay_type=RelayFlag.EXIT.name
    )
    middle = Packet(
        src_addr="relay1",
        src_port=4000,
        dest_addr="relay2",
        dst_port=5000,
        payload=inner.to_json(),
        relay_type=RelayFlag.ENTRY.name
    )
    outer = Packet (
        src_addr="client",
        src_port=4000,
        dest_addr="relay1",
        dst_port=5000,
        payload=middle.to_json(),
        relay_type= RelayFlag.NONE.name
    )

    json_str = outer.to_json()
    print("Sent JSON to relay 1:", json_str)
    json_str = json.loads(json_str)["payload"]
    print("At Relay 1", json_str)
    print("Sent JSON to relay 2:", json.dumps(json_str))
    json_str = json.loads(json_str)["payload"]
    print("At Relay 2", json_str)
    print("Sent JSON to server:", json.dumps(json_str))
    print("AT server", json.loads(json_str)["payload"])
    
test()

#TODO LATER: change the implementation to use pickles rather than json