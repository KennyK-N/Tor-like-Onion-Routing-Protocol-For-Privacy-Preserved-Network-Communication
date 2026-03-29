# CMPT-471-PROJECT


Client-> Server Communication
Client:
  plaintext → layered encryption (onion) → send over TCP

Relay 1:
  receive packet with encrypted data → decrypt one layer → forward to Relay 2

Relay 2:
  receive packet with encrypted data → decrypt one layer → forward to Relay 3

Relay 3:
  receive encrypted data → decrypt last layer → send to server over TCP

Server:
  receive plaintext packet from relay 3 → send response packet back

Server -> Client communication
Server:
    Gets plaintext packet from third relay -> Sends plaintext response packet back

Relay 3:
    Gets plaintext packet from server -> adds a layer and encrypts with its client symmetric key -> sends to relay 2

Relay 2: 
    Gets packet from relay 3 -> adds a layer and encrypts with its client symmetric key -> sends to relay 1

Relay 1 :
    Gets packet from relay 2 -> adds a layer and  encrypts with its client symmetric key -> sends to client

Client:
    Gets packet from relay 1 -> decrypts all layers with its symmetric keys -> done