# Onion Routing Protocol

A Tor-like onion routing implementation in Python that routes encrypted traffic through a chain of relay proxies to preserve network privacy.

---

## How It Works

The protocol routes traffic through at least 3 relay proxies between the client and server. No single relay ever knows both the client's identity and the server's destination at the same time.

```
Client → Guard Relay → Middle Relay → Exit Relay → Server
```

**Key exchange** — Before sending any data, the client performs a Diffie-Hellman (ECDH) key exchange with each relay in sequence. Each exchange is tunnelled through all preceding relays, so only the guard relay ever sees the client's real IP. Relay public keys are signed with RSA to prevent impersonation.

**Sending data** — Messages are wrapped in nested encrypted layers, one per relay. Each relay can only peel off its own layer and see the address of the next hop. Only the exit relay sees the server's address.

**Receiving data** — Responses travel back through the same chain. Each relay re-encrypts the response before passing it back, so only the exit relay can see the server's raw response. The client peels each layer using the shared keys it established during the exchange.

**Integrity** — HMAC-SHA256 is used on each layer to detect tampering in transit.

---

## Project Structure

```
.
├── client.py         # Client node — builds the circuit, does key exchange, sends/receives data
├── proxy.py          # Relay node — decrypts one layer, forwards to the next hop or key exchanges
├── server.py         # Exit server — receives the final decrypted request
├── crypto_utils.py   # All cryptography helpers (ECDH, RSA, AES-CBC, HMAC, HKDF)
├── packet.py         # Packet class definitions and pickle serialization helpers
├── run.sh            # Shell script to spin up proxies, server, and client in a tmux session
├── dockerfile        # Docker container setup
└── requirements.txt  # Python dependencies (just cryptography)
```

---

## Cryptography Overview

| Purpose | Algorithm |
|---|---|
| Key exchange | ECDH (SECP256R1) |
| Key derivation | HKDF-SHA256 |
| Data encryption | AES-256-CBC |
| Integrity | HMAC-SHA256 |
| Relay authentication | RSA-2048 with PSS signatures |

---

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/)
- [tmux](https://github.com/tmux/tmux) (inside the container, already set up)

---

### 1. Build and start the container

**First time:**
```bash
docker build -t <imagename> .
docker run -it <imagename>
```

**Reusing an existing container:**
```bash
docker ps -a
docker start <container_id>
docker exec -it <container_id> bash
```

---

### 2. Start the session

Inside the container, run:
```bash
./run.sh
```

This spins up 3 proxy relays, the server, a tcpdump capture, and a tmux session with a window for each.

To switch between tmux windows: press `Ctrl + B`, then `S`, then use the arrow keys to navigate.

---

### 3. Run the client

In the tmux **client** window:
```bash
python client.py > output/client.log 2>&1
```

> Make sure the `active_proxies/` folder is not empty — it should have one `.txt` file per running proxy. If it is empty, the proxies have not registered yet.

---

### 4. Stop the session

```bash
tmux kill-session -t onion
```

Or manually per window: `Ctrl + C` to stop the process, then `Ctrl + D` to close the window.

---

### 5. Copy output to your local machine

Run this **outside** the container in a separate terminal:
```bash
docker cp <container_id>:/app/output/ .
```

---

## Output

The `output/` folder contains:

| File | Description |
|---|---|
| `client.log` | Client-side logs including key exchange and response |
| `proxy1.log`, `proxy2.log`, `proxy3.log` | Per-relay logs showing encrypted payloads before/after each hop |
| `server.log` | Server-side logs |
| `capture.pcap` | Raw packet capture, open in Wireshark to verify encryption |

---

## Metrics

After a session the client prints:

- Key exchange duration (ms)
- Total session duration (ms)
- Total bytes sent and received
- Send and receive throughput (kbps)

---

## Privacy Guarantees

- The **guard relay** knows the client's IP but not the server's address
- The **exit relay** knows the server's address but not the client's IP
- The **middle relay** knows neither
- No relay can link the client to the server on its own
- Even if the guard and exit relays are controlled by the same party, they cannot easily determine they are part of the same circuit

---

## Dependencies

```
cryptography
```

Install manually if running outside Docker:
```bash
pip install -r requirements.txt
```