# CVpn

A small, educational userspace VPN written in modern C++17.

`CVpn` creates a TUN interface, encrypts IPv4 packets with ChaCha20-Poly1305
and moves them over UDP. It is deliberately compact: one binary, one TUN
device, one UDP socket, and a single-threaded `poll()` loop on both sides.

## Features

- Linux TUN device (`/dev/net/tun`, `IFF_TUN | IFF_NO_PI`)
- UDP transport with a compact binary protocol
- X25519 ephemeral key exchange per handshake
- HKDF-SHA256 key derivation, optional pre-shared key authentication
- AEAD (ChaCha20-Poly1305) for confidentiality and integrity
- 64-packet sliding-window replay protection
- Per-client sessions, virtual IP allocation, idle timeout
- Route table (CIDR) for allowed/pushed routes
- Optional installation of pushed routes through `ip route`
- CMake build, unit tests, AddressSanitizer option

## Components

| File | Responsibility |
| --- | --- |
| `constants.hpp/cpp` | Protocol constants, packet type names, global run flag |
| `crypto.hpp/cpp` | Random bytes, SHA-256, HKDF, HMAC, X25519, ChaCha20-Poly1305 |
| `network.hpp/cpp` | `Endpoint`, UDP socket, parsing |
| `routes.hpp/cpp` | CIDR parsing, route tables, `ip route` helpers |
| `protocol.hpp/cpp` | Packet header, handshake payloads, encryption helpers, IPv4 parsing |
| `tun.hpp/cpp` | TUN device open/configure/read/write |
| `session.hpp/cpp` | Replay window, IP pool, session store |
| `server.hpp/cpp` | UDP/TUN event loop, handshake, forwarding |
| `client.hpp/cpp` | Handshake, tunnel loop, keepalives, route installation |
| `main.cpp` | Argument parsing, signals |

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build
```

Optional sanitizers:

```sh
cmake -S . -B build -DVPN_SANITIZE=ON
cmake --build build -j
```

The build needs OpenSSL 3.x development headers and libraries, plus
`CAP_NET_ADMIN` at runtime (run as root or grant the capability).

## Usage

Server:

```sh
sudo ./build/CVpn server \
  --listen 0.0.0.0:51820 \
  --tun vpn0 \
  --tun-ip 10.8.0.1/24 \
  --pool 10.8.0.0/24 \
  --route 0.0.0.0/0 \
  --psk 'shared-secret'
```

Client:

```sh
sudo ./build/CVpn client \
  --server 203.0.113.10:51820 \
  --tun vpn0 \
  --psk 'shared-secret' \
  --install-routes
```

After the handshake the client configures its TUN address from the server's
assignment (for example `10.8.0.2/24`).

## Routing and NAT

`CVpn` is a layer-3 point-to-point tunnel. The server owns `10.8.0.1/24`
on its TUN device and hands addresses from `--pool` to clients. To give
clients access to the Internet through the server you also need, on the
server:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
```

Replace `eth0` with the server's external interface. Clients can then reach
the Internet through the tunnel once their default route points at `vpn0`.

Full-tunnel default routes require policy routing so that packets to the VPN
server itself do not re-enter the tunnel. `--install-routes` deliberately
skips `0.0.0.0/0` and prints a warning; install it manually, for example:

```sh
ip route add <server-public-ip>/32 via <original-gateway> dev <physical-iface>
ip route replace default dev vpn0
```

Split-tunnel routes (for example `192.168.0.0/16`) are installed
automatically by `--install-routes`.

## Protocol

Handshake:

1. Client sends `HELLO` with an X25519 public key, a random nonce and a
   timestamp.
2. Server replies with `HELLO_ACK` containing its X25519 public key, a
   random nonce, the assigned virtual IP, MTU and pushed routes.
3. Both sides derive `client->server`, `server->client` and `confirm` keys
   with HKDF-SHA256 over the X25519 shared secret. When a PSK is configured
   it is mixed into the HKDF salt and a truncated HMAC proves the server's
   identity.

Data packets carry an IPv4 packet, encrypted with ChaCha20-Poly1305. The
packet header is used as additional authenticated data. A monotonic counter
per direction provides nonce uniqueness and feeds a 64-packet replay window.

## Security notes

- Confidentiality and integrity rely on OpenSSL's ChaCha20-Poly1305 and
  X25519. The implementation has **not** been audited.
- Without `--psk` the handshake is vulnerable to an active man-in-the-middle.
  Use a strong pre-shared key.
- Replay protection covers a 64-packet window; very old packets are dropped.
- There is no perfect-forward-secrecy beyond the per-handshake ephemeral
  keys, no rekeying and no anti-DoS protection.
- Timestamps are checked with a 120 second tolerance; keep clocks in sync.
- Both endpoints need `CAP_NET_ADMIN`.

## License

Provided as-is for educational purposes.
