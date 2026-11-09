#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vpn/constants.hpp"
#include "vpn/crypto.hpp"
#include "vpn/routes.hpp"

namespace vpn {

struct PacketHeader {
  std::uint32_t magic = kMagic;
  std::uint8_t version = kVersion;
  PacketType type = PacketType::Data;
  std::uint8_t flags = 0;
  std::uint64_t session_id = 0;
  std::uint64_t counter = 0;
  std::uint16_t payload_len = 0;

  std::array<std::uint8_t, kHeaderSize> serialize() const;
  static std::optional<PacketHeader> parse(const std::uint8_t* data,
                                           std::size_t len);
};

struct Packet {
  PacketHeader header;
  Bytes payload;

  Bytes serialize() const;
  static std::optional<Packet> parse(const std::uint8_t* data, std::size_t len,
                                     std::string* error = nullptr);
};

// HELLO: client ephemeral public key, nonce, wall-clock timestamp and a
// truncated HMAC proof (zero when no PSK is configured).
struct HelloPayload {
  Key32 public_key{};
  Nonce16 nonce{};
  std::uint64_t timestamp = 0;
  Proof16 proof{};

  Bytes serialize() const;
  static std::optional<HelloPayload> parse(const std::uint8_t* data,
                                           std::size_t len);
};

// HELLO_ACK: server ephemeral public key, nonce, assigned address, MTU,
// pushed routes and a truncated HMAC proof over the handshake transcript.
struct HelloAckPayload {
  Key32 server_public_key{};
  Nonce16 server_nonce{};
  std::uint32_t assigned_ip = 0;  // network byte order
  std::uint8_t prefix_len = kDefaultPrefix;
  std::uint16_t mtu = kDefaultMtu;
  std::vector<Cidr> routes;
  Proof16 proof{};

  Bytes serialize() const;
  static std::optional<HelloAckPayload> parse(const std::uint8_t* data,
                                              std::size_t len);
};

Bytes hello_transcript(const Key32& client_public, const Nonce16& client_nonce,
                       std::uint64_t timestamp);

Bytes ack_transcript(const Key32& client_public, const Nonce16& client_nonce,
                     const HelloAckPayload& ack);

// Builds header + AEAD ciphertext + tag.
Bytes pack_encrypted(std::uint64_t session_id, std::uint64_t counter,
                     PacketType type, std::uint8_t direction,
                     const Key32& key, const std::uint8_t* plaintext,
                     std::size_t len);

bool unpack_encrypted(const Packet& packet, std::uint8_t direction,
                      const Key32& key, Bytes& plaintext);

struct Ipv4Info {
  std::uint32_t src = 0;  // network byte order
  std::uint32_t dst = 0;  // network byte order
  std::uint16_t total_len = 0;
  std::uint8_t protocol = 0;
};

// Validates an IPv4 header; total_len is checked against the buffer length.
std::optional<Ipv4Info> parse_ipv4(const std::uint8_t* data, std::size_t len);

}  // namespace vpn
