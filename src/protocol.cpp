#include "vpn/protocol.hpp"

#include <arpa/inet.h>

#include <cstring>

namespace vpn {
namespace {

void put_u16(std::uint8_t* out, std::uint16_t value) {
  out[0] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  out[1] = static_cast<std::uint8_t>(value & 0xFFu);
}

void put_u32(std::uint8_t* out, std::uint32_t value) {
  out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  out[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

void put_u64(std::uint8_t* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>(
        (value >> static_cast<unsigned>(56 - 8 * i)) & 0xFFu);
  }
}

std::uint16_t get_u16(const std::uint8_t* in) {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(in[0]) << 8) | in[1]);
}

std::uint32_t get_u32(const std::uint8_t* in) {
  return (static_cast<std::uint32_t>(in[0]) << 24) |
         (static_cast<std::uint32_t>(in[1]) << 16) |
         (static_cast<std::uint32_t>(in[2]) << 8) |
         static_cast<std::uint32_t>(in[3]);
}

std::uint64_t get_u64(const std::uint8_t* in) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | in[i];
  }
  return value;
}

void append_u8(Bytes& out, std::uint8_t value) { out.push_back(value); }

void append_u16(Bytes& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void append_u32(Bytes& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void append_u64(Bytes& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>(
        (value >> static_cast<unsigned>(56 - 8 * i)) & 0xFFu));
  }
}

void append(Bytes& out, const std::uint8_t* data, std::size_t len) {
  out.insert(out.end(), data, data + len);
}

bool valid_type(std::uint8_t type) {
  return type >= static_cast<std::uint8_t>(PacketType::Hello) &&
         type <= static_cast<std::uint8_t>(PacketType::Bye);
}

}  // namespace

std::array<std::uint8_t, kHeaderSize> PacketHeader::serialize() const {
  std::array<std::uint8_t, kHeaderSize> out{};
  put_u32(out.data() + 0, magic);
  out[4] = version;
  out[5] = static_cast<std::uint8_t>(type);
  out[6] = flags;
  out[7] = 0;
  put_u64(out.data() + 8, session_id);
  put_u64(out.data() + 16, counter);
  put_u16(out.data() + 24, payload_len);
  out[26] = 0;
  out[27] = 0;
  return out;
}

std::optional<PacketHeader> PacketHeader::parse(const std::uint8_t* data,
                                                std::size_t len) {
  if (data == nullptr || len < kHeaderSize) {
    return std::nullopt;
  }
  if (get_u32(data + 0) != kMagic || data[4] != kVersion) {
    return std::nullopt;
  }
  if (!valid_type(data[5]) || data[7] != 0 || data[26] != 0 || data[27] != 0) {
    return std::nullopt;
  }

  PacketHeader header;
  header.magic = kMagic;
  header.version = data[4];
  header.type = static_cast<PacketType>(data[5]);
  header.flags = data[6];
  header.session_id = get_u64(data + 8);
  header.counter = get_u64(data + 16);
  header.payload_len = get_u16(data + 24);
  if (header.payload_len > kMaxPayload) {
    return std::nullopt;
  }
  return header;
}

Bytes Packet::serialize() const {
  PacketHeader copy = header;
  copy.magic = kMagic;
  copy.version = kVersion;
  copy.payload_len = static_cast<std::uint16_t>(payload.size());

  const auto header_bytes = copy.serialize();
  Bytes out(header_bytes.begin(), header_bytes.end());
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::optional<Packet> Packet::parse(const std::uint8_t* data, std::size_t len,
                                    std::string* error) {
  const auto header = PacketHeader::parse(data, len);
  if (!header) {
    if (error != nullptr) {
      *error = "invalid header";
    }
    return std::nullopt;
  }

  const std::size_t expected = kHeaderSize + header->payload_len;
  if (len != expected) {
    if (error != nullptr) {
      *error = "length mismatch";
    }
    return std::nullopt;
  }

  Packet packet;
  packet.header = *header;
  packet.payload.assign(data + kHeaderSize, data + len);
  return packet;
}

Bytes HelloPayload::serialize() const {
  Bytes out;
  out.reserve(32 + 16 + 8 + 16);
  append(out, public_key.data(), public_key.size());
  append(out, nonce.data(), nonce.size());
  append_u64(out, timestamp);
  append(out, proof.data(), proof.size());
  return out;
}

std::optional<HelloPayload> HelloPayload::parse(const std::uint8_t* data,
                                                std::size_t len) {
  constexpr std::size_t kExpected = 32 + 16 + 8 + 16;
  if (data == nullptr || len != kExpected) {
    return std::nullopt;
  }
  HelloPayload payload;
  std::memcpy(payload.public_key.data(), data, 32);
  std::memcpy(payload.nonce.data(), data + 32, 16);
  payload.timestamp = get_u64(data + 48);
  std::memcpy(payload.proof.data(), data + 56, 16);
  return payload;
}

Bytes HelloAckPayload::serialize() const {
  if (routes.size() > 255) {
    return {};
  }

  Bytes out;
  out.reserve(72 + routes.size() * 5);
  append(out, server_public_key.data(), server_public_key.size());
  append(out, server_nonce.data(), server_nonce.size());
  append_u32(out, assigned_ip);
  append_u8(out, prefix_len);
  append_u16(out, mtu);
  append_u8(out, static_cast<std::uint8_t>(routes.size()));
  for (const auto& route : routes) {
    append_u32(out, route.network);
    append_u8(out, route.prefix);
  }
  append(out, proof.data(), proof.size());
  return out;
}

std::optional<HelloAckPayload> HelloAckPayload::parse(const std::uint8_t* data,
                                                      std::size_t len) {
  constexpr std::size_t kFixed = 32 + 16 + 4 + 1 + 2 + 1;
  constexpr std::size_t kMin = kFixed + 16;
  if (data == nullptr || len < kMin) {
    return std::nullopt;
  }

  const std::size_t route_count = data[55];
  if (len != kMin + route_count * 5) {
    return std::nullopt;
  }

  HelloAckPayload payload;
  std::memcpy(payload.server_public_key.data(), data, 32);
  std::memcpy(payload.server_nonce.data(), data + 32, 16);
  payload.assigned_ip = get_u32(data + 48);
  payload.prefix_len = data[52];
  if (payload.prefix_len > 32) {
    return std::nullopt;
  }
  payload.mtu = get_u16(data + 53);
  payload.routes.reserve(route_count);

  std::size_t offset = kFixed;
  for (std::size_t i = 0; i < route_count; ++i) {
    Cidr route;
    route.network = get_u32(data + offset);
    route.prefix = data[offset + 4];
    if (route.prefix > 32) {
      return std::nullopt;
    }
    route.network &= route.mask();
    payload.routes.push_back(route);
    offset += 5;
  }

  std::memcpy(payload.proof.data(), data + offset, 16);
  return payload;
}

Bytes hello_transcript(const Key32& client_public, const Nonce16& client_nonce,
                       std::uint64_t timestamp) {
  static constexpr char kLabel[] = "minevpn-hello";
  Bytes out;
  out.reserve(sizeof(kLabel) + client_public.size() + client_nonce.size() + 8);
  append(out, reinterpret_cast<const std::uint8_t*>(kLabel), sizeof(kLabel));
  append(out, client_public.data(), client_public.size());
  append(out, client_nonce.data(), client_nonce.size());
  append_u64(out, timestamp);
  return out;
}

Bytes ack_transcript(const Key32& client_public, const Nonce16& client_nonce,
                     const HelloAckPayload& ack) {
  static constexpr char kLabel[] = "minevpn-ack";
  Bytes out;
  out.reserve(sizeof(kLabel) + 32 + 16 + 32 + 16 + 4 + 1 + 2 + 1 +
              ack.routes.size() * 5);
  append(out, reinterpret_cast<const std::uint8_t*>(kLabel), sizeof(kLabel));
  append(out, client_public.data(), client_public.size());
  append(out, client_nonce.data(), client_nonce.size());
  append(out, ack.server_public_key.data(), ack.server_public_key.size());
  append(out, ack.server_nonce.data(), ack.server_nonce.size());
  append_u32(out, ntohl(ack.assigned_ip));
  append_u8(out, ack.prefix_len);
  append_u16(out, ack.mtu);
  append_u8(out, static_cast<std::uint8_t>(ack.routes.size()));
  for (const auto& route : ack.routes) {
    append_u32(out, route.network);
    append_u8(out, route.prefix);
  }
  return out;
}

Bytes pack_encrypted(std::uint64_t session_id, std::uint64_t counter,
                     PacketType type, std::uint8_t direction, const Key32& key,
                     const std::uint8_t* plaintext, std::size_t len) {
  if (len > kMaxPayload - kTagSize) {
    return {};
  }

  PacketHeader header;
  header.type = type;
  header.flags = static_cast<std::uint8_t>(
      kFlagEncrypted | (type == PacketType::Data ? 0 : kFlagControl));
  header.session_id = session_id;
  header.counter = counter;
  header.payload_len = static_cast<std::uint16_t>(len + kTagSize);

  const auto header_bytes = header.serialize();
  const auto nonce = build_nonce(direction, counter);

  Bytes ciphertext;
  if (!aead_encrypt(key, nonce.data(), header_bytes.data(), header_bytes.size(),
                    plaintext, len, ciphertext)) {
    return {};
  }

  Bytes out(header_bytes.begin(), header_bytes.end());
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  return out;
}

bool unpack_encrypted(const Packet& packet, std::uint8_t direction,
                      const Key32& key, Bytes& plaintext) {
  if ((packet.header.flags & kFlagEncrypted) == 0) {
    return false;
  }
  if (packet.payload.size() < kTagSize) {
    return false;
  }

  const auto header_bytes = packet.header.serialize();
  const auto nonce = build_nonce(direction, packet.header.counter);
  return aead_decrypt(key, nonce.data(), header_bytes.data(),
                      header_bytes.size(), packet.payload.data(),
                      packet.payload.size(), plaintext);
}

std::optional<Ipv4Info> parse_ipv4(const std::uint8_t* data, std::size_t len) {
  if (data == nullptr || len < 20) {
    return std::nullopt;
  }
  if ((data[0] >> 4) != 4) {
    return std::nullopt;
  }

  const std::size_t header_len = static_cast<std::size_t>(data[0] & 0x0F) * 4;
  if (header_len < 20 || header_len > len) {
    return std::nullopt;
  }

  const std::uint16_t total_len = get_u16(data + 2);
  if (total_len < header_len || total_len > len) {
    return std::nullopt;
  }

  Ipv4Info info;
  info.total_len = total_len;
  info.protocol = data[9];
  // Store addresses in the same convention as in_addr.s_addr (network bytes in
  // a host integer), matching ipv4_from_string() and the rest of the code.
  info.src = htonl(get_u32(data + 12));
  info.dst = htonl(get_u32(data + 16));
  return info;
}

}  // namespace vpn
