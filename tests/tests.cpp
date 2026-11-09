#include <arpa/inet.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "vpn/constants.hpp"
#include "vpn/crypto.hpp"
#include "vpn/network.hpp"
#include "vpn/protocol.hpp"
#include "vpn/routes.hpp"
#include "vpn/session.hpp"

namespace {

int failures = 0;

#define CHECK(condition)                                                    \
  do {                                                                      \
    if (!(condition)) {                                                     \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,         \
                   #condition);                                             \
      ++failures;                                                           \
    }                                                                       \
  } while (false)

vpn::Bytes from_hex(const std::string& text) {
  vpn::Bytes out;
  out.reserve(text.size() / 2);
  auto nibble = [](char character) -> int {
    if (character >= '0' && character <= '9') {
      return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
      return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
      return character - 'A' + 10;
    }
    return -1;
  };
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
    const int high = nibble(text[i]);
    const int low = nibble(text[i + 1]);
    if (high < 0 || low < 0) {
      break;
    }
    out.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return out;
}

std::string to_hex(const vpn::Bytes& bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 0x0F]);
  }
  return out;
}

std::string to_hex(const vpn::Key32& key) {
  return to_hex(vpn::Bytes(key.begin(), key.end()));
}

void test_hkdf_kat() {
  vpn::Key32 ikm{};
  std::memset(ikm.data(), 0x0b, 22);
  const vpn::Bytes salt = from_hex("000102030405060708090a0b0c");
  const vpn::Bytes info = from_hex("f0f1f2f3f4f5f6f7f8f9");
  const std::string info_string(reinterpret_cast<const char*>(info.data()),
                                info.size());

  const vpn::Key32 output =
      vpn::hkdf_sha256(ikm.data(), 22, salt.data(), salt.size(), info_string);
  CHECK(to_hex(output) ==
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
}

void test_chacha20_poly1305_kat() {
  const vpn::Key32 key = [&] {
    const auto bytes = from_hex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    vpn::Key32 out{};
    std::memcpy(out.data(), bytes.data(), out.size());
    return out;
  }();
  const vpn::Bytes nonce =
      from_hex("070000004041424344454647");
  const vpn::Bytes aad = from_hex("50515253c0c1c2c3c4c5c6c7");

  const std::string plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";

  vpn::Bytes encrypted;
  CHECK(vpn::aead_encrypt(
      key, nonce.data(), aad.data(), aad.size(),
      reinterpret_cast<const std::uint8_t*>(plaintext.data()),
      plaintext.size(), encrypted));
  CHECK(to_hex(encrypted) ==
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
        "1ae10b594f09e26a7e902ecbd0600691");

  vpn::Bytes decrypted;
  CHECK(vpn::aead_decrypt(key, nonce.data(), aad.data(), aad.size(),
                          encrypted.data(), encrypted.size(), decrypted));
  CHECK(std::string(decrypted.begin(), decrypted.end()) == plaintext);

  vpn::Bytes tampered = encrypted;
  tampered.back() ^= 0x01;
  CHECK(!vpn::aead_decrypt(key, nonce.data(), aad.data(), aad.size(),
                           tampered.data(), tampered.size(), decrypted));

  CHECK(!vpn::aead_decrypt(key, nonce.data(), aad.data(), aad.size(),
                           encrypted.data(), vpn::kTagSize - 1, decrypted));
}

void test_x25519_and_keys() {
  const vpn::X25519KeyPair alice = vpn::X25519KeyPair::generate();
  const vpn::X25519KeyPair bob = vpn::X25519KeyPair::generate();
  CHECK(alice.valid());
  CHECK(bob.valid());

  vpn::Key32 alice_secret{};
  vpn::Key32 bob_secret{};
  CHECK(alice.derive(bob.public_key(), alice_secret));
  CHECK(bob.derive(alice.public_key(), bob_secret));
  CHECK(alice_secret == bob_secret);

  vpn::Nonce16 client_nonce{};
  vpn::Nonce16 server_nonce{};
  for (std::size_t i = 0; i < client_nonce.size(); ++i) {
    client_nonce[i] = static_cast<std::uint8_t>(i + 1);
    server_nonce[i] = static_cast<std::uint8_t>(0x80 + i);
  }

  const vpn::SessionKeys client_keys = vpn::derive_session_keys(
      alice_secret, client_nonce, server_nonce, "topsecret");
  const vpn::SessionKeys server_keys = vpn::derive_session_keys(
      bob_secret, client_nonce, server_nonce, "topsecret");
  CHECK(client_keys.client_to_server == server_keys.client_to_server);
  CHECK(client_keys.server_to_client == server_keys.server_to_client);
  CHECK(client_keys.confirm == server_keys.confirm);

  const vpn::SessionKeys without_psk =
      vpn::derive_session_keys(alice_secret, client_nonce, server_nonce, "");
  CHECK(without_psk.client_to_server != client_keys.client_to_server);

  const vpn::Key32 psk_key =
      vpn::sha256(reinterpret_cast<const std::uint8_t*>("topsecret"), 9);
  vpn::HelloPayload hello;
  hello.public_key = alice.public_key();
  hello.nonce = client_nonce;
  hello.timestamp = 1700000000;
  hello.proof = vpn::compute_proof(
      psk_key, vpn::hello_transcript(hello.public_key, hello.nonce,
                                     hello.timestamp));

  const vpn::Bytes hello_wire = hello.serialize();
  const auto parsed_hello =
      vpn::HelloPayload::parse(hello_wire.data(), hello_wire.size());
  CHECK(parsed_hello.has_value());
  if (parsed_hello) {
    CHECK(parsed_hello->public_key == hello.public_key);
    CHECK(parsed_hello->nonce == hello.nonce);
    CHECK(parsed_hello->timestamp == hello.timestamp);
    const vpn::Proof16 proof = vpn::compute_proof(
        psk_key, vpn::hello_transcript(parsed_hello->public_key,
                                       parsed_hello->nonce,
                                       parsed_hello->timestamp));
    CHECK(vpn::constant_time_equal(proof.data(), parsed_hello->proof.data(),
                                  proof.size()));
  }

  vpn::HelloAckPayload ack;
  ack.server_public_key = bob.public_key();
  ack.server_nonce = server_nonce;
  ack.assigned_ip = vpn::ipv4_from_string("10.8.0.2");
  ack.prefix_len = 24;
  ack.mtu = 1400;
  ack.routes.push_back(*vpn::Cidr::parse("0.0.0.0/0"));
  ack.routes.push_back(*vpn::Cidr::parse("192.168.0.0/16"));
  ack.proof = vpn::compute_proof(
      client_keys.confirm,
      vpn::ack_transcript(hello.public_key, client_nonce, ack));

  const vpn::Bytes ack_wire = ack.serialize();
  const auto parsed_ack =
      vpn::HelloAckPayload::parse(ack_wire.data(), ack_wire.size());
  CHECK(parsed_ack.has_value());
  if (parsed_ack) {
    CHECK(parsed_ack->server_public_key == ack.server_public_key);
    CHECK(parsed_ack->assigned_ip == ack.assigned_ip);
    CHECK(parsed_ack->prefix_len == ack.prefix_len);
    CHECK(parsed_ack->mtu == ack.mtu);
    CHECK(parsed_ack->routes == ack.routes);
    const vpn::Proof16 proof = vpn::compute_proof(
        client_keys.confirm,
        vpn::ack_transcript(hello.public_key, client_nonce, *parsed_ack));
    CHECK(vpn::constant_time_equal(proof.data(), parsed_ack->proof.data(),
                                  proof.size()));
  }
}

std::vector<std::uint8_t> make_ipv4_packet(const char* source,
                                           const char* destination) {
  std::vector<std::uint8_t> packet(20, 0);
  packet[0] = 0x45;
  packet[2] = 0;
  packet[3] = 20;
  packet[8] = 64;
  packet[9] = 17;
  const std::uint32_t src = vpn::ipv4_from_string(source);
  const std::uint32_t dst = vpn::ipv4_from_string(destination);
  std::memcpy(packet.data() + 12, &src, 4);
  std::memcpy(packet.data() + 16, &dst, 4);
  return packet;
}

void test_protocol_packets() {
  vpn::PacketHeader header;
  header.type = vpn::PacketType::Data;
  header.flags = vpn::kFlagEncrypted;
  header.session_id = 0x1122334455667788ULL;
  header.counter = 42;
  header.payload_len = 3;

  const auto header_wire = header.serialize();
  const auto parsed_header =
      vpn::PacketHeader::parse(header_wire.data(), header_wire.size());
  CHECK(parsed_header.has_value());
  if (parsed_header) {
    CHECK(parsed_header->magic == vpn::kMagic);
    CHECK(parsed_header->version == vpn::kVersion);
    CHECK(parsed_header->type == vpn::PacketType::Data);
    CHECK(parsed_header->session_id == header.session_id);
    CHECK(parsed_header->counter == header.counter);
    CHECK(parsed_header->payload_len == 3);
  }

  vpn::Packet packet;
  packet.header.type = vpn::PacketType::Data;
  packet.header.session_id = 7;
  packet.header.counter = 9;
  packet.payload = {1, 2, 3, 4};
  vpn::Bytes wire = packet.serialize();
  const auto parsed_packet = vpn::Packet::parse(wire.data(), wire.size());
  CHECK(parsed_packet.has_value());
  if (parsed_packet) {
    CHECK(parsed_packet->header.session_id == 7);
    CHECK(parsed_packet->header.counter == 9);
    CHECK(parsed_packet->payload == packet.payload);
  }

  wire.push_back(0);
  CHECK(!vpn::Packet::parse(wire.data(), wire.size()));

  vpn::Packet truncated;
  truncated.payload = {1, 2, 3};
  CHECK(!vpn::Packet::parse(truncated.serialize().data(),
                            truncated.serialize().size() - 1));
}

void test_encrypted_roundtrip() {
  vpn::SessionKeys keys;
  keys.client_to_server.fill(0x11);
  keys.server_to_client.fill(0x22);
  keys.confirm.fill(0x33);

  const auto ip = make_ipv4_packet("10.8.0.2", "1.1.1.1");
  const vpn::Bytes wire = vpn::pack_encrypted(
      0xABCDEF, 1, vpn::PacketType::Data, vpn::kDirectionClientToServer,
      keys.client_to_server, ip.data(), ip.size());
  CHECK(!wire.empty());

  const auto packet = vpn::Packet::parse(wire.data(), wire.size());
  CHECK(packet.has_value());
  if (packet) {
    vpn::Bytes plaintext;
    CHECK(vpn::unpack_encrypted(*packet, vpn::kDirectionClientToServer,
                                keys.client_to_server, plaintext));
    CHECK(plaintext == ip);

    CHECK(!vpn::unpack_encrypted(*packet, vpn::kDirectionServerToClient,
                                 keys.client_to_server, plaintext));

    vpn::Packet tampered = *packet;
    tampered.payload.back() ^= 0x80;
    CHECK(!vpn::unpack_encrypted(tampered, vpn::kDirectionClientToServer,
                                 keys.client_to_server, plaintext));
  }

  vpn::Bytes keepalive = vpn::pack_encrypted(
      1, 2, vpn::PacketType::Keepalive, vpn::kDirectionServerToClient,
      keys.server_to_client, nullptr, 0);
  const auto keepalive_packet =
      vpn::Packet::parse(keepalive.data(), keepalive.size());
  CHECK(keepalive_packet.has_value());
  if (keepalive_packet) {
    vpn::Bytes plaintext;
    CHECK(vpn::unpack_encrypted(*keepalive_packet,
                                vpn::kDirectionServerToClient,
                                keys.server_to_client, plaintext));
    CHECK(plaintext.empty());
  }
}

void test_replay_window() {
  vpn::ReplayWindow window;
  CHECK(window.accept(1));
  CHECK(window.accept(2));
  CHECK(!window.accept(1));
  CHECK(window.accept(100));
  CHECK(window.accept(50));
  CHECK(!window.accept(50));
  CHECK(!window.accept(1));
  CHECK(window.accept(101));
  CHECK(!window.accept(0));
}

void test_routes() {
  const auto prefix = vpn::parse_ip_prefix("10.8.0.1/24");
  CHECK(prefix.has_value());
  if (prefix) {
    CHECK(vpn::ipv4_to_string(prefix->address) == "10.8.0.1");
    CHECK(prefix->prefix == 24);
  }

  const auto cidr = vpn::Cidr::parse("10.1.2.3/16");
  CHECK(cidr.has_value());
  if (cidr) {
    CHECK(cidr->network == ::ntohl(vpn::ipv4_from_string("10.1.0.0")));
    CHECK(cidr->to_string() == "10.1.0.0/16");
    CHECK(cidr->contains(vpn::ipv4_from_string("10.1.200.7")));
    CHECK(!cidr->contains(vpn::ipv4_from_string("10.2.0.1")));
  }

  CHECK(!vpn::Cidr::parse("10.0.0.0/33").has_value());
  CHECK(!vpn::Cidr::parse("not-an-ip/24").has_value());
  CHECK(vpn::Cidr::parse("0.0.0.0/0").has_value());

  vpn::RouteTable table;
  table.add(*vpn::Cidr::parse("10.0.0.0/8"));
  table.add(*vpn::Cidr::parse("10.1.0.0/16"));
  table.add(*vpn::Cidr::parse("0.0.0.0/0"));

  CHECK(table.contains(vpn::ipv4_from_string("8.8.8.8")));
  const auto match = table.longest_match(vpn::ipv4_from_string("10.1.2.3"));
  CHECK(match.has_value());
  if (match) {
    CHECK(match->prefix == 16);
  }

  CHECK(vpn::valid_interface_name("vpn0"));
  CHECK(!vpn::valid_interface_name("bad name"));
  CHECK(!vpn::valid_interface_name(""));
  CHECK(!vpn::valid_interface_name("toolonginterfacename"));
}

void test_address_pool_and_sessions() {
  const vpn::Cidr pool = *vpn::Cidr::parse("10.8.0.0/24");
  const std::uint32_t server_ip = vpn::ipv4_from_string("10.8.0.1");
  vpn::IpPool addresses(pool, server_ip);
  CHECK(addresses.capacity() == 253);

  const std::uint32_t first = addresses.allocate();
  const std::uint32_t second = addresses.allocate();
  const std::uint32_t third = addresses.allocate();
  CHECK(first != 0);
  CHECK(second != 0);
  CHECK(third != 0);
  CHECK(first != second);
  CHECK(first != third);
  CHECK(second != third);
  CHECK(vpn::ipv4_to_string(first) == "10.8.0.2");
  CHECK(vpn::ipv4_to_string(second) == "10.8.0.3");
  CHECK(addresses.used() == 3);
  addresses.release(second);
  CHECK(addresses.used() == 2);
  const std::uint32_t fourth = addresses.allocate();
  CHECK(fourth != 0);
  CHECK(fourth != first);
  CHECK(fourth != third);

  const auto endpoint = vpn::parse_endpoint("127.0.0.1:40000", 0);
  CHECK(endpoint.has_value());

  vpn::SessionStore store(pool, server_ip);
  vpn::SessionKeys keys;
  keys.client_to_server.fill(1);
  keys.server_to_client.fill(2);
  keys.confirm.fill(3);

  vpn::Session* session = store.create(*endpoint, keys);
  CHECK(session != nullptr);
  if (session != nullptr) {
    CHECK(session->virtual_ip == vpn::ipv4_from_string("10.8.0.2"));
    CHECK(store.by_id(session->id) == session);
    CHECK(store.by_endpoint(*endpoint) == session);
    CHECK(store.by_vip(session->virtual_ip) == session);
    CHECK(store.size() == 1);

    const auto expired = store.expire(
        std::chrono::steady_clock::now() + std::chrono::seconds(61),
        std::chrono::seconds(60));
    CHECK(expired.size() == 1);
    CHECK(store.size() == 0);
    CHECK(store.by_endpoint(*endpoint) == nullptr);
  }
}

void test_ipv4_parser() {
  const auto packet = make_ipv4_packet("10.8.0.2", "1.1.1.1");
  const auto info = vpn::parse_ipv4(packet.data(), packet.size());
  CHECK(info.has_value());
  if (info) {
    CHECK(info->src == vpn::ipv4_from_string("10.8.0.2"));
    CHECK(info->dst == vpn::ipv4_from_string("1.1.1.1"));
    CHECK(info->total_len == 20);
    CHECK(info->protocol == 17);
  }

  auto broken = packet;
  broken[0] = 0x44;
  CHECK(!vpn::parse_ipv4(broken.data(), broken.size()));

  broken = packet;
  broken[3] = 21;
  CHECK(!vpn::parse_ipv4(broken.data(), broken.size()));

  CHECK(!vpn::parse_ipv4(packet.data(), 19));
}

}  // namespace

int main() {
  test_hkdf_kat();
  test_chacha20_poly1305_kat();
  test_x25519_and_keys();
  test_protocol_packets();
  test_encrypted_roundtrip();
  test_replay_window();
  test_routes();
  test_address_pool_and_sessions();
  test_ipv4_parser();

  if (failures == 0) {
    std::printf("PASS: all tests\n");
    return 0;
  }
  std::fprintf(stderr, "FAILED: %d check(s)\n", failures);
  return 1;
}
