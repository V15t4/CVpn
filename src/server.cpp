#include "vpn/server.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>

#include "vpn/crypto.hpp"
#include "vpn/log.hpp"
#include "vpn/protocol.hpp"
#include "vpn/routes.hpp"
#include "vpn/session.hpp"
#include "vpn/tun.hpp"

namespace vpn {
namespace {

using Clock = std::chrono::steady_clock;

std::int64_t wall_clock_seconds() {
  return static_cast<std::int64_t>(std::time(nullptr));
}

std::string errno_string() {
  return std::string(std::strerror(errno));
}

}  // namespace

class Server {
 public:
  explicit Server(ServerConfig config)
      : config_(std::move(config)),
        sessions_(config_.pool, config_.tun_ip) {
    if (config_.routes.empty()) {
      config_.routes.push_back(Cidr::parse("0.0.0.0/0").value());
    }
    for (const auto& route : config_.routes) {
      allowed_.add(route);
    }
    if (!config_.psk.empty()) {
      psk_key_ = sha256(
          reinterpret_cast<const std::uint8_t*>(config_.psk.data()),
          config_.psk.size());
      has_psk_ = true;
    }
  }

  int run() {
    if (!initialize()) {
      return 1;
    }

    pollfd descriptors[2] = {};
    descriptors[0].fd = socket_.fd();
    descriptors[0].events = POLLIN;
    descriptors[1].fd = tun_.fd();
    descriptors[1].events = POLLIN;

    auto last_expire = Clock::now();
    log_info("server ready on %s", config_.listen.to_string().c_str());

    while (g_running.load()) {
      const int ready = ::poll(descriptors, 2, 500);
      if (ready < 0) {
        if (errno == EINTR) {
          continue;
        }
        log_error("poll failed: %s", errno_string().c_str());
        break;
      }

      if ((descriptors[0].revents & POLLIN) != 0) {
        drain_udp();
      }
      if ((descriptors[1].revents & POLLIN) != 0) {
        drain_tun();
      }

      const auto now = Clock::now();
      if (now - last_expire >= std::chrono::seconds(1)) {
        expire_sessions();
        last_expire = now;
      }
    }

    log_info("server stopped");
    return 0;
  }

 private:
  bool initialize() {
    std::string error;

    tun_ = TunDevice::open(config_.tun_name, &error);
    if (!tun_.valid()) {
      log_error("cannot open TUN: %s", error.c_str());
      return false;
    }
    if (!tun_.configure(config_.tun_ip, config_.tun_prefix, config_.mtu,
                        &error)) {
      log_error("cannot configure TUN: %s", error.c_str());
      return false;
    }
    if (!tun_.set_up(&error)) {
      log_error("cannot bring TUN up: %s", error.c_str());
      return false;
    }

    auto socket = UdpSocket::bind(config_.listen, &error);
    if (!socket) {
      log_error("cannot bind UDP socket: %s", error.c_str());
      return false;
    }
    socket_ = std::move(*socket);

    log_info("TUN %s: %s/%u, MTU %u", config_.tun_name.c_str(),
             ipv4_to_string(config_.tun_ip).c_str(), config_.tun_prefix,
             config_.mtu);
    log_info("address pool: %s, forwarding routes: %s",
             config_.pool.to_string().c_str(),
             allowed_.routes().empty()
                 ? "<none>"
                 : allowed_.routes().front().to_string().c_str());
    if (has_psk_) {
      log_info("pre-shared key authentication enabled");
    } else {
      log_warn("no --psk configured: server identity is not authenticated");
    }
    return true;
  }

  void drain_udp() {
    std::uint8_t buffer[kMaxPacketSize];
    for (int i = 0; i < 64; ++i) {
      Endpoint from;
      const ssize_t received =
          socket_.recv_from(buffer, sizeof(buffer), from);
      if (received < 0) {
        if (would_block()) {
          return;
        }
        log_debug("recv_from: %s", errno_string().c_str());
        continue;
      }
      if (received == 0) {
        continue;
      }

      std::string error;
      const auto packet = Packet::parse(
          buffer, static_cast<std::size_t>(received), &error);
      if (!packet) {
        ++dropped_;
        log_debug("dropped datagram from %s: %s", from.to_string().c_str(),
                  error.c_str());
        continue;
      }
      try {
        handle_packet(*packet, from);
      } catch (const std::exception& exception) {
        log_error("packet handling failed: %s", exception.what());
      }
    }
  }

  void drain_tun() {
    std::uint8_t buffer[kMaxPayload];
    for (int i = 0; i < 64; ++i) {
      const ssize_t received = tun_.read(buffer, sizeof(buffer));
      if (received < 0) {
        if (would_block()) {
          return;
        }
        log_debug("tun read: %s", errno_string().c_str());
        continue;
      }
      if (received > 0) {
        try {
          route_from_tun(buffer, static_cast<std::size_t>(received));
        } catch (const std::exception& exception) {
          log_error("TUN packet handling failed: %s", exception.what());
        }
      }
    }
  }

  void handle_packet(const Packet& packet, const Endpoint& from) {
    switch (packet.header.type) {
      case PacketType::Hello:
        handle_hello(packet, from);
        return;
      case PacketType::Data:
      case PacketType::Keepalive:
      case PacketType::Bye:
        handle_encrypted(packet, from);
        return;
      case PacketType::HelloAck:
        return;
    }
  }

  void handle_hello(const Packet& packet, const Endpoint& from) {
    const auto hello = HelloPayload::parse(packet.payload.data(),
                                           packet.payload.size());
    if (!hello) {
      log_debug("malformed HELLO from %s", from.to_string().c_str());
      return;
    }

    const std::int64_t now = wall_clock_seconds();
    const std::int64_t timestamp = static_cast<std::int64_t>(hello->timestamp);
    const std::int64_t delta = now >= timestamp ? now - timestamp
                                                : timestamp - now;
    if (delta > kTimestampToleranceSec) {
      log_warn("HELLO from %s rejected: clock skew %llds",
               from.to_string().c_str(),
               static_cast<long long>(delta));
      return;
    }

    if (has_psk_) {
      const auto transcript =
          hello_transcript(hello->public_key, hello->nonce, hello->timestamp);
      const Proof16 expected = compute_proof(psk_key_, transcript);
      if (!constant_time_equal(expected.data(), hello->proof.data(),
                               expected.size())) {
        log_warn("HELLO from %s rejected: bad PSK proof",
                 from.to_string().c_str());
        return;
      }
    }

    X25519KeyPair server_keypair;
    Key32 shared{};
    try {
      server_keypair = X25519KeyPair::generate();
      if (!server_keypair.derive(hello->public_key, shared)) {
        log_warn("HELLO from %s rejected: invalid public key",
                 from.to_string().c_str());
        return;
      }
    } catch (const std::exception& exception) {
      log_error("key exchange failed: %s", exception.what());
      return;
    }

    const Key32 server_public = server_keypair.public_key();
    Nonce16 server_nonce{};
    random_bytes(server_nonce.data(), server_nonce.size());

    SessionKeys keys;
    try {
      keys = derive_session_keys(shared, hello->nonce, server_nonce,
                                 config_.psk);
    } catch (const std::exception& exception) {
      log_error("key derivation failed: %s", exception.what());
      return;
    }

    Session* session = sessions_.create(from, keys);
    if (session == nullptr) {
      log_error("address pool exhausted; rejecting %s",
                from.to_string().c_str());
      return;
    }

    HelloAckPayload ack;
    ack.server_public_key = server_public;
    ack.server_nonce = server_nonce;
    ack.assigned_ip = session->virtual_ip;
    ack.prefix_len = config_.tun_prefix;
    ack.mtu = config_.mtu;
    ack.routes = config_.routes;

    const auto transcript =
        ack_transcript(hello->public_key, hello->nonce, ack);
    ack.proof = compute_proof(keys.confirm, transcript);

    Packet response;
    response.header.type = PacketType::HelloAck;
    response.header.flags = kFlagControl;
    response.header.session_id = session->id;
    response.header.counter = 0;
    response.payload = ack.serialize();

    const Bytes wire = response.serialize();
    log_info("session %016llx from %s assigned %s/%u",
             static_cast<unsigned long long>(session->id),
             from.to_string().c_str(),
             ipv4_to_string(session->virtual_ip).c_str(), ack.prefix_len);
    send_wire(wire, from);
  }

  void handle_encrypted(const Packet& packet, const Endpoint& from) {
    Session* session = sessions_.by_id(packet.header.session_id);
    if (session == nullptr) {
      log_debug("unknown session %016llx from %s",
                static_cast<unsigned long long>(packet.header.session_id),
                from.to_string().c_str());
      return;
    }

    if (!(session->endpoint == from)) {
      log_warn("session %016llx used from unexpected endpoint %s",
               static_cast<unsigned long long>(session->id),
               from.to_string().c_str());
      return;
    }

    Bytes plaintext;
    if (!unpack_encrypted(packet, kDirectionClientToServer,
                          session->keys.client_to_server, plaintext)) {
      log_debug("authentication failed for session %016llx",
                static_cast<unsigned long long>(session->id));
      return;
    }

    if (!session->replay.accept(packet.header.counter)) {
      log_debug("replayed packet %llu for session %016llx",
                static_cast<unsigned long long>(packet.header.counter),
                static_cast<unsigned long long>(session->id));
      return;
    }

    session->last_seen = Clock::now();

    if (packet.header.type == PacketType::Keepalive) {
      send_keepalive(*session);
      return;
    }

    if (packet.header.type == PacketType::Bye) {
      log_info("session %016llx closed by peer",
               static_cast<unsigned long long>(session->id));
      sessions_.remove(session->id);
      return;
    }

    const auto ip = parse_ipv4(plaintext.data(), plaintext.size());
    if (!ip) {
      ++dropped_;
      log_debug("session %016llx sent a non-IPv4 payload",
                static_cast<unsigned long long>(session->id));
      return;
    }

    if (ip->src != session->virtual_ip) {
      log_warn("session %016llx spoofed source %s (expected %s)",
               static_cast<unsigned long long>(session->id),
               ipv4_to_string(ip->src).c_str(),
               ipv4_to_string(session->virtual_ip).c_str());
      return;
    }

    if (!allowed_.contains(ip->dst)) {
      log_debug("destination %s denied by route policy",
                ipv4_to_string(ip->dst).c_str());
      return;
    }

    const ssize_t written = tun_.write(plaintext.data(), ip->total_len);
    if (written < 0) {
      if (!would_block()) {
        log_debug("tun write: %s", errno_string().c_str());
      }
      return;
    }

    ++session->rx_packets;
    session->rx_bytes += ip->total_len;
  }

  void route_from_tun(const std::uint8_t* data, std::size_t len) {
    const auto ip = parse_ipv4(data, len);
    if (!ip) {
      ++dropped_;
      return;
    }

    Session* session = sessions_.by_vip(ip->dst);
    if (session == nullptr) {
      log_debug("no session for destination %s",
                ipv4_to_string(ip->dst).c_str());
      return;
    }

    ++session->tx_counter;
    if (session->tx_counter == 0) {
      log_warn("session %016llx counter exhausted, rekey required",
               static_cast<unsigned long long>(session->id));
      sessions_.remove(session->id);
      return;
    }

    const Bytes wire =
        pack_encrypted(session->id, session->tx_counter, PacketType::Data,
                       kDirectionServerToClient, session->keys.server_to_client,
                       data, ip->total_len);
    if (wire.empty()) {
      log_error("failed to encrypt packet for session %016llx",
                static_cast<unsigned long long>(session->id));
      return;
    }

    if (send_wire(wire, session->endpoint)) {
      ++session->tx_packets;
      session->tx_bytes += ip->total_len;
    }
  }

  void send_keepalive(Session& session) {
    ++session.tx_counter;
    if (session.tx_counter == 0) {
      sessions_.remove(session.id);
      return;
    }
    const Bytes wire =
        pack_encrypted(session.id, session.tx_counter, PacketType::Keepalive,
                       kDirectionServerToClient, session.keys.server_to_client,
                       nullptr, 0);
    send_wire(wire, session.endpoint);
    ++session.tx_packets;
  }

  bool send_wire(const Bytes& wire, const Endpoint& to) {
    if (wire.empty()) {
      return false;
    }
    const ssize_t sent = socket_.send_to(wire.data(), wire.size(), to);
    if (sent < 0) {
      if (!would_block()) {
        log_warn("send to %s: %s", to.to_string().c_str(),
                 errno_string().c_str());
      }
      return false;
    }
    return static_cast<std::size_t>(sent) == wire.size();
  }

  void expire_sessions() {
    const auto expired =
        sessions_.expire(Clock::now(), std::chrono::seconds(kSessionTimeoutSec));
    for (const std::uint64_t id : expired) {
      log_info("session %016llx expired",
               static_cast<unsigned long long>(id));
    }
  }

  ServerConfig config_;
  TunDevice tun_;
  UdpSocket socket_;
  SessionStore sessions_;
  RouteTable allowed_;
  Key32 psk_key_{};
  bool has_psk_ = false;
  std::uint64_t dropped_ = 0;
};

int run_server(const ServerConfig& config) {
  Server server(config);
  return server.run();
}

}  // namespace vpn
