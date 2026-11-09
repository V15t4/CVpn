#include "vpn/client.hpp"

#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "vpn/crypto.hpp"
#include "vpn/log.hpp"
#include "vpn/protocol.hpp"
#include "vpn/routes.hpp"
#include "vpn/session.hpp"
#include "vpn/tun.hpp"

namespace vpn {
namespace {

using Clock = std::chrono::steady_clock;

std::string errno_string() {
  return std::string(std::strerror(errno));
}

}  // namespace

class Client {
 public:
  explicit Client(ClientConfig config) : config_(std::move(config)) {}

  int run() {
    std::string error;
    const std::string bind_host =
        config_.server.family() == AF_INET6 ? "::" : "0.0.0.0";
    auto socket =
        UdpSocket::bind(bind_host, 0, &error);
    if (!socket) {
      log_error("cannot create UDP socket: %s", error.c_str());
      return 1;
    }
    socket_ = std::move(*socket);

    tun_ = TunDevice::open(config_.tun_name, &error);
    if (!tun_.valid()) {
      log_error("cannot open TUN: %s", error.c_str());
      return 1;
    }

    // FIXME: handle roaming endpoints.
    log_info("client starting: server %s, TUN %s",
             config_.server.to_string().c_str(), config_.tun_name.c_str());

    pollfd descriptors[2] = {};
    descriptors[0].fd = socket_.fd();
    descriptors[0].events = POLLIN;
    descriptors[1].fd = tun_.fd();
    descriptors[1].events = POLLIN;

    while (g_running.load()) {
      if (!established_) {
        if (!handshake()) {
          if (!g_running.load()) {
            break;
          }
          log_warn("handshake with %s failed",
                   config_.server.to_string().c_str());
          for (int i = 0; i < 20 && g_running.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
          }
          continue;
        }
        log_info("tunnel established");
      }

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

      if (!established_) {
        continue;
      }

      const auto now = Clock::now();
      if (now - last_keepalive_ >=
          std::chrono::seconds(kKeepaliveIntervalSec)) {
        send_keepalive();
        last_keepalive_ = now;
      }

      if (now - last_rx_ > std::chrono::seconds(kSessionTimeoutSec)) {
        log_warn("server timed out; reconnecting");
        reset_session();
      }
    }

    if (established_) {
      send_encrypted(PacketType::Bye, nullptr, 0);
    }
    cleanup_routes();
    log_info("client stopped");
    return 0;
  }

 private:
  bool handshake() {
    X25519KeyPair ephemeral;
    Key32 client_public{};
    Nonce16 client_nonce{};

    try {
      ephemeral = X25519KeyPair::generate();
      client_public = ephemeral.public_key();
      random_bytes(client_nonce.data(), client_nonce.size());
    } catch (const std::exception& exception) {
      log_error("cannot generate handshake keys: %s", exception.what());
      return false;
    }

    HelloPayload hello;
    hello.public_key = client_public;
    hello.nonce = client_nonce;
    hello.timestamp = static_cast<std::uint64_t>(std::time(nullptr));

    if (!config_.psk.empty()) {
      const Key32 psk_digest =
          sha256(reinterpret_cast<const std::uint8_t*>(config_.psk.data()),
                 config_.psk.size());
      hello.proof = compute_proof(
          psk_digest,
          hello_transcript(hello.public_key, hello.nonce, hello.timestamp));
    }

    Packet request;
    request.header.type = PacketType::Hello;
    request.header.flags = kFlagControl;
    request.header.session_id = 0;
    request.header.counter = 0;
    request.payload = hello.serialize();
    const Bytes wire = request.serialize();

    log_debug("sending HELLO to %s", config_.server.to_string().c_str());

    for (int attempt = 0; attempt < kHandshakeAttempts && g_running.load();
         ++attempt) {
      const ssize_t sent =
          socket_.send_to(wire.data(), wire.size(), config_.server);
      if (sent < 0) {
        if (!would_block()) {
          log_warn("HELLO send: %s", errno_string().c_str());
        }
      }

      auto deadline = Clock::now() +
                      std::chrono::milliseconds(kHandshakeIntervalMs);
      while (g_running.load()) {
        const auto now = Clock::now();
        if (now >= deadline) {
          break;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        pollfd descriptor = {socket_.fd(), POLLIN, 0};
        const int ready =
            ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (ready < 0) {
          if (errno == EINTR) {
            continue;
          }
          return false;
        }
        if (ready == 0) {
          break;
        }

        for (int i = 0; i < 32; ++i) {
          std::uint8_t buffer[kMaxPacketSize];
          Endpoint from;
          const ssize_t received =
              socket_.recv_from(buffer, sizeof(buffer), from);
          if (received < 0) {
            if (would_block()) {
              break;
            }
            continue;
          }

          const auto packet = Packet::parse(
              buffer, static_cast<std::size_t>(received));
          if (!packet || packet->header.type != PacketType::HelloAck) {
            continue;
          }
          if (!(from == config_.server)) {
            log_debug("ignoring HELLO_ACK from unexpected %s",
                      from.to_string().c_str());
            continue;
          }
          if (handle_ack(*packet, ephemeral, client_public, client_nonce)) {
            return true;
          }
        }
      }

      log_debug("handshake attempt %d timed out", attempt + 1);
    }

    return false;
  }

  bool handle_ack(const Packet& packet, const X25519KeyPair& ephemeral,
                  const Key32& client_public, const Nonce16& client_nonce) {
    const auto ack =
        HelloAckPayload::parse(packet.payload.data(), packet.payload.size());
    if (!ack || packet.header.session_id == 0 || ack->assigned_ip == 0) {
      return false;
    }

    Key32 shared{};
    SessionKeys keys;
    try {
      if (!ephemeral.derive(ack->server_public_key, shared)) {
        log_warn("HELLO_ACK contains an invalid server key");
        return false;
      }
      keys = derive_session_keys(shared, client_nonce, ack->server_nonce,
                                 config_.psk);
    } catch (const std::exception& exception) {
      log_error("key derivation failed: %s", exception.what());
      return false;
    }

    const auto transcript = ack_transcript(client_public, client_nonce, *ack);
    const Proof16 expected = compute_proof(keys.confirm, transcript);
    if (!constant_time_equal(expected.data(), ack->proof.data(),
                             expected.size())) {
      log_warn("HELLO_ACK authentication failed");
      return false;
    }

    std::string error;
    if (!tun_.configure(ack->assigned_ip, ack->prefix_len, ack->mtu, &error)) {
      log_error("cannot configure TUN: %s", error.c_str());
      return false;
    }
    if (!tun_.set_up(&error)) {
      log_error("cannot bring TUN up: %s", error.c_str());
      return false;
    }

    session_id_ = packet.header.session_id;
    keys_ = keys;
    replay_.reset();
    tx_counter_ = 0;
    peer_ = config_.server;
    last_rx_ = Clock::now();
    last_keepalive_ = last_rx_;
    established_ = true;

    log_info("assigned address %s/%u, MTU %u, %zu pushed route(s)",
             ipv4_to_string(ack->assigned_ip).c_str(), ack->prefix_len,
             ack->mtu, ack->routes.size());

    pushed_routes_ = ack->routes;
    if (config_.install_routes) {
      install_pushed_routes();
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

      const auto packet = Packet::parse(
          buffer, static_cast<std::size_t>(received));
      if (!packet) {
        continue;
      }
      if (!established_ || packet->header.session_id != session_id_) {
        continue;
      }
      if (packet->header.type != PacketType::Data &&
          packet->header.type != PacketType::Keepalive &&
          packet->header.type != PacketType::Bye) {
        continue;
      }
      if (!(from == peer_)) {
        log_debug("ignoring packet from unexpected %s",
                  from.to_string().c_str());
        continue;
      }

      Bytes plaintext;
      if (!unpack_encrypted(*packet, kDirectionServerToClient,
                            keys_.server_to_client, plaintext)) {
        log_debug("packet authentication failed");
        continue;
      }
      if (!replay_.accept(packet->header.counter)) {
        log_debug("replayed packet %llu",
                  static_cast<unsigned long long>(packet->header.counter));
        continue;
      }

      last_rx_ = Clock::now();

      if (packet->header.type == PacketType::Keepalive) {
        continue;
      }
      if (packet->header.type == PacketType::Bye) {
        log_info("server closed the tunnel");
        reset_session();
        continue;
      }

      const auto ip = parse_ipv4(plaintext.data(), plaintext.size());
      if (!ip) {
        log_debug("received a non-IPv4 payload");
        continue;
      }

      const ssize_t written = tun_.write(plaintext.data(), ip->total_len);
      if (written < 0 && !would_block()) {
        log_debug("tun write: %s", errno_string().c_str());
      }
    }
  }

  void drain_tun() {
    if (!established_) {
      return;
    }

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
      if (received == 0) {
        continue;
      }

      const auto ip =
          parse_ipv4(buffer, static_cast<std::size_t>(received));
      if (!ip) {
        continue;
      }

      if (!send_encrypted(PacketType::Data, buffer, ip->total_len)) {
        log_debug("failed to send packet to %s",
                  ipv4_to_string(ip->dst).c_str());
      }
    }
  }

  bool send_encrypted(PacketType type, const std::uint8_t* data,
                      std::size_t len) {
    if (!established_) {
      return false;
    }

    ++tx_counter_;
    if (tx_counter_ == 0) {
      log_warn("packet counter exhausted; reconnecting");
      reset_session();
      return false;
    }

    const Bytes wire =
        pack_encrypted(session_id_, tx_counter_, type,
                       kDirectionClientToServer, keys_.client_to_server, data,
                       len);
    if (wire.empty()) {
      log_error("cannot encrypt %s packet", packet_type_name(type));
      return false;
    }

    const ssize_t sent = socket_.send_to(wire.data(), wire.size(), peer_);
    if (sent < 0) {
      if (!would_block()) {
        log_warn("send to %s: %s", peer_.to_string().c_str(),
                 errno_string().c_str());
      }
      return false;
    }
    return static_cast<std::size_t>(sent) == wire.size();
  }

  void send_keepalive() {
    send_encrypted(PacketType::Keepalive, nullptr, 0);
  }

  void reset_session() {
    established_ = false;
    session_id_ = 0;
    keys_ = SessionKeys{};
    replay_.reset();
    tx_counter_ = 0;
    peer_ = Endpoint{};
  }

  void install_pushed_routes() {
    for (const auto& route : pushed_routes_) {
      if (route.prefix == 0) {
        log_warn(
            "skipping default route %s: add a policy route manually to avoid "
            "routing the VPN server itself into the tunnel",
            route.to_string().c_str());
        continue;
      }
      if (install_route(config_.tun_name, route)) {
        installed_routes_.push_back(route);
        log_info("route %s dev %s", route.to_string().c_str(),
                 config_.tun_name.c_str());
      } else {
        log_warn("failed to install route %s dev %s",
                 route.to_string().c_str(), config_.tun_name.c_str());
      }
    }
  }

  void cleanup_routes() {
    for (const auto& route : installed_routes_) {
      remove_route(config_.tun_name, route);
    }
    installed_routes_.clear();
  }

  ClientConfig config_;
  UdpSocket socket_;
  TunDevice tun_;
  bool established_ = false;
  std::uint64_t session_id_ = 0;
  SessionKeys keys_;
  ReplayWindow replay_;
  std::uint64_t tx_counter_ = 0;
  Endpoint peer_;
  Clock::time_point last_rx_{};
  Clock::time_point last_keepalive_{};
  std::vector<Cidr> pushed_routes_;
  std::vector<Cidr> installed_routes_;
};

int run_client(const ClientConfig& config) {
  Client client(config);
  return client.run();
}

}  // namespace vpn
