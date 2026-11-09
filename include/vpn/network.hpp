#pragma once

#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <sys/socket.h>

#include "vpn/constants.hpp"

namespace vpn {

struct Endpoint {
  sockaddr_storage addr{};
  socklen_t len = 0;

  int family() const { return static_cast<int>(addr.ss_family); }
  std::string to_string() const;
  std::string key() const { return to_string(); }

  bool operator==(const Endpoint& other) const;
  bool operator!=(const Endpoint& other) const { return !(*this == other); }
};

struct EndpointHash {
  std::size_t operator()(const Endpoint& endpoint) const;
};

// Accepts "host:port", "[ipv6]:port" or "host" (uses default_port).
std::optional<Endpoint> parse_endpoint(const std::string& text,
                                       std::uint16_t default_port);
std::optional<Endpoint> endpoint_from_sockaddr(const sockaddr* addr,
                                               socklen_t len);

bool would_block();

class UdpSocket {
 public:
  UdpSocket() = default;
  ~UdpSocket();

  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;
  UdpSocket(UdpSocket&& other) noexcept;
  UdpSocket& operator=(UdpSocket&& other) noexcept;

  static std::optional<UdpSocket> bind(const Endpoint& endpoint,
                                       std::string* error = nullptr);
  static std::optional<UdpSocket> bind(const std::string& host,
                                       std::uint16_t port,
                                       std::string* error = nullptr);

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }

  bool set_nonblocking();
  bool set_reuse_address();

  // Returns bytes sent, or -1 with errno set. EAGAIN is a normal condition.
  ssize_t send_to(const std::uint8_t* data, std::size_t len,
                  const Endpoint& to);
  ssize_t recv_from(std::uint8_t* data, std::size_t len, Endpoint& from);

 private:
  explicit UdpSocket(int fd) : fd_(fd) {}
  int fd_ = -1;
};

}  // namespace vpn
