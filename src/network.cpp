#include "vpn/network.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace vpn {
namespace {

std::string errno_string(int code) {
  char buffer[256] = {};
  // GNU strerror_r may return a pointer instead of writing to the buffer.
  const char* text = strerror_r(code, buffer, sizeof(buffer));
  return text != nullptr ? std::string(text) : std::string("unknown error");
}

}  // namespace

std::string Endpoint::to_string() const {
  if (len == 0) {
    return "<empty>";
  }

  char host[NI_MAXHOST] = {};
  char service[NI_MAXSERV] = {};
  if (getnameinfo(reinterpret_cast<const sockaddr*>(&addr), len, host,
                  sizeof(host), service, sizeof(service),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return "<invalid>";
  }

  if (family() == AF_INET6) {
    return "[" + std::string(host) + "]:" + service;
  }
  return std::string(host) + ":" + service;
}

bool Endpoint::operator==(const Endpoint& other) const {
  if (len == 0 || other.len == 0) {
    return len == other.len;
  }
  if (addr.ss_family != other.addr.ss_family) {
    return false;
  }

  if (addr.ss_family == AF_INET) {
    const auto* a = reinterpret_cast<const sockaddr_in*>(&addr);
    const auto* b = reinterpret_cast<const sockaddr_in*>(&other.addr);
    return a->sin_port == b->sin_port &&
           a->sin_addr.s_addr == b->sin_addr.s_addr;
  }
  if (addr.ss_family == AF_INET6) {
    const auto* a = reinterpret_cast<const sockaddr_in6*>(&addr);
    const auto* b = reinterpret_cast<const sockaddr_in6*>(&other.addr);
    return a->sin6_port == b->sin6_port &&
           a->sin6_scope_id == b->sin6_scope_id &&
           std::memcmp(&a->sin6_addr, &b->sin6_addr,
                       sizeof(a->sin6_addr)) == 0;
  }
  return false;
}

std::size_t EndpointHash::operator()(const Endpoint& endpoint) const {
  return std::hash<std::string>{}(endpoint.key());
}

bool would_block() {
  return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

std::optional<Endpoint> endpoint_from_sockaddr(const sockaddr* addr,
                                               socklen_t len) {
  if (addr == nullptr || len == 0 ||
      (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
    return std::nullopt;
  }
  Endpoint endpoint;
  std::memcpy(&endpoint.addr, addr, len);
  endpoint.len = len;
  return endpoint;
}

std::optional<Endpoint> parse_endpoint(const std::string& text,
                                       std::uint16_t default_port) {
  if (text.empty()) {
    return std::nullopt;
  }

  std::string host;
  std::string service;

  if (text.front() == '[') {
    const auto close = text.find(']');
    if (close == std::string::npos) {
      return std::nullopt;
    }
    host = text.substr(1, close - 1);
    if (close + 1 < text.size()) {
      if (text[close + 1] != ':') {
        return std::nullopt;
      }
      service = text.substr(close + 2);
    }
  } else {
    const auto first_colon = text.find(':');
    const auto last_colon = text.rfind(':');
    if (first_colon != std::string::npos && first_colon == last_colon) {
      host = text.substr(0, first_colon);
      service = text.substr(first_colon + 1);
    } else {
      // No colon (hostname / IPv4) or several colons (bare IPv6 address).
      host = text;
    }
  }

  if (host.empty()) {
    return std::nullopt;
  }
  if (service.empty()) {
    service = std::to_string(default_port);
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICSERV;

  addrinfo* results = nullptr;
  const int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &results);
  if (rc != 0) {
    return std::nullopt;
  }

  std::optional<Endpoint> endpoint;
  for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
    endpoint = endpoint_from_sockaddr(entry->ai_addr,
                                      static_cast<socklen_t>(entry->ai_addrlen));
    if (endpoint) {
      break;
    }
  }
  freeaddrinfo(results);

  return endpoint;
}

UdpSocket::~UdpSocket() {
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : fd_(other.fd_) {
  other.fd_ = -1;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}

std::optional<UdpSocket> UdpSocket::bind(const std::string& host,
                                         std::uint16_t port,
                                         std::string* error) {
  const std::string text = (host.empty() ? "0.0.0.0" : host) + ":" +
                           std::to_string(port);
  const auto endpoint = parse_endpoint(text, port);
  if (!endpoint) {
    if (error != nullptr) {
      *error = "cannot resolve " + text;
    }
    return std::nullopt;
  }
  return bind(*endpoint, error);
}

std::optional<UdpSocket> UdpSocket::bind(const Endpoint& endpoint,
                                         std::string* error) {
  const int fd = ::socket(endpoint.family(), SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    if (error != nullptr) {
      *error = "socket: " + errno_string(errno);
    }
    return std::nullopt;
  }

  UdpSocket socket(fd);
  socket.set_reuse_address();

  if (::bind(fd, reinterpret_cast<const sockaddr*>(&endpoint.addr),
             endpoint.len) != 0) {
    if (error != nullptr) {
      *error = "bind " + endpoint.to_string() + ": " + errno_string(errno);
    }
    return std::nullopt;
  }

  if (!socket.set_nonblocking()) {
    if (error != nullptr) {
      *error = "fcntl(O_NONBLOCK): " + errno_string(errno);
    }
    return std::nullopt;
  }

  return socket;
}

bool UdpSocket::set_nonblocking() {
  if (fd_ < 0) {
    return false;
  }
  const int flags = fcntl(fd_, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(fd_, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool UdpSocket::set_reuse_address() {
  if (fd_ < 0) {
    return false;
  }
  int value = 1;
  return setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0;
}

ssize_t UdpSocket::send_to(const std::uint8_t* data, std::size_t len,
                           const Endpoint& to) {
  if (fd_ < 0 || to.len == 0) {
    errno = EBADF;
    return -1;
  }
  return ::sendto(fd_, data, len, MSG_NOSIGNAL,
                  reinterpret_cast<const sockaddr*>(&to.addr), to.len);
}

ssize_t UdpSocket::recv_from(std::uint8_t* data, std::size_t len,
                             Endpoint& from) {
  if (fd_ < 0) {
    errno = EBADF;
    return -1;
  }
  sockaddr_storage storage{};
  socklen_t storage_len = sizeof(storage);
  const ssize_t received =
      ::recvfrom(fd_, data, len, 0, reinterpret_cast<sockaddr*>(&storage),
                 &storage_len);
  if (received >= 0) {
    from.addr = storage;
    from.len = storage_len;
  }
  return received;
}

}  // namespace vpn
