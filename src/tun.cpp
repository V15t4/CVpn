#include "vpn/tun.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "vpn/routes.hpp"

namespace vpn {
namespace {

std::string errno_string(int code) {
  char buffer[256] = {};
  const char* text = strerror_r(code, buffer, sizeof(buffer));
  return text != nullptr ? std::string(text) : std::string("unknown error");
}

void set_error(std::string* error, const std::string& message) {
  if (error != nullptr) {
    *error = message;
  }
}

std::uint32_t prefix_to_mask(std::uint8_t prefix) {
  if (prefix == 0) {
    return 0;
  }
  if (prefix >= 32) {
    return 0xFFFFFFFFu;
  }
  return 0xFFFFFFFFu << (32 - prefix);
}

bool ioctl_address(int fd, const std::string& name, unsigned long request,
                   std::uint32_t address_network_order) {
  ifreq request_struct{};
  std::strncpy(request_struct.ifr_name, name.c_str(), IFNAMSIZ - 1);

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = address_network_order;
  std::memcpy(&request_struct.ifr_addr, &address, sizeof(address));

  return ::ioctl(fd, request, &request_struct) == 0;
}

}  // namespace

TunDevice::~TunDevice() {
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

TunDevice::TunDevice(TunDevice&& other) noexcept
    : fd_(other.fd_), name_(std::move(other.name_)) {
  other.fd_ = -1;
  other.name_.clear();
}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = other.fd_;
    name_ = std::move(other.name_);
    other.fd_ = -1;
    other.name_.clear();
  }
  return *this;
}

// FIXME: IPv4 only; no IPv6 TUN support yet.
TunDevice TunDevice::open(const std::string& name, std::string* error) {
  if (!valid_interface_name(name)) {
    set_error(error, "invalid TUN interface name: " + name);
    return {};
  }

  const int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    set_error(error, "open /dev/net/tun: " + errno_string(errno));
    return {};
  }

  ifreq request{};
  request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
  std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);

  if (::ioctl(fd, TUNSETIFF, &request) < 0) {
    set_error(error, "TUNSETIFF " + name + ": " + errno_string(errno));
    ::close(fd);
    return {};
  }

  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    set_error(error, "fcntl(O_NONBLOCK): " + errno_string(errno));
    ::close(fd);
    return {};
  }

  TunDevice device;
  device.fd_ = fd;
  device.name_ = request.ifr_name;
  return device;
}

ssize_t TunDevice::read(std::uint8_t* buffer, std::size_t len) {
  if (fd_ < 0) {
    errno = EBADF;
    return -1;
  }
  for (;;) {
    const ssize_t result = ::read(fd_, buffer, len);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    return result;
  }
}

ssize_t TunDevice::write(const std::uint8_t* buffer, std::size_t len) {
  if (fd_ < 0) {
    errno = EBADF;
    return -1;
  }
  for (;;) {
    const ssize_t result = ::write(fd_, buffer, len);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    return result;
  }
}

bool TunDevice::configure(std::uint32_t address_network_order,
                          std::uint8_t prefix, std::uint16_t mtu,
                          std::string* error) {
  if (fd_ < 0) {
    set_error(error, "TUN device is not open");
    return false;
  }

  const int socket_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    set_error(error, "socket: " + errno_string(errno));
    return false;
  }

  bool ok = ioctl_address(socket_fd, name_, SIOCSIFADDR,
                          address_network_order);
  if (!ok) {
    set_error(error, "SIOCSIFADDR: " + errno_string(errno));
  }

  if (ok) {
    ok = ioctl_address(socket_fd, name_, SIOCSIFNETMASK,
                       htonl(prefix_to_mask(prefix)));
    if (!ok) {
      set_error(error, "SIOCSIFNETMASK: " + errno_string(errno));
    }
  }

  if (ok && mtu > 0) {
    ifreq request{};
    std::strncpy(request.ifr_name, name_.c_str(), IFNAMSIZ - 1);
    request.ifr_mtu = mtu;
    ok = ::ioctl(socket_fd, SIOCSIFMTU, &request) == 0;
    if (!ok) {
      set_error(error, "SIOCSIFMTU: " + errno_string(errno));
    }
  }

  ::close(socket_fd);
  return ok;
}

bool TunDevice::set_up(std::string* error) {
  if (fd_ < 0) {
    set_error(error, "TUN device is not open");
    return false;
  }

  const int socket_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    set_error(error, "socket: " + errno_string(errno));
    return false;
  }

  ifreq request{};
  std::strncpy(request.ifr_name, name_.c_str(), IFNAMSIZ - 1);

  bool ok = ::ioctl(socket_fd, SIOCGIFFLAGS, &request) == 0;
  if (!ok) {
    set_error(error, "SIOCGIFFLAGS: " + errno_string(errno));
  }

  if (ok) {
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP);
    ok = ::ioctl(socket_fd, SIOCSIFFLAGS, &request) == 0;
    if (!ok) {
      set_error(error, "SIOCSIFFLAGS: " + errno_string(errno));
    }
  }

  ::close(socket_fd);
  return ok;
}

}  // namespace vpn
