#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace vpn {

// Linux TUN device (/dev/net/tun, IFF_TUN | IFF_NO_PI).
class TunDevice {
 public:
  TunDevice() = default;
  ~TunDevice();

  TunDevice(const TunDevice&) = delete;
  TunDevice& operator=(const TunDevice&) = delete;
  TunDevice(TunDevice&& other) noexcept;
  TunDevice& operator=(TunDevice&& other) noexcept;

  static TunDevice open(const std::string& name, std::string* error = nullptr);

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  const std::string& name() const { return name_; }

  ssize_t read(std::uint8_t* buffer, std::size_t len);
  ssize_t write(const std::uint8_t* buffer, std::size_t len);

  bool configure(std::uint32_t address_network_order, std::uint8_t prefix,
                 std::uint16_t mtu, std::string* error = nullptr);
  bool set_up(std::string* error = nullptr);

 private:
  int fd_ = -1;
  std::string name_;
};

}  // namespace vpn
