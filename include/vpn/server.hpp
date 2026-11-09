#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vpn/constants.hpp"
#include "vpn/network.hpp"
#include "vpn/routes.hpp"

namespace vpn {

struct ServerConfig {
  Endpoint listen;
  std::string tun_name = "vpn0";
  std::uint32_t tun_ip = 0;  // network byte order, e.g. 10.8.0.1
  std::uint8_t tun_prefix = kDefaultPrefix;
  Cidr pool{};
  std::vector<Cidr> routes;
  std::string psk;
  std::uint16_t mtu = kDefaultMtu;
  bool verbose = false;
};

int run_server(const ServerConfig& config);

}  // namespace vpn
