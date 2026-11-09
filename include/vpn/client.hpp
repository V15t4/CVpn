#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vpn/constants.hpp"
#include "vpn/network.hpp"

namespace vpn {

struct ClientConfig {
  Endpoint server;
  std::string tun_name = "vpn0";
  std::string psk;
  bool install_routes = false;
  bool verbose = false;
};

int run_client(const ClientConfig& config);

}  // namespace vpn
