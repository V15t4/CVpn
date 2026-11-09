#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vpn {

struct IpPrefix {
  std::uint32_t address = 0;  // network byte order, host bits preserved
  std::uint8_t prefix = 32;
};

// Parses "a.b.c.d/prefix" or "a.b.c.d" (implicit /32).
std::optional<IpPrefix> parse_ip_prefix(std::string_view text);

struct Cidr {
  std::uint32_t network = 0;  // host byte order, host bits cleared
  std::uint8_t prefix = 0;

  static std::optional<Cidr> parse(std::string_view text);
  static Cidr from_address(std::uint32_t address_network_order,
                           std::uint8_t prefix);

  std::uint32_t mask() const;
  bool contains(std::uint32_t address_network_order) const;
  std::string to_string() const;

  bool operator==(const Cidr& other) const {
    return network == other.network && prefix == other.prefix;
  }
  bool operator!=(const Cidr& other) const { return !(*this == other); }
  bool operator<(const Cidr& other) const {
    return network != other.network ? network < other.network
                                    : prefix < other.prefix;
  }
};

class RouteTable {
 public:
  void add(const Cidr& route);
  bool contains(std::uint32_t address_network_order) const;
  std::optional<Cidr> longest_match(std::uint32_t address_network_order) const;
  bool empty() const { return routes_.empty(); }
  const std::vector<Cidr>& routes() const { return routes_; }

 private:
  std::vector<Cidr> routes_;
};

bool valid_interface_name(const std::string& name);

// Adds/removes a route through `interface_name` using `ip route ...`.
// Requires CAP_NET_ADMIN. Returns false on failure (or when `ip` is missing).
bool install_route(const std::string& interface_name, const Cidr& route);
bool remove_route(const std::string& interface_name, const Cidr& route);

std::uint32_t ipv4_from_string(const std::string& text);  // network order, 0 on error
std::string ipv4_to_string(std::uint32_t address_network_order);

}  // namespace vpn
