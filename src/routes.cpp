#include "vpn/routes.hpp"

#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <string>

namespace vpn {
namespace {

bool run_ip_route(const char* action, const std::string& interface_name,
                  const Cidr& route) {
  if (!valid_interface_name(interface_name)) {
    return false;
  }

  const std::string destination = route.to_string();
  const pid_t pid = ::fork();
  if (pid < 0) {
    return false;
  }
  if (pid == 0) {
    ::execlp("ip", "ip", "route", action, destination.c_str(), "dev",
             interface_name.c_str(), static_cast<char*>(nullptr));
    ::_exit(127);
  }

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return false;
    }
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}  // namespace

std::optional<IpPrefix> parse_ip_prefix(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }

  const auto slash = text.find('/');
  const std::string_view address_text =
      slash == std::string_view::npos ? text : text.substr(0, slash);
  const std::string address_string(address_text);

  in_addr address{};
  if (::inet_pton(AF_INET, address_string.c_str(), &address) != 1) {
    return std::nullopt;
  }

  std::uint8_t prefix = 32;
  if (slash != std::string_view::npos) {
    const std::string_view prefix_text = text.substr(slash + 1);
    if (prefix_text.empty()) {
      return std::nullopt;
    }
    unsigned value = 0;
    const auto result =
        std::from_chars(prefix_text.data(), prefix_text.data() + prefix_text.size(),
                        value);
    if (result.ec != std::errc() ||
        result.ptr != prefix_text.data() + prefix_text.size() || value > 32) {
      return std::nullopt;
    }
    prefix = static_cast<std::uint8_t>(value);
  }

  return IpPrefix{address.s_addr, prefix};
}

std::optional<Cidr> Cidr::parse(std::string_view text) {
  const auto parsed = parse_ip_prefix(text);
  if (!parsed) {
    return std::nullopt;
  }
  return from_address(parsed->address, parsed->prefix);
}

Cidr Cidr::from_address(std::uint32_t address_network_order,
                        std::uint8_t prefix) {
  Cidr cidr;
  cidr.prefix = prefix > 32 ? 32 : prefix;
  const std::uint32_t host = ntohl(address_network_order);
  cidr.network = host & cidr.mask();
  return cidr;
}

std::uint32_t Cidr::mask() const {
  if (prefix == 0) {
    return 0;
  }
  if (prefix >= 32) {
    return 0xFFFFFFFFu;
  }
  return 0xFFFFFFFFu << (32 - prefix);
}

bool Cidr::contains(std::uint32_t address_network_order) const {
  return (ntohl(address_network_order) & mask()) == network;
}

std::string Cidr::to_string() const {
  return ipv4_to_string(htonl(network)) + "/" + std::to_string(prefix);
}

void RouteTable::add(const Cidr& route) {
  for (const auto& existing : routes_) {
    if (existing == route) {
      return;
    }
  }
  routes_.push_back(route);
}

bool RouteTable::contains(std::uint32_t address_network_order) const {
  for (const auto& route : routes_) {
    if (route.contains(address_network_order)) {
      return true;
    }
  }
  return false;
}

std::optional<Cidr> RouteTable::longest_match(
    std::uint32_t address_network_order) const {
  std::optional<Cidr> best;
  for (const auto& route : routes_) {
    if (route.contains(address_network_order) &&
        (!best || route.prefix > best->prefix)) {
      best = route;
    }
  }
  return best;
}

bool valid_interface_name(const std::string& name) {
  if (name.empty() || name.size() > 15) {
    return false;
  }
  for (const char character : name) {
    const bool allowed = (character >= 'a' && character <= 'z') ||
                         (character >= 'A' && character <= 'Z') ||
                         (character >= '0' && character <= '9') ||
                         character == '_' || character == '-' ||
                         character == '.';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

bool install_route(const std::string& interface_name, const Cidr& route) {
  return run_ip_route("replace", interface_name, route);
}

bool remove_route(const std::string& interface_name, const Cidr& route) {
  return run_ip_route("del", interface_name, route);
}

std::uint32_t ipv4_from_string(const std::string& text) {
  in_addr address{};
  if (::inet_pton(AF_INET, text.c_str(), &address) != 1) {
    return 0;
  }
  return address.s_addr;
}

std::string ipv4_to_string(std::uint32_t address_network_order) {
  in_addr address{};
  address.s_addr = address_network_order;
  char buffer[INET_ADDRSTRLEN] = {};
  if (::inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
    return "0.0.0.0";
  }
  return buffer;
}

}  // namespace vpn
