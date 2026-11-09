#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

#include "vpn/client.hpp"
#include "vpn/constants.hpp"
#include "vpn/log.hpp"
#include "vpn/network.hpp"
#include "vpn/routes.hpp"
#include "vpn/server.hpp"

namespace {

constexpr const char* kProgramName = "minevpn";
constexpr const char* kVersion = "0.1.0";

void handle_signal(int /*signal*/) {
  vpn::g_running.store(false);
}

void print_usage() {
  std::cout
      << "minevpn " << kVersion << " - small userspace IPv4 VPN\n\n"
      << "Usage:\n"
      << "  " << kProgramName << " server [options]\n"
      << "  " << kProgramName << " client --server HOST:PORT [options]\n\n"
      << "Server options:\n"
      << "  --listen HOST:PORT    UDP listen address (default 0.0.0.0:"
      << vpn::kDefaultPort << ")\n"
      << "  --tun NAME            TUN interface name (default vpn0)\n"
      << "  --tun-ip IP/PREFIX    server tunnel address (default 10.8.0.1/24)\n"
      << "  --pool CIDR           client address pool (default 10.8.0.0/24)\n"
      << "  --route CIDR          allowed/pushed route, repeatable\n"
      << "                        (default 0.0.0.0/0)\n"
      << "  --mtu N               TUN MTU (default " << vpn::kDefaultMtu << ")\n"
      << "  --psk TEXT            pre-shared key (recommended)\n\n"
      << "Client options:\n"
      << "  --server HOST:PORT    VPN server (required)\n"
      << "  --tun NAME            TUN interface name (default vpn0)\n"
      << "  --psk TEXT            pre-shared key (must match the server)\n"
      << "  --install-routes      install pushed routes via `ip route`\n"
      << "                        (0.0.0.0/0 is skipped; requires root)\n\n"
      << "Common options:\n"
      << "  -v, --verbose         debug logging\n"
      << "  -h, --help            show this help\n\n"
      << "Both modes require CAP_NET_ADMIN (run as root or setcap).\n"
      << "See README.md for routing/NAT examples and security notes.\n";
}

struct Argument {
  std::string key;
  std::string value;
};

Argument split_argument(const std::string& text,
                        const std::vector<std::string>& arguments,
                        std::size_t& index) {
  const auto equals = text.find('=');
  if (equals != std::string::npos) {
    return {text.substr(0, equals), text.substr(equals + 1)};
  }
  if (index + 1 >= arguments.size()) {
    throw std::runtime_error("missing value for " + text);
  }
  return {text, arguments[++index]};
}

std::uint16_t parse_u16(const std::string& text, const std::string& option) {
  char* end = nullptr;
  errno = 0;
  const unsigned long value = std::strtoul(text.c_str(), &end, 10);
  if (errno != 0 || end == text.c_str() || *end != '\0' || value > 65535) {
    throw std::runtime_error("invalid value for " + option + ": " + text);
  }
  return static_cast<std::uint16_t>(value);
}

vpn::Cidr parse_cidr(const std::string& text, const std::string& option) {
  const auto cidr = vpn::Cidr::parse(text);
  if (!cidr) {
    throw std::runtime_error("invalid CIDR for " + option + ": " + text);
  }
  return *cidr;
}

vpn::Endpoint parse_endpoint_or_throw(const std::string& text,
                                      std::uint16_t default_port,
                                      const std::string& option) {
  const auto endpoint = vpn::parse_endpoint(text, default_port);
  if (!endpoint) {
    throw std::runtime_error("invalid address for " + option + ": " + text);
  }
  return *endpoint;
}

int parse_server(std::vector<std::string> arguments) {
  vpn::ServerConfig config;
  config.listen =
      parse_endpoint_or_throw("0.0.0.0:" + std::to_string(vpn::kDefaultPort),
                              vpn::kDefaultPort, "--listen");

  const auto default_tunnel =
      vpn::parse_ip_prefix("10.8.0.1/24");
  config.tun_ip = default_tunnel->address;
  config.tun_prefix = default_tunnel->prefix;
  config.pool = vpn::Cidr::from_address(default_tunnel->address,
                                        default_tunnel->prefix);

  bool pool_explicit = false;

  for (std::size_t i = 1; i < arguments.size(); ++i) {
    const std::string key = arguments[i];
    if (key == "-h" || key == "--help") {
      print_usage();
      return 0;
    }
    if (key == "-v" || key == "--verbose") {
      config.verbose = true;
      vpn::set_verbose(true);
      continue;
    }

    const Argument argument = split_argument(key, arguments, i);
    if (argument.key == "--listen") {
      config.listen = parse_endpoint_or_throw(argument.value, vpn::kDefaultPort,
                                              "--listen");
    } else if (argument.key == "--tun") {
      config.tun_name = argument.value;
    } else if (argument.key == "--tun-ip") {
      const auto parsed = vpn::parse_ip_prefix(argument.value);
      if (!parsed) {
        throw std::runtime_error("invalid --tun-ip: " + argument.value);
      }
      config.tun_ip = parsed->address;
      config.tun_prefix = parsed->prefix;
    } else if (argument.key == "--pool") {
      config.pool = parse_cidr(argument.value, "--pool");
      pool_explicit = true;
    } else if (argument.key == "--route") {
      config.routes.push_back(parse_cidr(argument.value, "--route"));
    } else if (argument.key == "--mtu") {
      config.mtu = parse_u16(argument.value, "--mtu");
      if (config.mtu < 576) {
        throw std::runtime_error("--mtu must be at least 576");
      }
    } else if (argument.key == "--psk") {
      config.psk = argument.value;
    } else {
      throw std::runtime_error("unknown option: " + argument.key);
    }
  }

  if (!pool_explicit) {
    config.pool =
        vpn::Cidr::from_address(config.tun_ip, config.tun_prefix);
  }
  if (config.pool.prefix > 30) {
    throw std::runtime_error("--pool must contain at least two hosts (/30)");
  }
  if (!vpn::valid_interface_name(config.tun_name)) {
    throw std::runtime_error("invalid --tun name: " + config.tun_name);
  }

  return vpn::run_server(config);
}

int parse_client(std::vector<std::string> arguments) {
  vpn::ClientConfig config;
  bool have_server = false;

  for (std::size_t i = 1; i < arguments.size(); ++i) {
    const std::string key = arguments[i];
    if (key == "-h" || key == "--help") {
      print_usage();
      return 0;
    }
    if (key == "-v" || key == "--verbose") {
      config.verbose = true;
      vpn::set_verbose(true);
      continue;
    }
    if (key == "--install-routes") {
      config.install_routes = true;
      continue;
    }

    const Argument argument = split_argument(key, arguments, i);
    if (argument.key == "--server") {
      config.server = parse_endpoint_or_throw(argument.value, vpn::kDefaultPort,
                                              "--server");
      have_server = true;
    } else if (argument.key == "--tun") {
      config.tun_name = argument.value;
    } else if (argument.key == "--psk") {
      config.psk = argument.value;
    } else {
      throw std::runtime_error("unknown option: " + argument.key);
    }
  }

  if (!have_server) {
    throw std::runtime_error("client mode requires --server HOST:PORT");
  }
  if (!vpn::valid_interface_name(config.tun_name)) {
    throw std::runtime_error("invalid --tun name: " + config.tun_name);
  }

  return vpn::run_client(config);
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);
  std::signal(SIGPIPE, SIG_IGN);

  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }

  if (arguments.empty()) {
    print_usage();
    return 1;
  }
  if (arguments[0] == "-h" || arguments[0] == "--help") {
    print_usage();
    return 0;
  }
  if (arguments[0] == "--version") {
    std::cout << kProgramName << " " << kVersion << "\n";
    return 0;
  }

  const std::string command = arguments[0];
  arguments.erase(arguments.begin());

  try {
    if (command == "server") {
      return parse_server(arguments);
    }
    if (command == "client") {
      return parse_client(arguments);
    }
    throw std::runtime_error("unknown command: " + command);
  } catch (const std::exception& exception) {
    vpn::log_error("%s", exception.what());
    return 1;
  }
}
