#include "vpn/constants.hpp"

#include <atomic>

namespace vpn {

std::atomic<bool> g_running{true};

const char* packet_type_name(PacketType type) {
  switch (type) {
    case PacketType::Hello:
      return "HELLO";
    case PacketType::HelloAck:
      return "HELLO_ACK";
    case PacketType::Data:
      return "DATA";
    case PacketType::Keepalive:
      return "KEEPALIVE";
    case PacketType::Bye:
      return "BYE";
  }
  return "UNKNOWN";
}

}  // namespace vpn
