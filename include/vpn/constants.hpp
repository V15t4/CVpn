#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace vpn {

// Wire protocol constants.
inline constexpr std::uint32_t kMagic = 0x56504E31u;  // "VPN1"
inline constexpr std::uint8_t kVersion = 1;

// Header is packed manually: magic(4) ver(1) type(1) flags(1) reserved(1)
//                               session(8) counter(8) payload_len(2) reserved(2)
inline constexpr std::size_t kHeaderSize = 28;

inline constexpr std::size_t kKeySize = 32;
inline constexpr std::size_t kTagSize = 16;
inline constexpr std::size_t kNonceSize = 12;
inline constexpr std::size_t kHandshakeNonceSize = 16;
inline constexpr std::size_t kProofSize = 16;

// Maximum UDP payload we are willing to process.
inline constexpr std::size_t kMaxPayload = 2048;
inline constexpr std::size_t kMaxPacketSize = kHeaderSize + kMaxPayload;

inline constexpr std::uint16_t kDefaultPort = 51820;
inline constexpr std::uint16_t kDefaultMtu = 1400;
inline constexpr std::uint8_t kDefaultPrefix = 24;

inline constexpr std::uint8_t kFlagEncrypted = 0x01;
inline constexpr std::uint8_t kFlagControl = 0x02;

// Timing defaults (seconds / milliseconds).
inline constexpr int kHandshakeIntervalMs = 1000;
inline constexpr int kHandshakeAttempts = 10;
inline constexpr int kKeepaliveIntervalSec = 15;
inline constexpr int kSessionTimeoutSec = 60;
inline constexpr int kTimestampToleranceSec = 120;

// AEAD nonce direction tag.
inline constexpr std::uint8_t kDirectionClientToServer = 1;
inline constexpr std::uint8_t kDirectionServerToClient = 2;

enum class PacketType : std::uint8_t {
  Hello = 1,
  HelloAck = 2,
  Data = 3,
  Keepalive = 4,
  Bye = 5,
};

const char* packet_type_name(PacketType type);

// Set to false by SIGINT/SIGTERM handlers (see main.cpp).
extern std::atomic<bool> g_running;

}  // namespace vpn
