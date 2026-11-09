#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "vpn/crypto.hpp"
#include "vpn/network.hpp"
#include "vpn/routes.hpp"

namespace vpn {

// Sliding-window replay protection (64 packets).
class ReplayWindow {
 public:
  bool accept(std::uint64_t sequence);
  std::uint64_t highest() const { return highest_; }
  void reset() {
    highest_ = 0;
    bitmap_ = 0;
  }

 private:
  std::uint64_t highest_ = 0;
  std::uint64_t bitmap_ = 0;
};

struct Session {
  std::uint64_t id = 0;
  Endpoint endpoint;
  std::uint32_t virtual_ip = 0;  // network byte order
  SessionKeys keys;

  std::uint64_t tx_counter = 0;
  ReplayWindow replay;
  std::uint64_t rx_packets = 0;
  std::uint64_t tx_packets = 0;
  std::uint64_t rx_bytes = 0;
  std::uint64_t tx_bytes = 0;

  std::chrono::steady_clock::time_point created{};
  std::chrono::steady_clock::time_point last_seen{};
};

// Allocates host addresses from an IPv4 CIDR, excluding the server address.
class IpPool {
 public:
  IpPool(const Cidr& pool, std::uint32_t exclude_network_order);

  std::uint32_t allocate();  // network byte order; 0 when exhausted
  void release(std::uint32_t address_network_order);
  std::size_t capacity() const;
  std::size_t used() const { return used_.size(); }

 private:
  std::uint32_t first_ = 0;  // host byte order, inclusive
  std::uint32_t last_ = 0;   // host byte order, inclusive
  std::uint32_t exclude_ = 0;
  std::uint32_t next_ = 0;
  std::size_t capacity_ = 0;
  std::set<std::uint32_t> used_;
};

class SessionStore {
 public:
  SessionStore(const Cidr& pool, std::uint32_t server_ip_network_order);

  // Returns nullptr when the pool is exhausted.
  Session* create(const Endpoint& endpoint, const SessionKeys& keys);

  Session* by_id(std::uint64_t id);
  const Session* by_id(std::uint64_t id) const;
  Session* by_endpoint(const Endpoint& endpoint);
  Session* by_vip(std::uint32_t virtual_ip);

  void remove(std::uint64_t id);

  // Removes sessions that have been idle for longer than `timeout`.
  std::vector<std::uint64_t> expire(std::chrono::steady_clock::time_point now,
                                    std::chrono::seconds timeout);

  std::size_t size() const { return sessions_.size(); }

 private:
  std::uint64_t new_id() const;

  IpPool pool_;
  std::unordered_map<std::uint64_t, std::unique_ptr<Session>> sessions_;
  std::unordered_map<std::string, std::uint64_t> endpoint_index_;
  std::unordered_map<std::uint32_t, std::uint64_t> vip_index_;
};

}  // namespace vpn
