#include "vpn/session.hpp"

#include <arpa/inet.h>

#include <cstring>
#include <utility>

namespace vpn {

bool ReplayWindow::accept(std::uint64_t sequence) {
  if (sequence == 0) {
    return false;
  }

  if (sequence > highest_) {
    const std::uint64_t shift = sequence - highest_;
    if (shift >= 64) {
      bitmap_ = 0;
    } else {
      bitmap_ <<= shift;
    }
    bitmap_ |= 1;
    highest_ = sequence;
    return true;
  }

  const std::uint64_t difference = highest_ - sequence;
  if (difference >= 64) {
    return false;
  }

  const std::uint64_t bit = 1ULL << difference;
  if ((bitmap_ & bit) != 0) {
    return false;
  }
  bitmap_ |= bit;
  return true;
}

IpPool::IpPool(const Cidr& pool, std::uint32_t exclude_network_order) {
  exclude_ = ntohl(exclude_network_order);

  if (pool.prefix >= 31) {
    capacity_ = 0;
    return;
  }

  const std::uint32_t network = pool.network;
  const std::uint32_t broadcast = network | ~pool.mask();
  first_ = network + 1;
  last_ = broadcast - 1;
  next_ = first_;

  const std::uint64_t total =
      static_cast<std::uint64_t>(last_) - first_ + 1;
  capacity_ = static_cast<std::size_t>(
      total - (exclude_ >= first_ && exclude_ <= last_ ? 1 : 0));
}

std::uint32_t IpPool::allocate() {
  if (capacity_ == 0) {
    return 0;
  }

  const std::uint64_t total = static_cast<std::uint64_t>(last_) - first_ + 1;
  for (std::uint64_t step = 0; step < total; ++step) {
    const std::uint32_t candidate = next_;
    ++next_;
    if (next_ > last_) {
      next_ = first_;
    }

    if (candidate == exclude_ || used_.count(candidate) != 0) {
      continue;
    }

    used_.insert(candidate);
    return htonl(candidate);
  }

  return 0;
}

void IpPool::release(std::uint32_t address_network_order) {
  used_.erase(ntohl(address_network_order));
}

std::size_t IpPool::capacity() const { return capacity_; }

SessionStore::SessionStore(const Cidr& pool,
                           std::uint32_t server_ip_network_order)
    : pool_(pool, server_ip_network_order) {}

std::uint64_t SessionStore::new_id() const {
  for (;;) {
    std::uint64_t candidate = 0;
    random_bytes(reinterpret_cast<std::uint8_t*>(&candidate),
                 sizeof(candidate));
    if (candidate != 0 && sessions_.find(candidate) == sessions_.end()) {
      return candidate;
    }
  }
}

Session* SessionStore::create(const Endpoint& endpoint,
                              const SessionKeys& keys) {
  const std::uint32_t virtual_ip = pool_.allocate();
  if (virtual_ip == 0) {
    return nullptr;
  }

  auto session = std::make_unique<Session>();
  session->id = new_id();
  session->endpoint = endpoint;
  session->virtual_ip = virtual_ip;
  session->keys = keys;
  session->created = std::chrono::steady_clock::now();
  session->last_seen = session->created;

  const std::uint64_t id = session->id;
  Session* raw = session.get();
  sessions_.emplace(id, std::move(session));
  endpoint_index_[endpoint.key()] = id;
  vip_index_[virtual_ip] = id;
  return raw;
}

Session* SessionStore::by_id(std::uint64_t id) {
  const auto iterator = sessions_.find(id);
  return iterator == sessions_.end() ? nullptr : iterator->second.get();
}

const Session* SessionStore::by_id(std::uint64_t id) const {
  const auto iterator = sessions_.find(id);
  return iterator == sessions_.end() ? nullptr : iterator->second.get();
}

Session* SessionStore::by_endpoint(const Endpoint& endpoint) {
  const auto iterator = endpoint_index_.find(endpoint.key());
  if (iterator == endpoint_index_.end()) {
    return nullptr;
  }
  return by_id(iterator->second);
}

Session* SessionStore::by_vip(std::uint32_t virtual_ip) {
  const auto iterator = vip_index_.find(virtual_ip);
  if (iterator == vip_index_.end()) {
    return nullptr;
  }
  return by_id(iterator->second);
}

void SessionStore::remove(std::uint64_t id) {
  const auto iterator = sessions_.find(id);
  if (iterator == sessions_.end()) {
    return;
  }

  const std::uint32_t virtual_ip = iterator->second->virtual_ip;
  const std::string endpoint_key = iterator->second->endpoint.key();

  sessions_.erase(iterator);
  pool_.release(virtual_ip);

  const auto vip_iterator = vip_index_.find(virtual_ip);
  if (vip_iterator != vip_index_.end() && vip_iterator->second == id) {
    vip_index_.erase(vip_iterator);
  }

  const auto endpoint_iterator = endpoint_index_.find(endpoint_key);
  if (endpoint_iterator != endpoint_index_.end() &&
      endpoint_iterator->second == id) {
    endpoint_index_.erase(endpoint_iterator);
  }
}

std::vector<std::uint64_t> SessionStore::expire(
    std::chrono::steady_clock::time_point now, std::chrono::seconds timeout) {
  std::vector<std::uint64_t> expired;
  for (const auto& entry : sessions_) {
    if (now - entry.second->last_seen > timeout) {
      expired.push_back(entry.first);
    }
  }
  for (const std::uint64_t id : expired) {
    remove(id);
  }
  return expired;
}

}  // namespace vpn
