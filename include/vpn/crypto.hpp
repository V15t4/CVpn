#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "vpn/constants.hpp"

namespace vpn {

using Bytes = std::vector<std::uint8_t>;
using Key32 = std::array<std::uint8_t, kKeySize>;
using Nonce16 = std::array<std::uint8_t, kHandshakeNonceSize>;
using Proof16 = std::array<std::uint8_t, kProofSize>;

struct SessionKeys {
  Key32 client_to_server{};
  Key32 server_to_client{};
  Key32 confirm{};
};

// Fills `out` with cryptographically secure random bytes. Throws on failure.
void random_bytes(std::uint8_t* out, std::size_t len);
Bytes random_bytes(std::size_t len);

Key32 sha256(const std::uint8_t* data, std::size_t len);

// HKDF-SHA256 (extract + expand), always produces one 32-byte key.
Key32 hkdf_sha256(const std::uint8_t* ikm, std::size_t ikm_len,
                  const std::uint8_t* salt, std::size_t salt_len,
                  const std::string& info);

Key32 hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                  const std::uint8_t* data, std::size_t len);

// First 16 bytes of HMAC-SHA256(key, transcript).
Proof16 compute_proof(const Key32& key, const Bytes& transcript);

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                         std::size_t len);

class X25519KeyPair {
 public:
  X25519KeyPair() = default;
  ~X25519KeyPair();

  X25519KeyPair(const X25519KeyPair&) = delete;
  X25519KeyPair& operator=(const X25519KeyPair&) = delete;
  X25519KeyPair(X25519KeyPair&& other) noexcept;
  X25519KeyPair& operator=(X25519KeyPair&& other) noexcept;

  static X25519KeyPair generate();

  bool valid() const { return pkey_ != nullptr; }
  Key32 public_key() const;

  // X25519 ECDH. Returns false for an invalid peer key or all-zero secret.
  bool derive(const Key32& peer_public, Key32& shared) const;

 private:
  explicit X25519KeyPair(void* pkey) : pkey_(pkey) {}

  void* pkey_ = nullptr;
};

// Derives directional keys from the X25519 shared secret. A non-empty PSK is
// mixed into the HKDF salt, which also authenticates the server to the client.
SessionKeys derive_session_keys(const Key32& shared,
                                const Nonce16& client_nonce,
                                const Nonce16& server_nonce,
                                const std::string& psk);

std::array<std::uint8_t, kNonceSize> build_nonce(std::uint8_t direction,
                                                 std::uint64_t counter);

// AEAD_CHACHA20_POLY1305. `out` receives ciphertext followed by the 16-byte tag.
bool aead_encrypt(const Key32& key, const std::uint8_t* nonce,
                  const std::uint8_t* aad, std::size_t aad_len,
                  const std::uint8_t* plaintext, std::size_t plaintext_len,
                  Bytes& out);

bool aead_decrypt(const Key32& key, const std::uint8_t* nonce,
                  const std::uint8_t* aad, std::size_t aad_len,
                  const std::uint8_t* ciphertext_with_tag,
                  std::size_t ciphertext_len, Bytes& out);

}  // namespace vpn
