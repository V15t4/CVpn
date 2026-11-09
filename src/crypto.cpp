#include "vpn/crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>

namespace vpn {
namespace {

std::string openssl_errors() {
  std::string result;
  unsigned long code = 0;
  while ((code = ERR_get_error()) != 0) {
    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    if (!result.empty()) {
      result += "; ";
    }
    result += buffer;
  }
  return result.empty() ? "unknown OpenSSL error" : result;
}

[[noreturn]] void throw_openssl(const char* what) {
  throw std::runtime_error(std::string(what) + ": " + openssl_errors());
}

void append(Bytes& out, const std::uint8_t* data, std::size_t len) {
  out.insert(out.end(), data, data + len);
}

}  // namespace

void random_bytes(std::uint8_t* out, std::size_t len) {
  while (len > 0) {
    const int chunk = static_cast<int>(len > 1024 ? 1024 : len);
    if (RAND_bytes(out, chunk) != 1) {
      throw_openssl("RAND_bytes failed");
    }
    out += chunk;
    len -= static_cast<std::size_t>(chunk);
  }
}

Bytes random_bytes(std::size_t len) {
  Bytes out(len);
  if (len > 0) {
    random_bytes(out.data(), len);
  }
  return out;
}

Key32 sha256(const std::uint8_t* data, std::size_t len) {
  Key32 out{};
  unsigned int out_len = 0;
  if (EVP_Digest(data, len, out.data(), &out_len, EVP_sha256(), nullptr) != 1 ||
      out_len != out.size()) {
    throw_openssl("SHA-256 failed");
  }
  return out;
}

Key32 hkdf_sha256(const std::uint8_t* ikm, std::size_t ikm_len,
                  const std::uint8_t* salt, std::size_t salt_len,
                  const std::string& info) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  if (kdf == nullptr) {
    throw_openssl("EVP_KDF_fetch(HKDF) failed");
  }

  EVP_KDF_CTX* context = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (context == nullptr) {
    throw_openssl("EVP_KDF_CTX_new failed");
  }

  char digest[] = "SHA256";
  auto* key_arg = const_cast<std::uint8_t*>(ikm);
  auto* salt_arg = const_cast<std::uint8_t*>(salt);
  auto* info_arg = const_cast<char*>(info.data());

  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key_arg, ikm_len);
  params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt_arg, salt_len);
  params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info_arg, info.size());
  params[4] = OSSL_PARAM_construct_end();

  Key32 out{};
  const int rc = EVP_KDF_derive(context, out.data(), out.size(), params);
  EVP_KDF_CTX_free(context);
  if (rc != 1) {
    throw_openssl("HKDF derive failed");
  }
  return out;
}

Key32 hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                  const std::uint8_t* data, std::size_t len) {
  Key32 out{};
  unsigned int out_len = 0;
  if (HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, len, out.data(),
           &out_len) == nullptr ||
      out_len != out.size()) {
    throw_openssl("HMAC-SHA256 failed");
  }
  return out;
}

Proof16 compute_proof(const Key32& key, const Bytes& transcript) {
  const Key32 mac = hmac_sha256(key.data(), key.size(), transcript.data(),
                                transcript.size());
  Proof16 proof{};
  std::memcpy(proof.data(), mac.data(), proof.size());
  return proof;
}

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                         std::size_t len) {
  if (len == 0) {
    return true;
  }
  return CRYPTO_memcmp(a, b, len) == 0;
}

X25519KeyPair::~X25519KeyPair() {
  if (pkey_ != nullptr) {
    EVP_PKEY_free(static_cast<EVP_PKEY*>(pkey_));
  }
}

X25519KeyPair::X25519KeyPair(X25519KeyPair&& other) noexcept
    : pkey_(other.pkey_) {
  other.pkey_ = nullptr;
}

X25519KeyPair& X25519KeyPair::operator=(X25519KeyPair&& other) noexcept {
  if (this != &other) {
    if (pkey_ != nullptr) {
      EVP_PKEY_free(static_cast<EVP_PKEY*>(pkey_));
    }
    pkey_ = other.pkey_;
    other.pkey_ = nullptr;
  }
  return *this;
}

X25519KeyPair X25519KeyPair::generate() {
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (context == nullptr) {
    throw_openssl("EVP_PKEY_CTX_new_id(X25519) failed");
  }

  EVP_PKEY* key = nullptr;
  const bool ok = EVP_PKEY_keygen_init(context) == 1 &&
                  EVP_PKEY_keygen(context, &key) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok || key == nullptr) {
    throw_openssl("X25519 key generation failed");
  }
  return X25519KeyPair(key);
}

Key32 X25519KeyPair::public_key() const {
  if (pkey_ == nullptr) {
    throw std::runtime_error("X25519KeyPair: no private key");
  }
  Key32 out{};
  std::size_t len = out.size();
  if (EVP_PKEY_get_raw_public_key(static_cast<EVP_PKEY*>(pkey_), out.data(),
                                  &len) != 1 ||
      len != out.size()) {
    throw_openssl("X25519 public key export failed");
  }
  return out;
}

bool X25519KeyPair::derive(const Key32& peer_public, Key32& shared) const {
  if (pkey_ == nullptr) {
    return false;
  }

  EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peer_public.data(), peer_public.size());
  if (peer == nullptr) {
    ERR_clear_error();
    return false;
  }

  EVP_PKEY_CTX* context =
      EVP_PKEY_CTX_new(static_cast<EVP_PKEY*>(pkey_), nullptr);
  bool ok = context != nullptr;
  if (ok) {
    ok = EVP_PKEY_derive_init(context) == 1 &&
         EVP_PKEY_derive_set_peer(context, peer) == 1;
  }

  std::size_t len = shared.size();
  if (ok) {
    ok = EVP_PKEY_derive(context, shared.data(), &len) == 1 &&
         len == shared.size();
  }

  EVP_PKEY_CTX_free(context);
  EVP_PKEY_free(peer);
  if (!ok) {
    ERR_clear_error();
    return false;
  }
  return true;
}

SessionKeys derive_session_keys(const Key32& shared,
                                const Nonce16& client_nonce,
                                const Nonce16& server_nonce,
                                const std::string& psk) {
  Bytes salt;
  salt.reserve(client_nonce.size() + server_nonce.size() + kKeySize);
  append(salt, client_nonce.data(), client_nonce.size());
  append(salt, server_nonce.data(), server_nonce.size());
  if (!psk.empty()) {
    const Key32 psk_digest =
        sha256(reinterpret_cast<const std::uint8_t*>(psk.data()), psk.size());
    append(salt, psk_digest.data(), psk_digest.size());
  }

  const Key32 salt_digest = sha256(salt.data(), salt.size());

  SessionKeys keys;
  keys.client_to_server =
      hkdf_sha256(shared.data(), shared.size(), salt_digest.data(),
                  salt_digest.size(), "minevpn v1 client-to-server");
  keys.server_to_client =
      hkdf_sha256(shared.data(), shared.size(), salt_digest.data(),
                  salt_digest.size(), "minevpn v1 server-to-client");
  keys.confirm =
      hkdf_sha256(shared.data(), shared.size(), salt_digest.data(),
                  salt_digest.size(), "minevpn v1 confirm");
  return keys;
}

std::array<std::uint8_t, kNonceSize> build_nonce(std::uint8_t direction,
                                                 std::uint64_t counter) {
  std::array<std::uint8_t, kNonceSize> nonce{};
  nonce[3] = direction;
  for (int i = 0; i < 8; ++i) {
    nonce[4 + i] = static_cast<std::uint8_t>(
        (counter >> static_cast<unsigned>(56 - 8 * i)) & 0xFFu);
  }
  return nonce;
}

bool aead_encrypt(const Key32& key, const std::uint8_t* nonce,
                  const std::uint8_t* aad, std::size_t aad_len,
                  const std::uint8_t* plaintext, std::size_t plaintext_len,
                  Bytes& out) {
  out.clear();
  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  if (context == nullptr) {
    throw_openssl("EVP_CIPHER_CTX_new failed");
  }

  bool ok = EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr,
                               nullptr) == 1;
  ok = ok &&
       EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, kNonceSize,
                           nullptr) == 1;
  ok = ok && EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce) == 1;

  int len = 0;
  if (ok && aad_len > 0) {
    ok = EVP_EncryptUpdate(context, nullptr, &len, aad,
                           static_cast<int>(aad_len)) == 1;
  }

  out.resize(plaintext_len + kTagSize);
  int written = 0;
  if (ok && plaintext_len > 0) {
    ok = EVP_EncryptUpdate(context, out.data(), &written, plaintext,
                           static_cast<int>(plaintext_len)) == 1;
  }

  int final_len = 0;
  if (ok) {
    ok = EVP_EncryptFinal_ex(context, out.data() + written, &final_len) == 1;
  }
  written += final_len;

  if (ok) {
    ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, kTagSize,
                             out.data() + written) == 1;
  }

  EVP_CIPHER_CTX_free(context);
  if (!ok) {
    out.clear();
    return false;
  }
  out.resize(static_cast<std::size_t>(written) + kTagSize);
  return true;
}

bool aead_decrypt(const Key32& key, const std::uint8_t* nonce,
                  const std::uint8_t* aad, std::size_t aad_len,
                  const std::uint8_t* ciphertext_with_tag,
                  std::size_t ciphertext_len, Bytes& out) {
  out.clear();
  if (ciphertext_len < kTagSize) {
    return false;
  }

  const std::size_t body_len = ciphertext_len - kTagSize;
  const std::uint8_t* tag = ciphertext_with_tag + body_len;

  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  if (context == nullptr) {
    throw_openssl("EVP_CIPHER_CTX_new failed");
  }

  bool ok = EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr,
                               nullptr) == 1;
  ok = ok &&
       EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, kNonceSize,
                           nullptr) == 1;
  ok = ok && EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce) == 1;

  int len = 0;
  if (ok && aad_len > 0) {
    ok = EVP_DecryptUpdate(context, nullptr, &len, aad,
                           static_cast<int>(aad_len)) == 1;
  }

  out.resize(body_len);
  int written = 0;
  if (ok && body_len > 0) {
    ok = EVP_DecryptUpdate(context, out.data(), &written, ciphertext_with_tag,
                           static_cast<int>(body_len)) == 1;
  }

  if (ok) {
    ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, kTagSize,
                             const_cast<std::uint8_t*>(tag)) == 1;
  }

  int final_len = 0;
  if (ok) {
    ok = EVP_DecryptFinal_ex(context, out.data() + written, &final_len) == 1;
  }
  written += final_len;

  EVP_CIPHER_CTX_free(context);
  if (!ok) {
    out.clear();
    return false;
  }
  out.resize(static_cast<std::size_t>(written));
  return true;
}

}  // namespace vpn
