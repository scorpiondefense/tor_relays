#include "tor/crypto/hash.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>
#include <stdexcept>

namespace tor::crypto {

// Sha1 implementation
struct Sha1::Impl {
    EVP_MD_CTX* ctx{nullptr};

    Impl() {
        ctx = EVP_MD_CTX_new();
        if (ctx) {
            EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
        }
    }

    ~Impl() {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }

    Impl(const Impl& other) {
        ctx = EVP_MD_CTX_new();
        if (ctx && other.ctx) {
            EVP_MD_CTX_copy_ex(ctx, other.ctx);
        }
    }
};

Sha1::Sha1() : impl_(std::make_unique<Impl>()) {}
Sha1::~Sha1() = default;
Sha1::Sha1(Sha1&&) noexcept = default;
Sha1& Sha1::operator=(Sha1&&) noexcept = default;

std::expected<void, HashError> Sha1::update(std::span<const uint8_t> data) {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }
    if (EVP_DigestUpdate(impl_->ctx, data.data(), data.size()) != 1) {
        return std::unexpected(HashError::UpdateFailed);
    }
    return {};
}

std::expected<std::array<uint8_t, SHA1_DIGEST_LEN>, HashError> Sha1::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    std::array<uint8_t, SHA1_DIGEST_LEN> result;
    unsigned int len = result.size();

    if (EVP_DigestFinal_ex(impl_->ctx, result.data(), &len) != 1) {
        return std::unexpected(HashError::FinalizeFailed);
    }

    // Reset for reuse
    EVP_DigestInit_ex(impl_->ctx, EVP_sha1(), nullptr);

    return result;
}

std::expected<Sha1, HashError> Sha1::clone() const {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    Sha1 cloned;
    if (EVP_MD_CTX_copy_ex(cloned.impl_->ctx, impl_->ctx) != 1) {
        return std::unexpected(HashError::OpenSSLError);
    }
    return cloned;
}

void Sha1::reset() {
    if (impl_ && impl_->ctx) {
        EVP_DigestInit_ex(impl_->ctx, EVP_sha1(), nullptr);
    }
}

// Sha256 implementation
struct Sha256::Impl {
    EVP_MD_CTX* ctx{nullptr};

    Impl() {
        ctx = EVP_MD_CTX_new();
        if (ctx) {
            EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        }
    }

    ~Impl() {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

Sha256::Sha256() : impl_(std::make_unique<Impl>()) {}
Sha256::~Sha256() = default;
Sha256::Sha256(Sha256&&) noexcept = default;
Sha256& Sha256::operator=(Sha256&&) noexcept = default;

std::expected<void, HashError> Sha256::update(std::span<const uint8_t> data) {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }
    if (EVP_DigestUpdate(impl_->ctx, data.data(), data.size()) != 1) {
        return std::unexpected(HashError::UpdateFailed);
    }
    return {};
}

std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError> Sha256::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    std::array<uint8_t, SHA256_DIGEST_LEN> result;
    unsigned int len = result.size();

    if (EVP_DigestFinal_ex(impl_->ctx, result.data(), &len) != 1) {
        return std::unexpected(HashError::FinalizeFailed);
    }

    EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr);
    return result;
}

std::expected<Sha256, HashError> Sha256::clone() const {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    Sha256 cloned;
    if (EVP_MD_CTX_copy_ex(cloned.impl_->ctx, impl_->ctx) != 1) {
        return std::unexpected(HashError::OpenSSLError);
    }
    return cloned;
}

void Sha256::reset() {
    if (impl_ && impl_->ctx) {
        EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr);
    }
}

// HmacSha256 implementation
struct HmacSha256::Impl {
    EVP_MAC* mac{nullptr};
    EVP_MAC_CTX* ctx{nullptr};
    std::vector<uint8_t> key;

    Impl() {
        mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    }

    ~Impl() {
        if (ctx) {
            EVP_MAC_CTX_free(ctx);
        }
        if (mac) {
            EVP_MAC_free(mac);
        }
    }
};

HmacSha256::HmacSha256() : impl_(std::make_unique<Impl>()) {}
HmacSha256::~HmacSha256() = default;
HmacSha256::HmacSha256(HmacSha256&&) noexcept = default;
HmacSha256& HmacSha256::operator=(HmacSha256&&) noexcept = default;

std::expected<void, HashError> HmacSha256::init(std::span<const uint8_t> key) {
    if (!impl_ || !impl_->mac) {
        return std::unexpected(HashError::OpenSSLError);
    }

    impl_->key.assign(key.begin(), key.end());

    if (impl_->ctx) {
        EVP_MAC_CTX_free(impl_->ctx);
    }
    impl_->ctx = EVP_MAC_CTX_new(impl_->mac);
    if (!impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(impl_->ctx, impl_->key.data(), impl_->key.size(), params) != 1) {
        return std::unexpected(HashError::OpenSSLError);
    }

    return {};
}

std::expected<void, HashError> HmacSha256::update(std::span<const uint8_t> data) {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }
    if (EVP_MAC_update(impl_->ctx, data.data(), data.size()) != 1) {
        return std::unexpected(HashError::UpdateFailed);
    }
    return {};
}

std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError> HmacSha256::finalize() {
    if (!impl_ || !impl_->ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    std::array<uint8_t, SHA256_DIGEST_LEN> result;
    size_t len = result.size();

    if (EVP_MAC_final(impl_->ctx, result.data(), &len, result.size()) != 1) {
        return std::unexpected(HashError::FinalizeFailed);
    }

    // Reinitialize for reuse
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_init(impl_->ctx, impl_->key.data(), impl_->key.size(), params);

    return result;
}

void HmacSha256::reset() {
    if (impl_ && impl_->ctx && !impl_->key.empty()) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
        params[1] = OSSL_PARAM_construct_end();
        EVP_MAC_init(impl_->ctx, impl_->key.data(), impl_->key.size(), params);
    }
}

// RunningDigest implementation
RunningDigest::RunningDigest() = default;
RunningDigest::~RunningDigest() = default;
RunningDigest::RunningDigest(RunningDigest&&) noexcept = default;
RunningDigest& RunningDigest::operator=(RunningDigest&&) noexcept = default;

std::expected<void, HashError> RunningDigest::init(std::span<const uint8_t> seed) {
    hasher_.reset();
    auto result = hasher_.update(seed);
    if (!result) {
        return result;
    }
    initialized_ = true;
    return {};
}

std::expected<uint32_t, HashError> RunningDigest::update_and_digest(
    std::span<const uint8_t> data
) {
    if (!initialized_) {
        return std::unexpected(HashError::OpenSSLError);
    }

    // Clone current state, update clone, get digest
    auto cloned = hasher_.clone();
    if (!cloned) {
        return std::unexpected(cloned.error());
    }

    auto upd = cloned->update(data);
    if (!upd) {
        return std::unexpected(upd.error());
    }

    auto digest = cloned->finalize();
    if (!digest) {
        return std::unexpected(digest.error());
    }

    // Update our state too
    (void)hasher_.update(data);

    // Return first 4 bytes as uint32
    return (static_cast<uint32_t>((*digest)[0]) << 24) |
           (static_cast<uint32_t>((*digest)[1]) << 16) |
           (static_cast<uint32_t>((*digest)[2]) << 8) |
           static_cast<uint32_t>((*digest)[3]);
}

std::expected<void, HashError> RunningDigest::update(std::span<const uint8_t> data) {
    if (!initialized_) {
        return std::unexpected(HashError::OpenSSLError);
    }
    return hasher_.update(data);
}

std::expected<RunningDigest, HashError> RunningDigest::clone() const {
    RunningDigest cloned;
    auto hasher_clone = hasher_.clone();
    if (!hasher_clone) {
        return std::unexpected(hasher_clone.error());
    }
    cloned.hasher_ = std::move(*hasher_clone);
    cloned.initialized_ = initialized_;
    return cloned;
}

// Convenience functions
std::expected<std::array<uint8_t, SHA1_DIGEST_LEN>, HashError>
sha1(std::span<const uint8_t> data) {
    Sha1 hasher;
    auto result = hasher.update(data);
    if (!result) {
        return std::unexpected(result.error());
    }
    return hasher.finalize();
}

std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
sha256(std::span<const uint8_t> data) {
    Sha256 hasher;
    auto result = hasher.update(data);
    if (!result) {
        return std::unexpected(result.error());
    }
    return hasher.finalize();
}

std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    HmacSha256 hmac;
    auto init_result = hmac.init(key);
    if (!init_result) {
        return std::unexpected(init_result.error());
    }

    auto update_result = hmac.update(data);
    if (!update_result) {
        return std::unexpected(update_result.error());
    }

    return hmac.finalize();
}

std::expected<std::vector<uint8_t>, HashError>
hkdf_sha256(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info,
    size_t length
) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        return std::unexpected(HashError::OpenSSLError);
    }

    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        return std::unexpected(HashError::OpenSSLError);
    }

    // OpenSSL requires non-NULL pointers for octet string params,
    // even when the length is 0. Use a dummy byte for empty spans.
    uint8_t dummy = 0;
    auto safe_ptr = [&](std::span<const uint8_t> s) -> uint8_t* {
        return s.empty() ? &dummy : const_cast<uint8_t*>(s.data());
    };

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_octet_string("key",
        safe_ptr(ikm), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string("salt",
        safe_ptr(salt), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string("info",
        safe_ptr(info), info.size());
    params[4] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> output(length);

    if (EVP_KDF_derive(ctx, output.data(), length, params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        return std::unexpected(HashError::OpenSSLError);
    }

    EVP_KDF_CTX_free(ctx);
    return output;
}

std::expected<std::vector<uint8_t>, HashError>
hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info,
    size_t length
) {
    // Empty salt
    return hkdf_sha256(std::span<const uint8_t>{}, ikm, info, length);
}

// Hex encoding
std::string to_hex(std::span<const uint8_t> data) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

std::expected<std::vector<uint8_t>, HashError> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return std::unexpected(HashError::InvalidLength);
    }

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            uint8_t nibble;
            if (c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                nibble = 10 + (c - 'a');
            } else if (c >= 'A' && c <= 'F') {
                nibble = 10 + (c - 'A');
            } else {
                return std::unexpected(HashError::InvalidLength);
            }
            byte = (byte << 4) | nibble;
        }
        result.push_back(byte);
    }

    return result;
}

// Base64 encoding
std::string to_base64(std::span<const uint8_t> data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);

    BUF_MEM* ptr;
    BIO_get_mem_ptr(b64, &ptr);

    std::string result(ptr->data, ptr->length);
    BIO_free_all(b64);

    return result;
}

std::expected<std::vector<uint8_t>, HashError> from_base64(const std::string& b64) {
    BIO* bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    BIO* b64_bio = BIO_new(BIO_f_base64());
    bio = BIO_push(b64_bio, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> result(b64.size());
    int len = BIO_read(bio, result.data(), static_cast<int>(result.size()));
    BIO_free_all(bio);

    if (len < 0) {
        return std::unexpected(HashError::InvalidLength);
    }

    result.resize(len);
    return result;
}

// Utility
std::string hash_error_message(HashError err) {
    switch (err) {
        case HashError::InvalidLength: return "Invalid length";
        case HashError::UpdateFailed: return "Update failed";
        case HashError::FinalizeFailed: return "Finalize failed";
        case HashError::OpenSSLError: return "OpenSSL error";
        default: return "Unknown hash error";
    }
}

// Constant-time comparison
bool constant_time_compare(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
) {
    if (a.size() != b.size()) {
        return false;
    }

    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

}  // namespace tor::crypto
