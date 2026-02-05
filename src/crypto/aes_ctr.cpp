#include "tor/crypto/aes_ctr.hpp"
#include <openssl/evp.h>
#include <cstring>

namespace tor::crypto {

struct AesCtr128::Impl {
    EVP_CIPHER_CTX* ctx{nullptr};
    std::array<uint8_t, AES_KEY_LEN> key{};
    std::array<uint8_t, AES_CTR_NONCE_LEN> initial_nonce{};

    Impl() {
        ctx = EVP_CIPHER_CTX_new();
    }

    ~Impl() {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

AesCtr128::AesCtr128() : impl_(std::make_unique<Impl>()) {}
AesCtr128::~AesCtr128() = default;
AesCtr128::AesCtr128(AesCtr128&&) noexcept = default;
AesCtr128& AesCtr128::operator=(AesCtr128&&) noexcept = default;

std::expected<void, AesError> AesCtr128::init(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce
) {
    if (key.size() != AES_KEY_LEN) {
        return std::unexpected(AesError::InvalidKeyLength);
    }
    if (nonce.size() != AES_CTR_NONCE_LEN) {
        return std::unexpected(AesError::InvalidNonceLength);
    }

    if (!impl_ || !impl_->ctx) {
        return std::unexpected(AesError::OpenSSLError);
    }

    std::copy(key.begin(), key.end(), impl_->key.begin());
    std::copy(nonce.begin(), nonce.end(), impl_->initial_nonce.begin());

    if (EVP_EncryptInit_ex(impl_->ctx, EVP_aes_128_ctr(), nullptr,
                           impl_->key.data(), impl_->initial_nonce.data()) != 1) {
        return std::unexpected(AesError::OpenSSLError);
    }

    initialized_ = true;
    return {};
}

std::expected<void, AesError> AesCtr128::init(std::span<const uint8_t> key) {
    std::array<uint8_t, AES_CTR_NONCE_LEN> zero_nonce{};
    return init(key, zero_nonce);
}

void AesCtr128::reset() {
    if (impl_ && impl_->ctx && initialized_) {
        EVP_EncryptInit_ex(impl_->ctx, nullptr, nullptr,
                          impl_->key.data(), impl_->initial_nonce.data());
    }
}

std::expected<void, AesError> AesCtr128::process(std::span<uint8_t> data) {
    if (!initialized_) {
        return std::unexpected(AesError::EncryptionFailed);
    }

    int len;
    if (EVP_EncryptUpdate(impl_->ctx, data.data(), &len,
                          data.data(), static_cast<int>(data.size())) != 1) {
        return std::unexpected(AesError::EncryptionFailed);
    }

    return {};
}

std::expected<std::vector<uint8_t>, AesError>
AesCtr128::process(std::span<const uint8_t> data) {
    if (!initialized_) {
        return std::unexpected(AesError::EncryptionFailed);
    }

    std::vector<uint8_t> output(data.size());
    int len;

    if (EVP_EncryptUpdate(impl_->ctx, output.data(), &len,
                          data.data(), static_cast<int>(data.size())) != 1) {
        return std::unexpected(AesError::EncryptionFailed);
    }

    output.resize(len);
    return output;
}

std::expected<std::vector<uint8_t>, AesError>
aes_ctr_128(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> data
) {
    AesCtr128 cipher;
    auto result = cipher.init(key, nonce);
    if (!result) {
        return std::unexpected(result.error());
    }
    return cipher.process(data);
}

std::string aes_error_message(AesError err) {
    switch (err) {
        case AesError::InvalidKeyLength: return "Invalid key length";
        case AesError::InvalidNonceLength: return "Invalid nonce length";
        case AesError::EncryptionFailed: return "Encryption failed";
        case AesError::DecryptionFailed: return "Decryption failed";
        case AesError::OpenSSLError: return "OpenSSL error";
        default: return "Unknown AES error";
    }
}

}  // namespace tor::crypto
