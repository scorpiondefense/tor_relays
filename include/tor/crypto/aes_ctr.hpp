#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

namespace tor::crypto {

// AES-128-CTR constants
constexpr size_t AES_KEY_LEN = 16;
constexpr size_t AES_BLOCK_LEN = 16;
constexpr size_t AES_CTR_NONCE_LEN = 16;

// AES error types
enum class AesError {
    InvalidKeyLength,
    InvalidNonceLength,
    EncryptionFailed,
    DecryptionFailed,
    OpenSSLError,
};

// AES-128-CTR stream cipher for relay cell encryption
class AesCtr128 {
public:
    AesCtr128();
    ~AesCtr128();

    // Disable copying, allow moving
    AesCtr128(const AesCtr128&) = delete;
    AesCtr128& operator=(const AesCtr128&) = delete;
    AesCtr128(AesCtr128&&) noexcept;
    AesCtr128& operator=(AesCtr128&&) noexcept;

    // Initialize cipher with key and initial counter (nonce)
    [[nodiscard]] std::expected<void, AesError> init(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce
    );

    // Initialize with key, starting counter at zero
    [[nodiscard]] std::expected<void, AesError> init(std::span<const uint8_t> key);

    // Reset counter to initial value (for new direction)
    void reset();

    // Encrypt/decrypt in place (CTR mode is symmetric)
    [[nodiscard]] std::expected<void, AesError> process(std::span<uint8_t> data);

    // Encrypt/decrypt returning new buffer
    [[nodiscard]] std::expected<std::vector<uint8_t>, AesError>
    process(std::span<const uint8_t> data);

    // Check if initialized
    [[nodiscard]] bool is_initialized() const { return initialized_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool initialized_{false};
};

// Convenience functions
[[nodiscard]] std::expected<std::vector<uint8_t>, AesError>
aes_ctr_128(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> data
);

// Utility
[[nodiscard]] std::string aes_error_message(AesError err);

}  // namespace tor::crypto
