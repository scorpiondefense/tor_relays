#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace tor::crypto {

// Hash sizes
constexpr size_t SHA1_DIGEST_LEN = 20;
constexpr size_t SHA256_DIGEST_LEN = 32;

// Hash error types
enum class HashError {
    InvalidLength,
    UpdateFailed,
    FinalizeFailed,
    OpenSSLError,
};

// SHA-1 hash (used for relay cell digest)
class Sha1 {
public:
    Sha1();
    ~Sha1();

    // Disable copying, allow moving
    Sha1(const Sha1&) = delete;
    Sha1& operator=(const Sha1&) = delete;
    Sha1(Sha1&&) noexcept;
    Sha1& operator=(Sha1&&) noexcept;

    // Update with data
    [[nodiscard]] std::expected<void, HashError> update(std::span<const uint8_t> data);

    // Finalize and get digest (resets internal state)
    [[nodiscard]] std::expected<std::array<uint8_t, SHA1_DIGEST_LEN>, HashError> finalize();

    // Clone current state (for running digest)
    [[nodiscard]] std::expected<Sha1, HashError> clone() const;

    // Reset to initial state
    void reset();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// SHA-256 hash
class Sha256 {
public:
    Sha256();
    ~Sha256();

    // Disable copying, allow moving
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    Sha256(Sha256&&) noexcept;
    Sha256& operator=(Sha256&&) noexcept;

    // Update with data
    [[nodiscard]] std::expected<void, HashError> update(std::span<const uint8_t> data);

    // Finalize and get digest
    [[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError> finalize();

    // Clone current state
    [[nodiscard]] std::expected<Sha256, HashError> clone() const;

    // Reset to initial state
    void reset();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// HMAC-SHA256
class HmacSha256 {
public:
    HmacSha256();
    ~HmacSha256();

    // Disable copying, allow moving
    HmacSha256(const HmacSha256&) = delete;
    HmacSha256& operator=(const HmacSha256&) = delete;
    HmacSha256(HmacSha256&&) noexcept;
    HmacSha256& operator=(HmacSha256&&) noexcept;

    // Initialize with key
    [[nodiscard]] std::expected<void, HashError> init(std::span<const uint8_t> key);

    // Update with data
    [[nodiscard]] std::expected<void, HashError> update(std::span<const uint8_t> data);

    // Finalize and get MAC
    [[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError> finalize();

    // Reset with same key
    void reset();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Running digest for relay cells (maintains state across multiple cells)
class RunningDigest {
public:
    RunningDigest();
    ~RunningDigest();

    // Disable copying, allow moving
    RunningDigest(const RunningDigest&) = delete;
    RunningDigest& operator=(const RunningDigest&) = delete;
    RunningDigest(RunningDigest&&) noexcept;
    RunningDigest& operator=(RunningDigest&&) noexcept;

    // Initialize with seed (first 20 bytes from key material)
    [[nodiscard]] std::expected<void, HashError> init(std::span<const uint8_t> seed);

    // Update digest with relay cell payload and get first 4 bytes
    [[nodiscard]] std::expected<uint32_t, HashError> update_and_digest(
        std::span<const uint8_t> data
    );

    // Just update without computing intermediate digest
    [[nodiscard]] std::expected<void, HashError> update(std::span<const uint8_t> data);

    // Clone current state
    [[nodiscard]] std::expected<RunningDigest, HashError> clone() const;

private:
    Sha1 hasher_;
    bool initialized_{false};
};

// Convenience functions

// One-shot SHA-1
[[nodiscard]] std::expected<std::array<uint8_t, SHA1_DIGEST_LEN>, HashError>
sha1(std::span<const uint8_t> data);

// One-shot SHA-256
[[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
sha256(std::span<const uint8_t> data);

// One-shot HMAC-SHA256
[[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data);

// HKDF-SHA256 (RFC 5869)
[[nodiscard]] std::expected<std::vector<uint8_t>, HashError>
hkdf_sha256(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info,
    size_t length
);

// HKDF-SHA256 with empty salt
[[nodiscard]] std::expected<std::vector<uint8_t>, HashError>
hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info,
    size_t length
);

// Hex encoding/decoding
[[nodiscard]] std::string to_hex(std::span<const uint8_t> data);
[[nodiscard]] std::expected<std::vector<uint8_t>, HashError> from_hex(const std::string& hex);

// Base64 encoding/decoding
[[nodiscard]] std::string to_base64(std::span<const uint8_t> data);
[[nodiscard]] std::expected<std::vector<uint8_t>, HashError> from_base64(const std::string& b64);

// Utility
[[nodiscard]] std::string hash_error_message(HashError err);

// Constant-time comparison
[[nodiscard]] bool constant_time_compare(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
);

}  // namespace tor::crypto
