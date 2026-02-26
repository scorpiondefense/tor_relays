#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace tor::crypto {

// Key sizes
constexpr size_t ED25519_PUBLIC_KEY_LEN = 32;
constexpr size_t ED25519_SECRET_KEY_LEN = 64;  // Seed + public key
constexpr size_t ED25519_SEED_LEN = 32;
constexpr size_t ED25519_SIGNATURE_LEN = 64;
constexpr size_t CURVE25519_KEY_LEN = 32;
constexpr size_t RSA_KEY_LEN = 1024 / 8;  // 1024-bit for legacy
constexpr size_t DIGEST_LEN = 20;  // SHA-1 fingerprint

// Error types
enum class KeyError {
    GenerationFailed,
    InvalidKeyLength,
    InvalidKey,
    SigningFailed,
    VerificationFailed,
    DerivationFailed,
    ParseError,
    OpenSSLError,
};

// Ed25519 public key (identity key)
class Ed25519PublicKey {
public:
    static constexpr size_t SIZE = ED25519_PUBLIC_KEY_LEN;

    Ed25519PublicKey() = default;
    explicit Ed25519PublicKey(std::array<uint8_t, SIZE> data);
    explicit Ed25519PublicKey(std::span<const uint8_t> data);

    [[nodiscard]] const std::array<uint8_t, SIZE>& data() const { return data_; }
    [[nodiscard]] std::span<const uint8_t> as_span() const { return data_; }
    [[nodiscard]] std::string to_base64() const;
    [[nodiscard]] std::string fingerprint() const;  // SHA-256 hash in hex

    [[nodiscard]] bool verify(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature
    ) const;

    [[nodiscard]] static std::expected<Ed25519PublicKey, KeyError>
    from_base64(const std::string& encoded);

    bool operator==(const Ed25519PublicKey&) const = default;

private:
    std::array<uint8_t, SIZE> data_{};
};

// Ed25519 secret key (identity key pair)
class Ed25519SecretKey {
public:
    static constexpr size_t SIZE = ED25519_SECRET_KEY_LEN;
    static constexpr size_t SEED_SIZE = ED25519_SEED_LEN;

    Ed25519SecretKey() = default;
    ~Ed25519SecretKey();

    // Disable copying, allow moving
    Ed25519SecretKey(const Ed25519SecretKey&) = delete;
    Ed25519SecretKey& operator=(const Ed25519SecretKey&) = delete;
    Ed25519SecretKey(Ed25519SecretKey&&) noexcept;
    Ed25519SecretKey& operator=(Ed25519SecretKey&&) noexcept;

    [[nodiscard]] static std::expected<Ed25519SecretKey, KeyError> generate();
    [[nodiscard]] static std::expected<Ed25519SecretKey, KeyError>
    from_seed(std::span<const uint8_t> seed);

    [[nodiscard]] const Ed25519PublicKey& public_key() const { return public_key_; }
    [[nodiscard]] std::span<const uint8_t> seed() const;

    [[nodiscard]] std::expected<std::array<uint8_t, ED25519_SIGNATURE_LEN>, KeyError>
    sign(std::span<const uint8_t> message) const;

private:
    std::array<uint8_t, SIZE> data_{};
    Ed25519PublicKey public_key_;
    bool initialized_{false};

    void clear();
};

// Curve25519 public key (onion key for ntor)
class Curve25519PublicKey {
public:
    static constexpr size_t SIZE = CURVE25519_KEY_LEN;

    Curve25519PublicKey() = default;
    explicit Curve25519PublicKey(std::array<uint8_t, SIZE> data);
    explicit Curve25519PublicKey(std::span<const uint8_t> data);

    [[nodiscard]] const std::array<uint8_t, SIZE>& data() const { return data_; }
    [[nodiscard]] std::span<const uint8_t> as_span() const { return data_; }
    [[nodiscard]] std::string to_base64() const;

    [[nodiscard]] static std::expected<Curve25519PublicKey, KeyError>
    from_base64(const std::string& encoded);

    // Check if key is a low-order point (must reject these!)
    [[nodiscard]] bool is_low_order() const;

    bool operator==(const Curve25519PublicKey&) const = default;

private:
    std::array<uint8_t, SIZE> data_{};
};

// Curve25519 secret key (onion key for ntor)
class Curve25519SecretKey {
public:
    static constexpr size_t SIZE = CURVE25519_KEY_LEN;

    Curve25519SecretKey() = default;
    ~Curve25519SecretKey();

    // Disable copying, allow moving
    Curve25519SecretKey(const Curve25519SecretKey&) = delete;
    Curve25519SecretKey& operator=(const Curve25519SecretKey&) = delete;
    Curve25519SecretKey(Curve25519SecretKey&&) noexcept;
    Curve25519SecretKey& operator=(Curve25519SecretKey&&) noexcept;

    [[nodiscard]] static std::expected<Curve25519SecretKey, KeyError> generate();
    [[nodiscard]] static std::expected<Curve25519SecretKey, KeyError>
    from_bytes(std::span<const uint8_t> data);

    [[nodiscard]] const Curve25519PublicKey& public_key() const { return public_key_; }
    [[nodiscard]] std::span<const uint8_t> as_bytes() const { return data_; }

    // Perform X25519 Diffie-Hellman
    [[nodiscard]] std::expected<std::array<uint8_t, SIZE>, KeyError>
    diffie_hellman(const Curve25519PublicKey& peer_public) const;

private:
    std::array<uint8_t, SIZE> data_{};
    Curve25519PublicKey public_key_;
    bool initialized_{false};

    void clear();
};

// Key pair combining identity and onion keys
struct RelayKeyPair {
    Ed25519SecretKey identity_key;
    Curve25519SecretKey onion_key;

    [[nodiscard]] static std::expected<RelayKeyPair, KeyError> generate();
};

// Node ID (SHA-1 hash of identity key for legacy compatibility)
class NodeId {
public:
    static constexpr size_t SIZE = DIGEST_LEN;

    NodeId() = default;
    explicit NodeId(std::array<uint8_t, SIZE> data);
    explicit NodeId(const Ed25519PublicKey& identity_key);

    [[nodiscard]] const std::array<uint8_t, SIZE>& data() const { return data_; }
    [[nodiscard]] std::span<const uint8_t> as_span() const { return data_; }
    [[nodiscard]] std::string to_hex() const;
    [[nodiscard]] std::string to_base64() const;

    [[nodiscard]] static std::expected<NodeId, KeyError> from_hex(const std::string& hex);
    [[nodiscard]] static std::expected<NodeId, KeyError> from_base64(const std::string& b64);

    bool operator==(const NodeId&) const = default;

private:
    std::array<uint8_t, SIZE> data_{};
};

// Utility functions
[[nodiscard]] std::string key_error_message(KeyError err);

// Secure memory operations
void secure_zero(void* ptr, size_t len);
[[nodiscard]] std::vector<uint8_t> random_bytes(size_t len);

}  // namespace tor::crypto

// Hash specialization for NodeId to allow use in unordered containers
namespace std {
template<>
struct hash<tor::crypto::NodeId> {
    size_t operator()(const tor::crypto::NodeId& id) const noexcept {
        const auto& data = id.data();
        size_t result = 0;
        // Simple FNV-1a-like hash over the node ID bytes
        for (size_t i = 0; i < data.size(); ++i) {
            result ^= static_cast<size_t>(data[i]);
            result *= 0x100000001b3ULL;
        }
        return result;
    }
};
}  // namespace std
