#pragma once

#include "tor/crypto/keys.hpp"
#include "tor/crypto/ntor.hpp"
#include <optional>

namespace tor::test {

// Mock crypto provider for controlled testing
class MockCryptoProvider {
public:
    MockCryptoProvider() = default;

    // Control Ed25519 verification results
    void set_ed25519_verify_result(bool result) {
        ed25519_verify_result_ = result;
    }

    bool verify_ed25519(
        const crypto::Ed25519PublicKey& key,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature
    ) {
        if (ed25519_verify_result_.has_value()) {
            return *ed25519_verify_result_;
        }
        return key.verify(message, signature);
    }

    // Control Curve25519 DH results
    void set_dh_result(std::optional<std::array<uint8_t, 32>> result) {
        dh_result_ = result;
    }

    void fail_dh_with(crypto::KeyError error) {
        dh_error_ = error;
    }

    std::expected<std::array<uint8_t, 32>, crypto::KeyError>
    diffie_hellman(
        const crypto::Curve25519SecretKey& secret,
        const crypto::Curve25519PublicKey& peer
    ) {
        if (dh_error_.has_value()) {
            return std::unexpected(*dh_error_);
        }
        if (dh_result_.has_value()) {
            return *dh_result_;
        }
        return secret.diffie_hellman(peer);
    }

    // Control ntor handshake results
    void set_ntor_client_result(
        std::optional<std::array<uint8_t, crypto::NTOR_CLIENT_HANDSHAKE_LEN>> result
    ) {
        ntor_client_result_ = result;
    }

    void set_ntor_server_result(
        std::optional<std::pair<std::array<uint8_t, crypto::NTOR_SERVER_HANDSHAKE_LEN>,
                               crypto::NtorKeyMaterial>> result
    ) {
        ntor_server_result_ = result;
    }

    void fail_ntor_with(crypto::NtorError error) {
        ntor_error_ = error;
    }

    // Reset all mock states
    void reset() {
        ed25519_verify_result_.reset();
        dh_result_.reset();
        dh_error_.reset();
        ntor_client_result_.reset();
        ntor_server_result_.reset();
        ntor_error_.reset();
    }

private:
    std::optional<bool> ed25519_verify_result_;
    std::optional<std::array<uint8_t, 32>> dh_result_;
    std::optional<crypto::KeyError> dh_error_;
    std::optional<std::array<uint8_t, crypto::NTOR_CLIENT_HANDSHAKE_LEN>> ntor_client_result_;
    std::optional<std::pair<std::array<uint8_t, crypto::NTOR_SERVER_HANDSHAKE_LEN>,
                           crypto::NtorKeyMaterial>> ntor_server_result_;
    std::optional<crypto::NtorError> ntor_error_;
};

// Test key generator - generates deterministic keys for testing
class TestKeyGenerator {
public:
    // Generate Ed25519 key pair from seed
    static crypto::Ed25519SecretKey generate_ed25519(uint64_t seed) {
        std::array<uint8_t, 32> seed_bytes{};
        for (int i = 0; i < 8; ++i) {
            seed_bytes[i] = static_cast<uint8_t>(seed >> (i * 8));
        }
        auto result = crypto::Ed25519SecretKey::from_seed(seed_bytes);
        if (!result) {
            throw std::runtime_error("Failed to generate test Ed25519 key");
        }
        return std::move(*result);
    }

    // Generate Curve25519 key pair from seed
    static crypto::Curve25519SecretKey generate_curve25519(uint64_t seed) {
        std::array<uint8_t, 32> seed_bytes{};
        for (int i = 0; i < 8; ++i) {
            seed_bytes[i] = static_cast<uint8_t>(seed >> (i * 8));
        }
        auto result = crypto::Curve25519SecretKey::from_bytes(seed_bytes);
        if (!result) {
            throw std::runtime_error("Failed to generate test Curve25519 key");
        }
        return std::move(*result);
    }

    // Generate node ID from seed
    static crypto::NodeId generate_node_id(uint64_t seed) {
        std::array<uint8_t, 20> id{};
        for (int i = 0; i < 8; ++i) {
            id[i] = static_cast<uint8_t>(seed >> (i * 8));
        }
        return crypto::NodeId(id);
    }
};

}  // namespace tor::test
