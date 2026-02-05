#pragma once

#include "tor/crypto/keys.hpp"
#include <array>
#include <cstdint>
#include <expected>
#include <span>

namespace tor::crypto {

// ntor handshake constants
constexpr size_t NTOR_ONION_KEY_LEN = 32;
constexpr size_t NTOR_CLIENT_HANDSHAKE_LEN = 84;  // node_id(20) + key_id(32) + client_pk(32)
constexpr size_t NTOR_SERVER_HANDSHAKE_LEN = 64;  // server_pk(32) + auth(32)
constexpr size_t NTOR_KEY_SEED_LEN = 32;
constexpr size_t NTOR_AUTH_LEN = 32;

// Protocol ID for ntor
inline constexpr std::array<uint8_t, 24> NTOR_PROTO_ID = {
    'n', 't', 'o', 'r', '-', 'c', 'u', 'r', 'v', 'e', '2', '5',
    '5', '1', '9', '-', 's', 'h', 'a', '2', '5', '6', '-', '1'
};

// Server string constant
inline constexpr std::array<uint8_t, 15> NTOR_SERVER_STR = {
    'S', 'e', 'r', 'v', 'e', 'r', ' ', 'k', 'e', 'y', ' ', 'd', 'a', 't', 'a'
};

// Expand string constant
inline constexpr std::array<uint8_t, 18> NTOR_EXPAND_STR = {
    'n', 't', 'o', 'r', '-', 'c', 'u', 'r', 'v', 'e',
    '2', '5', '5', '1', '9', '-', '1', ':'
};

// MAC string constant
inline constexpr std::array<uint8_t, 28> NTOR_MAC_STR = {
    'n', 't', 'o', 'r', '-', 'c', 'u', 'r', 'v', 'e', '2', '5', '5', '1',
    '9', '-', 's', 'h', 'a', '2', '5', '6', '-', '1', ':', 'm', 'a', 'c'
};

// Verify string constant
inline constexpr std::array<uint8_t, 31> NTOR_VERIFY_STR = {
    'n', 't', 'o', 'r', '-', 'c', 'u', 'r', 'v', 'e', '2', '5', '5', '1',
    '9', '-', 's', 'h', 'a', '2', '5', '6', '-', '1', ':', 'v', 'e', 'r',
    'i', 'f', 'y'
};

// ntor handshake errors
enum class NtorError {
    InvalidHandshakeLength,
    InvalidKeyId,
    InvalidNodeId,
    KeyDerivationFailed,
    AuthVerificationFailed,
    LowOrderPoint,
    InternalError,
};

// Derived key material from ntor handshake
struct NtorKeyMaterial {
    std::array<uint8_t, 16> forward_key;   // AES-128-CTR key for outgoing
    std::array<uint8_t, 16> backward_key;  // AES-128-CTR key for incoming
    std::array<uint8_t, 20> forward_digest; // SHA-1 seed for outgoing
    std::array<uint8_t, 20> backward_digest; // SHA-1 seed for incoming
    std::array<uint8_t, 20> kh;  // Key hash for hidden service

    static constexpr size_t TOTAL_LEN = 16 + 16 + 20 + 20 + 20;  // 92 bytes
};

// Client-side ntor handshake state
class NtorClientHandshake {
public:
    NtorClientHandshake() = default;

    // Initialize with server's node ID and onion key
    [[nodiscard]] std::expected<std::array<uint8_t, NTOR_CLIENT_HANDSHAKE_LEN>, NtorError>
    create_request(
        const NodeId& server_node_id,
        const Curve25519PublicKey& server_onion_key
    );

    // Complete handshake with server's response, derive keys
    [[nodiscard]] std::expected<NtorKeyMaterial, NtorError>
    complete_handshake(std::span<const uint8_t> server_response);

private:
    Curve25519SecretKey ephemeral_key_;
    NodeId server_node_id_;
    Curve25519PublicKey server_onion_key_;
    bool request_created_{false};
};

// Server-side ntor handshake
class NtorServerHandshake {
public:
    NtorServerHandshake() = default;

    // Process client request and generate response
    [[nodiscard]] std::expected<std::pair<std::array<uint8_t, NTOR_SERVER_HANDSHAKE_LEN>, NtorKeyMaterial>, NtorError>
    process_request(
        std::span<const uint8_t> client_request,
        const NodeId& our_node_id,
        const Curve25519SecretKey& our_onion_key
    );

private:
    // Internal key derivation helper
    [[nodiscard]] std::expected<std::pair<NtorKeyMaterial, std::array<uint8_t, NTOR_AUTH_LEN>>, NtorError>
    derive_keys(
        const std::array<uint8_t, 32>& secret_input,
        const Curve25519PublicKey& client_ephemeral,
        const Curve25519PublicKey& server_ephemeral,
        const NodeId& node_id,
        const Curve25519PublicKey& server_onion_key
    );
};

// Helper functions for ntor
namespace ntor_detail {

// HMAC-SHA256 with ntor protocol domain separation
[[nodiscard]] std::array<uint8_t, 32> hmac_sha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data
);

// HKDF-SHA256 key expansion
[[nodiscard]] std::vector<uint8_t> hkdf_expand(
    std::span<const uint8_t> prk,
    std::span<const uint8_t> info,
    size_t length
);

// Compute secret_input for ntor
[[nodiscard]] std::array<uint8_t, 32> compute_secret_input(
    const std::array<uint8_t, 32>& exp_xy,
    const std::array<uint8_t, 32>& exp_xb,
    const NodeId& node_id,
    const Curve25519PublicKey& server_onion_key,
    const Curve25519PublicKey& client_ephemeral,
    const Curve25519PublicKey& server_ephemeral
);

// Compute auth value
[[nodiscard]] std::array<uint8_t, 32> compute_auth(
    std::span<const uint8_t> verify,
    const NodeId& node_id,
    const Curve25519PublicKey& server_onion_key,
    const Curve25519PublicKey& server_ephemeral,
    const Curve25519PublicKey& client_ephemeral
);

}  // namespace ntor_detail

// Utility
[[nodiscard]] std::string ntor_error_message(NtorError err);

}  // namespace tor::crypto
