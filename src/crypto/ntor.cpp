#include "tor/crypto/ntor.hpp"
#include "tor/crypto/hash.hpp"
#include <cstring>

namespace tor::crypto {

namespace ntor_detail {

std::array<uint8_t, 32> hmac_sha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data
) {
    auto result = tor::crypto::hmac_sha256(key, data);
    if (!result) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    return *result;
}

std::vector<uint8_t> hkdf_expand(
    std::span<const uint8_t> prk,
    std::span<const uint8_t> info,
    size_t length
) {
    auto result = hkdf_sha256(prk, info, length);
    if (!result) {
        throw std::runtime_error("HKDF expand failed");
    }
    return *result;
}

std::array<uint8_t, 32> compute_secret_input(
    const std::array<uint8_t, 32>& exp_xy,
    const std::array<uint8_t, 32>& exp_xb,
    const NodeId& node_id,
    const Curve25519PublicKey& server_onion_key,
    const Curve25519PublicKey& client_ephemeral,
    const Curve25519PublicKey& server_ephemeral
) {
    // secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
    std::vector<uint8_t> input;
    input.reserve(32 + 32 + 20 + 32 + 32 + 32 + NTOR_PROTO_ID.size());

    input.insert(input.end(), exp_xy.begin(), exp_xy.end());
    input.insert(input.end(), exp_xb.begin(), exp_xb.end());
    input.insert(input.end(), node_id.data().begin(), node_id.data().end());
    input.insert(input.end(), server_onion_key.data().begin(), server_onion_key.data().end());
    input.insert(input.end(), client_ephemeral.data().begin(), client_ephemeral.data().end());
    input.insert(input.end(), server_ephemeral.data().begin(), server_ephemeral.data().end());
    input.insert(input.end(), NTOR_PROTO_ID.begin(), NTOR_PROTO_ID.end());

    return hmac_sha256(NTOR_EXPAND_STR, input);
}

std::array<uint8_t, 32> compute_auth(
    std::span<const uint8_t> verify,
    const NodeId& node_id,
    const Curve25519PublicKey& server_onion_key,
    const Curve25519PublicKey& server_ephemeral,
    const Curve25519PublicKey& client_ephemeral
) {
    // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    std::vector<uint8_t> input;
    input.reserve(verify.size() + 20 + 32 + 32 + 32 + NTOR_PROTO_ID.size() + NTOR_SERVER_STR.size());

    input.insert(input.end(), verify.begin(), verify.end());
    input.insert(input.end(), node_id.data().begin(), node_id.data().end());
    input.insert(input.end(), server_onion_key.data().begin(), server_onion_key.data().end());
    input.insert(input.end(), server_ephemeral.data().begin(), server_ephemeral.data().end());
    input.insert(input.end(), client_ephemeral.data().begin(), client_ephemeral.data().end());
    input.insert(input.end(), NTOR_PROTO_ID.begin(), NTOR_PROTO_ID.end());
    input.insert(input.end(), NTOR_SERVER_STR.begin(), NTOR_SERVER_STR.end());

    return hmac_sha256(NTOR_MAC_STR, input);
}

}  // namespace ntor_detail

// NtorClientHandshake implementation
std::expected<std::array<uint8_t, NTOR_CLIENT_HANDSHAKE_LEN>, NtorError>
NtorClientHandshake::create_request(
    const NodeId& server_node_id,
    const Curve25519PublicKey& server_onion_key
) {
    // Generate ephemeral key pair
    auto key_result = Curve25519SecretKey::generate();
    if (!key_result) {
        return std::unexpected(NtorError::InternalError);
    }
    ephemeral_key_ = std::move(*key_result);
    server_node_id_ = server_node_id;
    server_onion_key_ = server_onion_key;

    // Build request: node_id (20) | key_id (32) | client_pk (32)
    std::array<uint8_t, NTOR_CLIENT_HANDSHAKE_LEN> request{};
    std::copy(server_node_id.data().begin(), server_node_id.data().end(),
              request.begin());
    std::copy(server_onion_key.data().begin(), server_onion_key.data().end(),
              request.begin() + 20);
    std::copy(ephemeral_key_.public_key().data().begin(),
              ephemeral_key_.public_key().data().end(),
              request.begin() + 52);

    request_created_ = true;
    return request;
}

std::expected<NtorKeyMaterial, NtorError>
NtorClientHandshake::complete_handshake(std::span<const uint8_t> server_response) {
    if (!request_created_) {
        return std::unexpected(NtorError::InternalError);
    }

    if (server_response.size() != NTOR_SERVER_HANDSHAKE_LEN) {
        return std::unexpected(NtorError::InvalidHandshakeLength);
    }

    // Parse server response: server_pk (32) | auth (32)
    Curve25519PublicKey server_ephemeral(
        std::span<const uint8_t>(server_response.data(), 32));
    std::array<uint8_t, 32> server_auth;
    std::copy(server_response.begin() + 32, server_response.end(), server_auth.begin());

    // Check for low-order point
    if (server_ephemeral.is_low_order()) {
        return std::unexpected(NtorError::LowOrderPoint);
    }

    // Compute shared secrets
    auto exp_xy = ephemeral_key_.diffie_hellman(server_ephemeral);
    if (!exp_xy) {
        return std::unexpected(NtorError::KeyDerivationFailed);
    }

    auto exp_xb = ephemeral_key_.diffie_hellman(server_onion_key_);
    if (!exp_xb) {
        return std::unexpected(NtorError::KeyDerivationFailed);
    }

    // Compute secret_input
    auto secret_input = ntor_detail::compute_secret_input(
        *exp_xy, *exp_xb, server_node_id_, server_onion_key_,
        ephemeral_key_.public_key(), server_ephemeral);

    // Derive verify
    auto verify = ntor_detail::hmac_sha256(NTOR_VERIFY_STR, secret_input);

    // Compute expected auth
    auto expected_auth = ntor_detail::compute_auth(
        verify, server_node_id_, server_onion_key_,
        server_ephemeral, ephemeral_key_.public_key());

    // Verify auth
    if (!constant_time_compare(expected_auth, server_auth)) {
        return std::unexpected(NtorError::AuthVerificationFailed);
    }

    // Derive key material using HKDF
    auto key_material = ntor_detail::hkdf_expand(secret_input, NTOR_EXPAND_STR,
                                                  NtorKeyMaterial::TOTAL_LEN);

    NtorKeyMaterial keys;
    size_t offset = 0;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 16, keys.forward_key.begin());
    offset += 16;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 16, keys.backward_key.begin());
    offset += 16;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 20, keys.forward_digest.begin());
    offset += 20;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 20, keys.backward_digest.begin());
    offset += 20;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 20, keys.kh.begin());

    return keys;
}

// NtorServerHandshake implementation
std::expected<std::pair<std::array<uint8_t, NTOR_SERVER_HANDSHAKE_LEN>, NtorKeyMaterial>, NtorError>
NtorServerHandshake::process_request(
    std::span<const uint8_t> client_request,
    const NodeId& our_node_id,
    const Curve25519SecretKey& our_onion_key
) {
    if (client_request.size() != NTOR_CLIENT_HANDSHAKE_LEN) {
        return std::unexpected(NtorError::InvalidHandshakeLength);
    }

    // Parse client request
    NodeId client_node_id(std::array<uint8_t, 20>{});
    std::copy(client_request.begin(), client_request.begin() + 20,
              const_cast<uint8_t*>(client_node_id.data().data()));

    // Verify node_id matches
    if (!(client_node_id == our_node_id)) {
        return std::unexpected(NtorError::InvalidNodeId);
    }

    Curve25519PublicKey client_key_id(
        std::span<const uint8_t>(client_request.data() + 20, 32));

    // Verify key_id matches our onion key
    if (!(client_key_id == our_onion_key.public_key())) {
        return std::unexpected(NtorError::InvalidKeyId);
    }

    Curve25519PublicKey client_ephemeral(
        std::span<const uint8_t>(client_request.data() + 52, 32));

    // Check for low-order point
    if (client_ephemeral.is_low_order()) {
        return std::unexpected(NtorError::LowOrderPoint);
    }

    // Generate ephemeral key pair
    auto ephemeral_result = Curve25519SecretKey::generate();
    if (!ephemeral_result) {
        return std::unexpected(NtorError::InternalError);
    }
    auto& ephemeral_key = *ephemeral_result;

    // Compute shared secrets
    auto exp_xy = ephemeral_key.diffie_hellman(client_ephemeral);
    if (!exp_xy) {
        return std::unexpected(NtorError::KeyDerivationFailed);
    }

    auto exp_xb = our_onion_key.diffie_hellman(client_ephemeral);
    if (!exp_xb) {
        return std::unexpected(NtorError::KeyDerivationFailed);
    }

    // Compute secret_input
    auto secret_input = ntor_detail::compute_secret_input(
        *exp_xy, *exp_xb, our_node_id, our_onion_key.public_key(),
        client_ephemeral, ephemeral_key.public_key());

    // Derive verify
    auto verify = ntor_detail::hmac_sha256(NTOR_VERIFY_STR, secret_input);

    // Compute auth
    auto auth = ntor_detail::compute_auth(
        verify, our_node_id, our_onion_key.public_key(),
        ephemeral_key.public_key(), client_ephemeral);

    // Build response
    std::array<uint8_t, NTOR_SERVER_HANDSHAKE_LEN> response;
    std::copy(ephemeral_key.public_key().data().begin(),
              ephemeral_key.public_key().data().end(),
              response.begin());
    std::copy(auth.begin(), auth.end(), response.begin() + 32);

    // Derive key material
    auto key_material = ntor_detail::hkdf_expand(secret_input, NTOR_EXPAND_STR,
                                                  NtorKeyMaterial::TOTAL_LEN);

    NtorKeyMaterial keys;
    size_t offset = 0;
    // Note: Server uses backward as forward and vice versa
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 16, keys.backward_key.begin());
    offset += 16;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 16, keys.forward_key.begin());
    offset += 16;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 20, keys.backward_digest.begin());
    offset += 20;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 20, keys.forward_digest.begin());
    offset += 20;
    std::copy(key_material.begin() + offset,
              key_material.begin() + offset + 20, keys.kh.begin());

    return std::make_pair(response, keys);
}

std::string ntor_error_message(NtorError err) {
    switch (err) {
        case NtorError::InvalidHandshakeLength: return "Invalid handshake length";
        case NtorError::InvalidKeyId: return "Invalid key ID";
        case NtorError::InvalidNodeId: return "Invalid node ID";
        case NtorError::KeyDerivationFailed: return "Key derivation failed";
        case NtorError::AuthVerificationFailed: return "Auth verification failed";
        case NtorError::LowOrderPoint: return "Low-order point rejected";
        case NtorError::InternalError: return "Internal error";
        default: return "Unknown ntor error";
    }
}

}  // namespace tor::crypto
