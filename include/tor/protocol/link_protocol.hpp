#pragma once

#include "tor/core/cell.hpp"
#include "tor/core/channel.hpp"
#include "tor/crypto/keys.hpp"
#include "tor/crypto/tls.hpp"
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace tor::protocol {

// Link protocol error types
enum class LinkProtocolError {
    VersionMismatch,
    CertificateError,
    AuthenticationFailed,
    ProtocolViolation,
    InvalidCell,
    Timeout,
    Closed,
};

// Supported link protocol versions
constexpr uint16_t LINK_PROTOCOL_MIN = 4;
constexpr uint16_t LINK_PROTOCOL_MAX = 5;

// Link protocol state machine
enum class LinkState {
    Initial,
    VersionsSent,
    VersionsReceived,
    CertsSent,
    CertsReceived,
    AuthChallengeSent,
    AuthChallengeReceived,
    AuthenticateSent,
    AuthenticateReceived,
    NetinfoSent,
    NetinfoReceived,
    Open,
    Failed,
};

// VERSIONS cell handling
class VersionsHandler {
public:
    VersionsHandler() = default;

    // Create VERSIONS cell with our supported versions
    [[nodiscard]] core::VariableCell create_versions_cell() const;

    // Parse received VERSIONS cell
    [[nodiscard]] std::expected<std::vector<uint16_t>, LinkProtocolError>
    parse_versions_cell(const core::VariableCell& cell) const;

    // Negotiate best common version
    [[nodiscard]] std::expected<uint16_t, LinkProtocolError>
    negotiate_version(std::span<const uint16_t> peer_versions) const;

private:
    std::vector<uint16_t> supported_versions_{4, 5};
};

// CERTS cell handling
class CertsHandler {
public:
    CertsHandler() = default;

    // Create CERTS cell with our certificates
    [[nodiscard]] std::expected<core::VariableCell, LinkProtocolError>
    create_certs_cell(
        const crypto::Ed25519SecretKey& identity_key,
        const crypto::Ed25519PublicKey& identity_pub,
        const std::vector<uint8_t>& tls_cert
    ) const;

    // Parse and validate received CERTS cell
    [[nodiscard]] std::expected<std::vector<crypto::TorCertificate>, LinkProtocolError>
    parse_certs_cell(const core::VariableCell& cell) const;

    // Validate certificate chain
    [[nodiscard]] std::expected<crypto::Ed25519PublicKey, LinkProtocolError>
    validate_certificates(
        const std::vector<crypto::TorCertificate>& certs,
        const std::vector<uint8_t>& tls_cert
    ) const;
};

// AUTH_CHALLENGE cell handling
class AuthChallengeHandler {
public:
    AuthChallengeHandler() = default;

    // Create AUTH_CHALLENGE cell
    [[nodiscard]] std::expected<core::VariableCell, LinkProtocolError>
    create_auth_challenge_cell() const;

    // Parse AUTH_CHALLENGE cell
    struct AuthChallengeData {
        std::array<uint8_t, 32> challenge;
        std::vector<uint16_t> methods;
    };

    [[nodiscard]] std::expected<AuthChallengeData, LinkProtocolError>
    parse_auth_challenge_cell(const core::VariableCell& cell) const;

    // Supported auth methods
    static constexpr uint16_t AUTH_METHOD_RSA_SHA256_TLSSECRET = 1;
    static constexpr uint16_t AUTH_METHOD_ED25519_SHA256_RFC5705 = 3;
};

// AUTHENTICATE cell handling
class AuthenticateHandler {
public:
    AuthenticateHandler() = default;

    // Create AUTHENTICATE cell
    [[nodiscard]] std::expected<core::VariableCell, LinkProtocolError>
    create_authenticate_cell(
        uint16_t auth_method,
        const crypto::Ed25519SecretKey& identity_key,
        const std::array<uint8_t, 32>& challenge,
        const std::vector<uint8_t>& tls_cert,
        std::span<const uint8_t> tls_secrets
    ) const;

    // Verify AUTHENTICATE cell
    [[nodiscard]] std::expected<void, LinkProtocolError>
    verify_authenticate_cell(
        const core::VariableCell& cell,
        const crypto::Ed25519PublicKey& peer_identity,
        const std::array<uint8_t, 32>& challenge,
        const std::vector<uint8_t>& peer_tls_cert,
        std::span<const uint8_t> tls_secrets
    ) const;
};

// NETINFO cell handling
class NetinfoHandler {
public:
    NetinfoHandler() = default;

    // Create NETINFO cell
    [[nodiscard]] core::Cell create_netinfo_cell(
        const std::vector<uint8_t>& other_address,  // Address we see for peer
        const std::vector<std::vector<uint8_t>>& our_addresses
    ) const;

    // Parse NETINFO cell
    [[nodiscard]] std::expected<core::NetInfoData, LinkProtocolError>
    parse_netinfo_cell(const core::Cell& cell) const;
};

// Complete link protocol handshake handler
class LinkProtocolHandler {
public:
    LinkProtocolHandler();
    ~LinkProtocolHandler() = default;

    // Perform handshake as initiator (client connecting to server)
    [[nodiscard]] std::expected<void, LinkProtocolError>
    handshake_as_initiator(
        core::Channel& channel,
        const crypto::Ed25519SecretKey& identity_key,
        const crypto::Ed25519PublicKey& identity_pub
    );

    // Perform handshake as responder (server accepting connection)
    [[nodiscard]] std::expected<void, LinkProtocolError>
    handshake_as_responder(
        core::Channel& channel,
        const crypto::Ed25519SecretKey& identity_key,
        const crypto::Ed25519PublicKey& identity_pub
    );

    // Get negotiated version
    [[nodiscard]] uint16_t negotiated_version() const { return negotiated_version_; }

    // Get peer identity
    [[nodiscard]] const crypto::Ed25519PublicKey& peer_identity() const {
        return peer_identity_;
    }

    // Get peer addresses from NETINFO
    [[nodiscard]] const std::vector<std::vector<uint8_t>>& peer_addresses() const {
        return peer_addresses_;
    }

    // Get current state
    [[nodiscard]] LinkState state() const { return state_; }

private:
    VersionsHandler versions_handler_;
    CertsHandler certs_handler_;
    AuthChallengeHandler auth_challenge_handler_;
    AuthenticateHandler authenticate_handler_;
    NetinfoHandler netinfo_handler_;

    LinkState state_{LinkState::Initial};
    uint16_t negotiated_version_{0};
    crypto::Ed25519PublicKey peer_identity_;
    std::vector<std::vector<uint8_t>> peer_addresses_;
};

// Utility
[[nodiscard]] std::string link_protocol_error_message(LinkProtocolError err);
[[nodiscard]] const char* link_state_name(LinkState state);

}  // namespace tor::protocol
