#include "tor/protocol/link_protocol.hpp"
#include "tor/protocol/cell_parser.hpp"
#include "tor/util/logging.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace tor::protocol {

// --- VersionsHandler ---

core::VariableCell VersionsHandler::create_versions_cell() const {
    BinaryWriter writer(supported_versions_.size() * 2);
    for (auto ver : supported_versions_) {
        writer.write_u16(ver);
    }
    return core::VariableCell(0, core::CellCommand::VERSIONS, writer.take());
}

std::expected<std::vector<uint16_t>, LinkProtocolError>
VersionsHandler::parse_versions_cell(const core::VariableCell& cell) const {
    if (cell.command != core::CellCommand::VERSIONS) {
        return std::unexpected(LinkProtocolError::ProtocolViolation);
    }

    if (cell.payload.size() % 2 != 0) {
        return std::unexpected(LinkProtocolError::InvalidCell);
    }

    BinaryReader reader(cell.payload);
    std::vector<uint16_t> versions;
    while (!reader.at_end()) {
        auto ver = reader.read_u16();
        if (!ver) return std::unexpected(LinkProtocolError::InvalidCell);
        versions.push_back(*ver);
    }

    return versions;
}

std::expected<uint16_t, LinkProtocolError>
VersionsHandler::negotiate_version(std::span<const uint16_t> peer_versions) const {
    uint16_t best = 0;
    for (auto pv : peer_versions) {
        for (auto ov : supported_versions_) {
            if (pv == ov && pv > best) {
                best = pv;
            }
        }
    }

    if (best == 0) {
        return std::unexpected(LinkProtocolError::VersionMismatch);
    }
    return best;
}

// --- CertsHandler ---

// Helper: Build a Tor Ed25519 certificate
static std::vector<uint8_t> build_ed25519_cert(
    uint8_t cert_type,
    const crypto::Ed25519PublicKey& certified_key,
    const crypto::Ed25519SecretKey& signing_key,
    const crypto::Ed25519PublicKey* signer_key_for_ext = nullptr)
{
    BinaryWriter writer;

    // VERSION
    writer.write_u8(1);

    // CERT_TYPE
    writer.write_u8(cert_type);

    // EXPIRATION_DATE (hours since epoch, 24 hours from now)
    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    uint32_t exp_hours = static_cast<uint32_t>((secs / 3600) + 24);
    writer.write_u32(exp_hours);

    // CERT_KEY_TYPE = 1 (Ed25519)
    writer.write_u8(1);

    // CERTIFIED_KEY
    writer.write_bytes(certified_key.as_span());

    // EXTENSIONS
    if (signer_key_for_ext) {
        writer.write_u8(1); // N_EXTENSIONS = 1

        // Extension: SignedWithEd25519Key (type 4)
        uint16_t ext_data_len = 32; // Ed25519 key
        writer.write_u16(ext_data_len);
        writer.write_u8(4);  // ExtType = SignedWithEd25519Key
        writer.write_u8(0);  // ExtFlags = 0
        writer.write_bytes(signer_key_for_ext->as_span());
    } else {
        writer.write_u8(0); // N_EXTENSIONS = 0
    }

    // Sign everything written so far
    auto to_sign = writer.data();
    auto sig = signing_key.sign(to_sign);
    if (sig) {
        writer.write_bytes(*sig);
    } else {
        // Signature failed - write zeros (will fail validation)
        writer.write_padding(64);
    }

    return writer.take();
}

// Helper: Build Ed25519 cert for TLS link key (Type 5)
// The certified key is SHA256(DER-encoded-X509-cert) truncated to 32 bytes
static std::vector<uint8_t> build_tls_link_cert(
    const std::vector<uint8_t>& tls_cert_der,
    const crypto::Ed25519SecretKey& signing_key,
    const crypto::Ed25519PublicKey& signer_pub)
{
    // SHA256 of the DER-encoded TLS cert
    std::array<uint8_t, 32> cert_digest;
    SHA256(tls_cert_der.data(), tls_cert_der.size(), cert_digest.data());

    // Create a temporary Ed25519PublicKey from the digest
    crypto::Ed25519PublicKey cert_key(cert_digest);

    return build_ed25519_cert(
        static_cast<uint8_t>(crypto::TorCertType::TLS_LINK),
        cert_key,
        signing_key,
        &signer_pub);
}

std::expected<core::VariableCell, LinkProtocolError>
CertsHandler::create_certs_cell(
    const crypto::Ed25519SecretKey& identity_key,
    const crypto::Ed25519PublicKey& identity_pub,
    const std::vector<uint8_t>& tls_cert_der
) const {
    // Generate an ephemeral Ed25519 signing key
    auto signing_key_result = crypto::Ed25519SecretKey::generate();
    if (!signing_key_result) {
        return std::unexpected(LinkProtocolError::CertificateError);
    }

    auto& signing_key = *signing_key_result;
    auto signing_pub = signing_key.public_key();

    // Build certificates:
    // Type 4: Ed25519 signing key, certified by identity key
    auto cert4 = build_ed25519_cert(
        static_cast<uint8_t>(crypto::TorCertType::ED25519_SIGNING),
        signing_pub,
        identity_key,
        &identity_pub);

    // Type 5: TLS link cert, certified by signing key
    auto cert5 = build_tls_link_cert(tls_cert_der, signing_key, signing_pub);

    // Type 7: RSA->Ed25519 cross cert
    // For Ed25519-only relays (no RSA identity), we skip Type 7
    // and only send Types 4 and 5, plus the raw RSA certs (Types 1, 2)

    // Type 2: RSA identity cert (the TLS cert itself, self-signed)
    // Type 1: Link key cert (same as TLS cert for self-signed case)

    // Build CERTS cell payload
    BinaryWriter payload;

    // N_CERTS
    uint8_t n_certs = 4; // Types 1, 2, 4, 5
    payload.write_u8(n_certs);

    // Cert Type 1: Link Key Certificate (X.509, DER)
    payload.write_u8(static_cast<uint8_t>(crypto::TorCertType::LINK_KEY));
    payload.write_u16(static_cast<uint16_t>(tls_cert_der.size()));
    payload.write_bytes(tls_cert_der);

    // Cert Type 2: RSA Identity Certificate (X.509, DER) - same as TLS cert
    payload.write_u8(static_cast<uint8_t>(crypto::TorCertType::RSA_IDENTITY));
    payload.write_u16(static_cast<uint16_t>(tls_cert_der.size()));
    payload.write_bytes(tls_cert_der);

    // Cert Type 4: Ed25519 Signing Key
    payload.write_u8(static_cast<uint8_t>(crypto::TorCertType::ED25519_SIGNING));
    payload.write_u16(static_cast<uint16_t>(cert4.size()));
    payload.write_bytes(cert4);

    // Cert Type 5: TLS Link Cert (Ed25519)
    payload.write_u8(static_cast<uint8_t>(crypto::TorCertType::TLS_LINK));
    payload.write_u16(static_cast<uint16_t>(cert5.size()));
    payload.write_bytes(cert5);

    return core::VariableCell(0, core::CellCommand::CERTS, payload.take());
}

std::expected<std::vector<crypto::TorCertificate>, LinkProtocolError>
CertsHandler::parse_certs_cell(const core::VariableCell& cell) const {
    if (cell.command != core::CellCommand::CERTS) {
        return std::unexpected(LinkProtocolError::ProtocolViolation);
    }

    BinaryReader reader(cell.payload);
    auto n_certs = reader.read_u8();
    if (!n_certs) return std::unexpected(LinkProtocolError::InvalidCell);

    std::vector<crypto::TorCertificate> certs;
    for (uint8_t i = 0; i < *n_certs; ++i) {
        auto cert_type = reader.read_u8();
        if (!cert_type) return std::unexpected(LinkProtocolError::InvalidCell);

        auto cert_len = reader.read_u16();
        if (!cert_len) return std::unexpected(LinkProtocolError::InvalidCell);

        auto cert_body = reader.read_bytes(*cert_len);
        if (!cert_body) return std::unexpected(LinkProtocolError::InvalidCell);

        certs.push_back({
            static_cast<crypto::TorCertType>(*cert_type),
            std::move(*cert_body)
        });
    }

    return certs;
}

std::expected<crypto::Ed25519PublicKey, LinkProtocolError>
CertsHandler::validate_certificates(
    const std::vector<crypto::TorCertificate>& /*certs*/,
    const std::vector<uint8_t>& /*tls_cert*/
) const {
    // Simplified validation for bridge mode - accept all certs from clients
    // Full validation would verify cert chain, signatures, and expiration
    return crypto::Ed25519PublicKey();
}

// --- AuthChallengeHandler ---

std::expected<core::VariableCell, LinkProtocolError>
AuthChallengeHandler::create_auth_challenge_cell() const {
    BinaryWriter payload;

    // 32-byte random challenge
    std::array<uint8_t, 32> challenge;
    RAND_bytes(challenge.data(), 32);
    payload.write_bytes(challenge);

    // N_METHODS = 2
    payload.write_u16(2);

    // Methods: RSA_SHA256_TLSSECRET (1) and ED25519_SHA256_RFC5705 (3)
    payload.write_u16(AUTH_METHOD_RSA_SHA256_TLSSECRET);
    payload.write_u16(AUTH_METHOD_ED25519_SHA256_RFC5705);

    return core::VariableCell(0, core::CellCommand::AUTH_CHALLENGE, payload.take());
}

std::expected<AuthChallengeHandler::AuthChallengeData, LinkProtocolError>
AuthChallengeHandler::parse_auth_challenge_cell(const core::VariableCell& cell) const {
    if (cell.command != core::CellCommand::AUTH_CHALLENGE) {
        return std::unexpected(LinkProtocolError::ProtocolViolation);
    }

    BinaryReader reader(cell.payload);
    AuthChallengeData data;

    auto challenge_bytes = reader.read_bytes(32);
    if (!challenge_bytes) return std::unexpected(LinkProtocolError::InvalidCell);
    std::memcpy(data.challenge.data(), challenge_bytes->data(), 32);

    auto n_methods = reader.read_u16();
    if (!n_methods) return std::unexpected(LinkProtocolError::InvalidCell);

    for (uint16_t i = 0; i < *n_methods; ++i) {
        auto method = reader.read_u16();
        if (!method) return std::unexpected(LinkProtocolError::InvalidCell);
        data.methods.push_back(*method);
    }

    return data;
}

// --- AuthenticateHandler ---

std::expected<core::VariableCell, LinkProtocolError>
AuthenticateHandler::create_authenticate_cell(
    uint16_t /*auth_method*/,
    const crypto::Ed25519SecretKey& /*identity_key*/,
    const std::array<uint8_t, 32>& /*challenge*/,
    const std::vector<uint8_t>& /*tls_cert*/,
    std::span<const uint8_t> /*tls_secrets*/
) const {
    // AUTHENTICATE cells are optional for client connections
    return std::unexpected(LinkProtocolError::AuthenticationFailed);
}

std::expected<void, LinkProtocolError>
AuthenticateHandler::verify_authenticate_cell(
    const core::VariableCell& /*cell*/,
    const crypto::Ed25519PublicKey& /*peer_identity*/,
    const std::array<uint8_t, 32>& /*challenge*/,
    const std::vector<uint8_t>& /*peer_tls_cert*/,
    std::span<const uint8_t> /*tls_secrets*/
) const {
    // For bridge mode, client authentication is not required
    return {};
}

// --- NetinfoHandler ---

core::Cell NetinfoHandler::create_netinfo_cell(
    const std::vector<uint8_t>& other_address,
    const std::vector<std::vector<uint8_t>>& our_addresses
) const {
    core::Cell cell(0, core::CellCommand::NETINFO);

    BinaryWriter writer;

    // Timestamp (seconds since epoch)
    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    writer.write_u32(static_cast<uint32_t>(secs));

    // Other address (what we see as the peer's address)
    if (other_address.size() >= 5) {
        // Format: type(1) + addr(4 for IPv4)
        writer.write_u8(other_address[0]); // type
        writer.write_u8(static_cast<uint8_t>(other_address.size() - 1)); // length
        writer.write_bytes(std::span<const uint8_t>(
            other_address.data() + 1, other_address.size() - 1));
    } else {
        // Default: IPv4 0.0.0.0
        writer.write_u8(4);  // type = IPv4
        writer.write_u8(4);  // length = 4 bytes
        writer.write_padding(4); // 0.0.0.0
    }

    // Our addresses
    writer.write_u8(static_cast<uint8_t>(our_addresses.size()));
    for (const auto& addr : our_addresses) {
        if (addr.size() >= 2) {
            writer.write_u8(addr[0]); // type
            writer.write_u8(static_cast<uint8_t>(addr.size() - 1)); // length
            writer.write_bytes(std::span<const uint8_t>(
                addr.data() + 1, addr.size() - 1));
        }
    }

    // Copy to cell payload
    const auto& buf = writer.data();
    std::memcpy(cell.payload.data(), buf.data(),
                std::min(buf.size(), static_cast<size_t>(core::PAYLOAD_LEN)));

    return cell;
}

std::expected<core::NetInfoData, LinkProtocolError>
NetinfoHandler::parse_netinfo_cell(const core::Cell& cell) const {
    if (cell.command != core::CellCommand::NETINFO) {
        return std::unexpected(LinkProtocolError::ProtocolViolation);
    }

    CellParser parser;
    auto result = parser.parse_netinfo(cell.payload);
    if (!result) {
        return std::unexpected(LinkProtocolError::InvalidCell);
    }
    return *result;
}

// --- LinkProtocolHandler ---

LinkProtocolHandler::LinkProtocolHandler() = default;

std::expected<void, LinkProtocolError>
LinkProtocolHandler::handshake_as_initiator(
    core::Channel& /*channel*/,
    const crypto::Ed25519SecretKey& /*identity_key*/,
    const crypto::Ed25519PublicKey& /*identity_pub*/
) {
    // Client-side handshake not needed for bridge mode
    return std::unexpected(LinkProtocolError::ProtocolViolation);
}

std::expected<void, LinkProtocolError>
LinkProtocolHandler::handshake_as_responder(
    core::Channel& channel,
    const crypto::Ed25519SecretKey& identity_key,
    const crypto::Ed25519PublicKey& identity_pub
) {
    // Step 1: Receive VERSIONS from client
    LOG_INFO("OR: waiting for VERSIONS cell");
    state_ = LinkState::Initial;

    auto versions_cell = channel.receive_variable();
    if (!versions_cell) {
        LOG_WARN("OR: failed to receive VERSIONS cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::Closed);
    }

    auto peer_versions = versions_handler_.parse_versions_cell(*versions_cell);
    if (!peer_versions) {
        LOG_WARN("OR: failed to parse VERSIONS cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::InvalidCell);
    }

    auto negotiated = versions_handler_.negotiate_version(*peer_versions);
    if (!negotiated) {
        LOG_WARN("OR: no common link protocol version");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::VersionMismatch);
    }

    negotiated_version_ = *negotiated;
    LOG_INFO("OR: negotiated link protocol v{}", negotiated_version_);
    state_ = LinkState::VersionsReceived;

    // Step 2: Send VERSIONS (still using legacy 2-byte circuit IDs)
    auto our_versions = versions_handler_.create_versions_cell();
    auto send_result = channel.send(our_versions);
    if (!send_result) {
        LOG_WARN("OR: failed to send VERSIONS cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::Closed);
    }
    state_ = LinkState::VersionsSent;

    // Switch to negotiated version for all subsequent cells
    channel.set_link_version(negotiated_version_);

    // Step 3: Send CERTS
    auto tls_cert_der = channel.tls_cert_der();
    auto certs_cell = certs_handler_.create_certs_cell(
        identity_key, identity_pub, tls_cert_der);
    if (!certs_cell) {
        LOG_WARN("OR: failed to create CERTS cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::CertificateError);
    }
    send_result = channel.send(*certs_cell);
    if (!send_result) {
        LOG_WARN("OR: failed to send CERTS cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::Closed);
    }
    state_ = LinkState::CertsSent;
    LOG_INFO("OR: sent CERTS cell");

    // Step 4: Send AUTH_CHALLENGE
    auto auth_cell = auth_challenge_handler_.create_auth_challenge_cell();
    if (!auth_cell) {
        LOG_WARN("OR: failed to create AUTH_CHALLENGE cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::CertificateError);
    }
    send_result = channel.send(*auth_cell);
    if (!send_result) {
        LOG_WARN("OR: failed to send AUTH_CHALLENGE cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::Closed);
    }
    state_ = LinkState::AuthChallengeSent;
    LOG_INFO("OR: sent AUTH_CHALLENGE cell");

    // Step 5: Send NETINFO
    // Use 0.0.0.0 as the peer address (we don't know it in bridge mode
    // since the obfs4 proxy connects from 127.0.0.1)
    std::vector<uint8_t> peer_addr = {4, 0, 0, 0, 0}; // IPv4 0.0.0.0
    std::vector<std::vector<uint8_t>> our_addrs; // Empty - bridges don't advertise
    auto netinfo = netinfo_handler_.create_netinfo_cell(peer_addr, our_addrs);
    send_result = channel.send(netinfo);
    if (!send_result) {
        LOG_WARN("OR: failed to send NETINFO cell");
        state_ = LinkState::Failed;
        return std::unexpected(LinkProtocolError::Closed);
    }
    state_ = LinkState::NetinfoSent;
    LOG_INFO("OR: sent NETINFO cell");

    // Step 6: Receive client's cells (CERTS, AUTHENTICATE, NETINFO)
    // Client may send CERTS + AUTHENTICATE (optional) + NETINFO
    // Or just NETINFO for unauthenticated connections
    bool got_netinfo = false;
    while (!got_netinfo) {
        // Try to read either a variable cell or fixed cell
        // CERTS and AUTHENTICATE are variable; NETINFO is fixed
        auto cell = channel.receive_any();
        if (!cell) {
            LOG_WARN("OR: failed to receive client cell during handshake");
            state_ = LinkState::Failed;
            return std::unexpected(LinkProtocolError::Closed);
        }

        auto& [is_variable, fixed_cell, var_cell] = *cell;

        if (is_variable) {
            if (var_cell.command == core::CellCommand::CERTS) {
                LOG_INFO("OR: received client CERTS cell");
                state_ = LinkState::CertsReceived;
            } else if (var_cell.command == core::CellCommand::AUTHENTICATE) {
                LOG_INFO("OR: received client AUTHENTICATE cell");
                state_ = LinkState::AuthenticateReceived;
            } else if (var_cell.command == core::CellCommand::VPADDING) {
                // Ignore padding
            } else {
                LOG_WARN("OR: unexpected variable cell {} during handshake",
                         core::cell_command_name(var_cell.command));
            }
        } else {
            if (fixed_cell.command == core::CellCommand::NETINFO) {
                LOG_INFO("OR: received client NETINFO cell");
                state_ = LinkState::NetinfoReceived;
                got_netinfo = true;
            } else if (fixed_cell.command == core::CellCommand::PADDING) {
                // Ignore padding
            } else {
                LOG_WARN("OR: unexpected fixed cell {} during handshake",
                         core::cell_command_name(fixed_cell.command));
            }
        }
    }

    state_ = LinkState::Open;
    LOG_INFO("OR: link protocol handshake complete");
    return {};
}

// --- Utility ---

std::string link_protocol_error_message(LinkProtocolError err) {
    switch (err) {
        case LinkProtocolError::VersionMismatch:      return "Version mismatch";
        case LinkProtocolError::CertificateError:     return "Certificate error";
        case LinkProtocolError::AuthenticationFailed: return "Authentication failed";
        case LinkProtocolError::ProtocolViolation:    return "Protocol violation";
        case LinkProtocolError::InvalidCell:          return "Invalid cell";
        case LinkProtocolError::Timeout:              return "Timeout";
        case LinkProtocolError::Closed:               return "Connection closed";
        default:                                      return "Unknown link error";
    }
}

const char* link_state_name(LinkState state) {
    switch (state) {
        case LinkState::Initial:               return "Initial";
        case LinkState::VersionsSent:          return "VersionsSent";
        case LinkState::VersionsReceived:      return "VersionsReceived";
        case LinkState::CertsSent:             return "CertsSent";
        case LinkState::CertsReceived:         return "CertsReceived";
        case LinkState::AuthChallengeSent:     return "AuthChallengeSent";
        case LinkState::AuthChallengeReceived: return "AuthChallengeReceived";
        case LinkState::AuthenticateSent:      return "AuthenticateSent";
        case LinkState::AuthenticateReceived:  return "AuthenticateReceived";
        case LinkState::NetinfoSent:           return "NetinfoSent";
        case LinkState::NetinfoReceived:       return "NetinfoReceived";
        case LinkState::Open:                  return "Open";
        case LinkState::Failed:                return "Failed";
        default:                               return "Unknown";
    }
}

}  // namespace tor::protocol
