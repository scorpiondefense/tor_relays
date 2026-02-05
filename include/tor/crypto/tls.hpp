#pragma once

#include "tor/crypto/keys.hpp"
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace tor::crypto {

// TLS error types
enum class TlsError {
    ContextCreationFailed,
    CertificateLoadFailed,
    KeyLoadFailed,
    HandshakeFailed,
    ReadFailed,
    WriteFailed,
    VerificationFailed,
    ConnectionClosed,
    WouldBlock,
    OpenSSLError,
};

// TLS version requirements
enum class TlsVersion {
    TLS_1_2,
    TLS_1_3,
};

// Certificate types for Tor link protocol
enum class TorCertType : uint8_t {
    LINK_KEY = 1,           // Link key certificate
    RSA_IDENTITY = 2,       // RSA identity certificate
    RSA_AUTHENTICATE = 3,   // RSA authentication certificate
    ED25519_SIGNING = 4,    // Ed25519 signing key
    TLS_LINK = 5,          // TLS link certificate
    ED25519_AUTHENTICATE = 6,  // Ed25519 authentication
    ED25519_IDENTITY = 7,   // Ed25519 identity
};

// Certificate structure for CERTS cell
struct TorCertificate {
    TorCertType type;
    std::vector<uint8_t> body;

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    [[nodiscard]] static std::expected<TorCertificate, TlsError>
    parse(std::span<const uint8_t> data, size_t& offset);
};

// TLS context for server/client mode
class TlsContext {
public:
    TlsContext();
    ~TlsContext();

    // Disable copying, allow moving
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    TlsContext(TlsContext&&) noexcept;
    TlsContext& operator=(TlsContext&&) noexcept;

    // Initialize as server with certificate and key
    [[nodiscard]] std::expected<void, TlsError> init_server(
        const std::string& cert_path,
        const std::string& key_path
    );

    // Initialize as server with in-memory cert and key (PEM format)
    [[nodiscard]] std::expected<void, TlsError> init_server(
        std::span<const uint8_t> cert_pem,
        std::span<const uint8_t> key_pem
    );

    // Initialize as client
    [[nodiscard]] std::expected<void, TlsError> init_client();

    // Set minimum TLS version
    void set_min_version(TlsVersion version);

    // Set cipher list (OpenSSL format)
    [[nodiscard]] std::expected<void, TlsError> set_ciphers(const std::string& ciphers);

    // Generate self-signed certificate for relay
    [[nodiscard]] static std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, TlsError>
    generate_self_signed_cert(const Ed25519SecretKey& identity_key);

    // Get internal handle (for use with TlsConnection)
    [[nodiscard]] void* native_handle() { return ctx_; }

    [[nodiscard]] bool is_initialized() const { return ctx_ != nullptr; }

private:
    void* ctx_{nullptr};  // SSL_CTX*
};

// TLS connection wrapping a socket
class TlsConnection {
public:
    TlsConnection();
    ~TlsConnection();

    // Disable copying, allow moving
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
    TlsConnection(TlsConnection&&) noexcept;
    TlsConnection& operator=(TlsConnection&&) noexcept;

    // Initialize with context and file descriptor
    [[nodiscard]] std::expected<void, TlsError> init(TlsContext& ctx, int fd);

    // Perform handshake (may need to be called multiple times for non-blocking)
    [[nodiscard]] std::expected<void, TlsError> handshake();

    // Accept incoming connection (server side)
    [[nodiscard]] std::expected<void, TlsError> accept();

    // Connect to peer (client side)
    [[nodiscard]] std::expected<void, TlsError> connect();

    // Read data
    [[nodiscard]] std::expected<size_t, TlsError> read(std::span<uint8_t> buffer);

    // Write data
    [[nodiscard]] std::expected<size_t, TlsError> write(std::span<const uint8_t> data);

    // Shutdown connection
    [[nodiscard]] std::expected<void, TlsError> shutdown();

    // Check if handshake is complete
    [[nodiscard]] bool is_handshake_complete() const;

    // Get peer certificate (if any)
    [[nodiscard]] std::expected<std::vector<uint8_t>, TlsError> get_peer_certificate() const;

    // Get negotiated cipher
    [[nodiscard]] std::string get_cipher() const;

    // Get TLS version
    [[nodiscard]] std::string get_version() const;

private:
    void* ssl_{nullptr};  // SSL*
    bool handshake_complete_{false};
};

// In-memory BIO for testing
class MemoryBio {
public:
    MemoryBio();
    ~MemoryBio();

    // Disable copying, allow moving
    MemoryBio(const MemoryBio&) = delete;
    MemoryBio& operator=(const MemoryBio&) = delete;
    MemoryBio(MemoryBio&&) noexcept;
    MemoryBio& operator=(MemoryBio&&) noexcept;

    // Write data to BIO
    [[nodiscard]] std::expected<size_t, TlsError> write(std::span<const uint8_t> data);

    // Read data from BIO
    [[nodiscard]] std::expected<size_t, TlsError> read(std::span<uint8_t> buffer);

    // Get pending bytes to read
    [[nodiscard]] size_t pending() const;

    // Get internal handle
    [[nodiscard]] void* native_handle() { return bio_; }

private:
    void* bio_{nullptr};  // BIO*
};

// Utility
[[nodiscard]] std::string tls_error_message(TlsError err);
[[nodiscard]] std::string get_openssl_error();

}  // namespace tor::crypto
