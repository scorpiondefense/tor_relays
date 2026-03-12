#include "tor/crypto/tls.hpp"
#include "tor/util/logging.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstring>
#include <cerrno>
#include <sys/select.h>
#include <sstream>
#include <iomanip>

namespace tor::crypto {

// TlsContext implementation
TlsContext::TlsContext() = default;

TlsContext::~TlsContext() {
    if (ctx_) {
        SSL_CTX_free(static_cast<SSL_CTX*>(ctx_));
    }
}

TlsContext::TlsContext(TlsContext&& other) noexcept : ctx_(other.ctx_) {
    other.ctx_ = nullptr;
}

TlsContext& TlsContext::operator=(TlsContext&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            SSL_CTX_free(static_cast<SSL_CTX*>(ctx_));
        }
        ctx_ = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

std::expected<void, TlsError> TlsContext::init_server(
    const std::string& cert_path,
    const std::string& key_path
) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) {
        return std::unexpected(TlsError::ContextCreationFailed);
    }

    auto* ssl_ctx = static_cast<SSL_CTX*>(ctx_);

    // Set minimum TLS version
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    // Load certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        ctx_ = nullptr;
        return std::unexpected(TlsError::CertificateLoadFailed);
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        ctx_ = nullptr;
        return std::unexpected(TlsError::KeyLoadFailed);
    }

    return {};
}

std::expected<void, TlsError> TlsContext::init_server(
    std::span<const uint8_t> cert_pem,
    std::span<const uint8_t> key_pem
) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) {
        return std::unexpected(TlsError::ContextCreationFailed);
    }

    auto* ssl_ctx = static_cast<SSL_CTX*>(ctx_);
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    // Load certificate from memory
    BIO* cert_bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);

    if (!cert || SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
        if (cert) X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        ctx_ = nullptr;
        return std::unexpected(TlsError::CertificateLoadFailed);
    }
    X509_free(cert);

    // Load private key from memory
    BIO* key_bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);

    if (!pkey || SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        SSL_CTX_free(ssl_ctx);
        ctx_ = nullptr;
        return std::unexpected(TlsError::KeyLoadFailed);
    }
    EVP_PKEY_free(pkey);

    return {};
}

std::expected<void, TlsError> TlsContext::init_client() {
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        return std::unexpected(TlsError::ContextCreationFailed);
    }

    auto* ssl_ctx = static_cast<SSL_CTX*>(ctx_);
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    return {};
}

void TlsContext::set_min_version(TlsVersion version) {
    if (!ctx_) return;

    auto* ssl_ctx = static_cast<SSL_CTX*>(ctx_);
    int ver = (version == TlsVersion::TLS_1_3) ? TLS1_3_VERSION : TLS1_2_VERSION;
    SSL_CTX_set_min_proto_version(ssl_ctx, ver);
}

std::expected<void, TlsError> TlsContext::set_ciphers(const std::string& ciphers) {
    if (!ctx_) {
        return std::unexpected(TlsError::ContextCreationFailed);
    }

    auto* ssl_ctx = static_cast<SSL_CTX*>(ctx_);
    if (SSL_CTX_set_cipher_list(ssl_ctx, ciphers.c_str()) != 1) {
        return std::unexpected(TlsError::OpenSSLError);
    }

    return {};
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, TlsError>
TlsContext::generate_self_signed_cert(const Ed25519SecretKey& identity_key) {
    // Generate RSA key for TLS (Ed25519 not directly usable in TLS certs)
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) {
        return std::unexpected(TlsError::KeyLoadFailed);
    }

    // Create certificate
    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return std::unexpected(TlsError::CertificateLoadFailed);
    }

    // X.509 v3 (version field = 2) — matches standard Tor TLS certs
    X509_set_version(x509, 2);

    // Set random serial number (avoid fingerprinting with fixed serial)
    {
        uint8_t serial_bytes[8];
        RAND_bytes(serial_bytes, sizeof(serial_bytes));
        BIGNUM* bn_serial = BN_bin2bn(serial_bytes, sizeof(serial_bytes), nullptr);
        if (bn_serial) {
            BN_to_ASN1_INTEGER(bn_serial, X509_get_serialNumber(x509));
            BN_free(bn_serial);
        }
    }

    // Set validity: random offset in past (0-30 days) to now+1 year
    // Matches standard Tor behavior of randomizing notBefore
    {
        uint32_t rand_offset;
        RAND_bytes(reinterpret_cast<uint8_t*>(&rand_offset), sizeof(rand_offset));
        long past_offset = -static_cast<long>(rand_offset % (30 * 24 * 60 * 60));
        X509_gmtime_adj(X509_get_notBefore(x509), past_offset);
        X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);
    }

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject name - use random-looking hostname to avoid fingerprinting
    // Standard Tor generates random hostnames like "www.XXXXX.com"
    {
        uint8_t cn_rand[8];
        RAND_bytes(cn_rand, sizeof(cn_rand));
        std::ostringstream cn_oss;
        cn_oss << "www.";
        for (int i = 0; i < 8; ++i)
            cn_oss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(cn_rand[i]);
        cn_oss << ".net";
        std::string cn = cn_oss.str();

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(cn.c_str()),
                                   -1, -1, 0);
        X509_set_issuer_name(x509, name);
    }

    // Sign certificate
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return std::unexpected(TlsError::CertificateLoadFailed);
    }

    // Export certificate to PEM
    BIO* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, x509);

    BUF_MEM* cert_mem;
    BIO_get_mem_ptr(cert_bio, &cert_mem);
    std::vector<uint8_t> cert_pem(cert_mem->data, cert_mem->data + cert_mem->length);
    BIO_free(cert_bio);

    // Export private key to PEM
    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    BUF_MEM* key_mem;
    BIO_get_mem_ptr(key_bio, &key_mem);
    std::vector<uint8_t> key_pem(key_mem->data, key_mem->data + key_mem->length);
    BIO_free(key_bio);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return std::make_pair(cert_pem, key_pem);
}

// TlsConnection implementation
TlsConnection::TlsConnection() = default;

TlsConnection::~TlsConnection() {
    if (ssl_) {
        SSL_free(static_cast<SSL*>(ssl_));
    }
}

TlsConnection::TlsConnection(TlsConnection&& other) noexcept
    : ssl_(other.ssl_), handshake_complete_(other.handshake_complete_) {
    other.ssl_ = nullptr;
    other.handshake_complete_ = false;
}

TlsConnection& TlsConnection::operator=(TlsConnection&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            SSL_free(static_cast<SSL*>(ssl_));
        }
        ssl_ = other.ssl_;
        handshake_complete_ = other.handshake_complete_;
        other.ssl_ = nullptr;
        other.handshake_complete_ = false;
    }
    return *this;
}

std::expected<void, TlsError> TlsConnection::init(TlsContext& ctx, int fd) {
    if (!ctx.is_initialized()) {
        return std::unexpected(TlsError::ContextCreationFailed);
    }

    ssl_ = SSL_new(static_cast<SSL_CTX*>(ctx.native_handle()));
    if (!ssl_) {
        return std::unexpected(TlsError::ContextCreationFailed);
    }

    if (SSL_set_fd(static_cast<SSL*>(ssl_), fd) != 1) {
        SSL_free(static_cast<SSL*>(ssl_));
        ssl_ = nullptr;
        return std::unexpected(TlsError::OpenSSLError);
    }

    return {};
}

std::expected<void, TlsError> TlsConnection::handshake() {
    if (!ssl_) {
        return std::unexpected(TlsError::HandshakeFailed);
    }

    // Retry handshake on WANT_READ/WANT_WRITE (non-blocking socket support)
    for (int attempts = 0; attempts < 100; ++attempts) {
        int result = SSL_do_handshake(static_cast<SSL*>(ssl_));
        if (result == 1) {
            handshake_complete_ = true;
            return {};
        }

        int err = SSL_get_error(static_cast<SSL*>(ssl_), result);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Wait for socket to be ready using select()
            int fd = SSL_get_fd(static_cast<SSL*>(ssl_));
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            struct timeval tv = {10, 0}; // 10 second timeout

            int sel_result;
            if (err == SSL_ERROR_WANT_READ) {
                sel_result = select(fd + 1, &fds, nullptr, nullptr, &tv);
            } else {
                sel_result = select(fd + 1, nullptr, &fds, nullptr, &tv);
            }

            if (sel_result <= 0) {
                return std::unexpected(TlsError::HandshakeFailed);
            }
            continue;
        }

        return std::unexpected(TlsError::HandshakeFailed);
    }

    return std::unexpected(TlsError::HandshakeFailed);
}

std::expected<void, TlsError> TlsConnection::accept() {
    if (!ssl_) {
        return std::unexpected(TlsError::HandshakeFailed);
    }

    SSL_set_accept_state(static_cast<SSL*>(ssl_));
    return handshake();
}

std::expected<void, TlsError> TlsConnection::connect() {
    if (!ssl_) {
        return std::unexpected(TlsError::HandshakeFailed);
    }

    SSL_set_connect_state(static_cast<SSL*>(ssl_));
    return handshake();
}

std::expected<size_t, TlsError> TlsConnection::read(std::span<uint8_t> buffer) {
    if (!ssl_ || !handshake_complete_) {
        return std::unexpected(TlsError::ReadFailed);
    }

    // Clear any stale errors before SSL_read
    ERR_clear_error();

    for (int attempts = 0; attempts < 100; ++attempts) {
        // Check SSL_pending first
        int pending = SSL_pending(static_cast<SSL*>(ssl_));
        if (pending > 0) {
            LOG_DEBUG("TLS read: {} bytes pending in SSL buffer", pending);
        }

        int result = SSL_read(static_cast<SSL*>(ssl_), buffer.data(),
                              static_cast<int>(buffer.size()));
        if (result > 0) {
            return static_cast<size_t>(result);
        }

        int err = SSL_get_error(static_cast<SSL*>(ssl_), result);
        int saved_errno = errno;
        LOG_DEBUG("TLS read: SSL_read returned {}, SSL_error={}, errno={} ({}), attempt={}",
                  result, err, saved_errno, strerror(saved_errno), attempts);

        if (err == SSL_ERROR_ZERO_RETURN) {
            LOG_DEBUG("TLS read: peer sent close_notify");
            return std::unexpected(TlsError::ConnectionClosed);
        }
        if (err == SSL_ERROR_SYSCALL) {
            unsigned long ossl_err = ERR_peek_error();
            LOG_DEBUG("TLS read: SSL_ERROR_SYSCALL, errno={}, openssl_err={}",
                      saved_errno, ossl_err);
            if (result == 0) {
                LOG_DEBUG("TLS read: unexpected EOF (peer closed without close_notify)");
                return std::unexpected(TlsError::ConnectionClosed);
            }
            return std::unexpected(TlsError::ReadFailed);
        }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            int fd = SSL_get_fd(static_cast<SSL*>(ssl_));
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            struct timeval tv = {300, 0}; // 5 minute timeout for reads
            int sel_result;
            if (err == SSL_ERROR_WANT_READ) {
                sel_result = select(fd + 1, &fds, nullptr, nullptr, &tv);
            } else {
                sel_result = select(fd + 1, nullptr, &fds, nullptr, &tv);
            }
            if (sel_result <= 0) {
                LOG_DEBUG("TLS read: select returned {} (timeout or error)", sel_result);
                return std::unexpected(TlsError::ReadFailed);
            }
            continue;
        }

        if (err == SSL_ERROR_SSL) {
            unsigned long ossl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ossl_err, err_buf, sizeof(err_buf));
            LOG_DEBUG("TLS read: SSL_ERROR_SSL: {}", err_buf);
        }

        return std::unexpected(TlsError::ReadFailed);
    }

    return std::unexpected(TlsError::ReadFailed);
}

std::expected<size_t, TlsError> TlsConnection::write(std::span<const uint8_t> data) {
    if (!ssl_ || !handshake_complete_) {
        return std::unexpected(TlsError::WriteFailed);
    }

    size_t total_written = 0;
    while (total_written < data.size()) {
        for (int attempts = 0; attempts < 100; ++attempts) {
            int result = SSL_write(static_cast<SSL*>(ssl_),
                                   data.data() + total_written,
                                   static_cast<int>(data.size() - total_written));
            if (result > 0) {
                total_written += static_cast<size_t>(result);
                break;
            }

            int err = SSL_get_error(static_cast<SSL*>(ssl_), result);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                int fd = SSL_get_fd(static_cast<SSL*>(ssl_));
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                struct timeval tv = {10, 0}; // 10 second timeout for writes
                int sel_result;
                if (err == SSL_ERROR_WANT_READ) {
                    sel_result = select(fd + 1, &fds, nullptr, nullptr, &tv);
                } else {
                    sel_result = select(fd + 1, nullptr, &fds, nullptr, &tv);
                }
                if (sel_result <= 0) {
                    return std::unexpected(TlsError::WriteFailed);
                }
                continue;
            }

            return std::unexpected(TlsError::WriteFailed);
        }
    }

    return total_written;
}

std::expected<void, TlsError> TlsConnection::shutdown() {
    if (!ssl_) {
        return {};
    }

    SSL_shutdown(static_cast<SSL*>(ssl_));
    return {};
}

bool TlsConnection::is_handshake_complete() const {
    return handshake_complete_;
}

std::expected<std::vector<uint8_t>, TlsError> TlsConnection::get_peer_certificate() const {
    if (!ssl_) {
        return std::unexpected(TlsError::OpenSSLError);
    }

    X509* cert = SSL_get_peer_certificate(static_cast<SSL*>(ssl_));
    if (!cert) {
        return std::unexpected(TlsError::CertificateLoadFailed);
    }

    BIO* bio = BIO_new(BIO_s_mem());
    i2d_X509_bio(bio, cert);

    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    std::vector<uint8_t> result(mem->data, mem->data + mem->length);

    BIO_free(bio);
    X509_free(cert);

    return result;
}

std::string TlsConnection::get_cipher() const {
    if (!ssl_) return "";
    const char* cipher = SSL_get_cipher(static_cast<SSL*>(ssl_));
    return cipher ? cipher : "";
}

std::string TlsConnection::get_version() const {
    if (!ssl_) return "";
    const char* version = SSL_get_version(static_cast<SSL*>(ssl_));
    return version ? version : "";
}

// MemoryBio implementation
MemoryBio::MemoryBio() {
    bio_ = BIO_new(BIO_s_mem());
}

MemoryBio::~MemoryBio() {
    if (bio_) {
        BIO_free(static_cast<BIO*>(bio_));
    }
}

MemoryBio::MemoryBio(MemoryBio&& other) noexcept : bio_(other.bio_) {
    other.bio_ = nullptr;
}

MemoryBio& MemoryBio::operator=(MemoryBio&& other) noexcept {
    if (this != &other) {
        if (bio_) {
            BIO_free(static_cast<BIO*>(bio_));
        }
        bio_ = other.bio_;
        other.bio_ = nullptr;
    }
    return *this;
}

std::expected<size_t, TlsError> MemoryBio::write(std::span<const uint8_t> data) {
    if (!bio_) {
        return std::unexpected(TlsError::OpenSSLError);
    }

    int result = BIO_write(static_cast<BIO*>(bio_), data.data(),
                           static_cast<int>(data.size()));
    if (result < 0) {
        return std::unexpected(TlsError::WriteFailed);
    }

    return static_cast<size_t>(result);
}

std::expected<size_t, TlsError> MemoryBio::read(std::span<uint8_t> buffer) {
    if (!bio_) {
        return std::unexpected(TlsError::OpenSSLError);
    }

    int result = BIO_read(static_cast<BIO*>(bio_), buffer.data(),
                          static_cast<int>(buffer.size()));
    if (result < 0) {
        return std::unexpected(TlsError::ReadFailed);
    }

    return static_cast<size_t>(result);
}

size_t MemoryBio::pending() const {
    if (!bio_) return 0;
    return BIO_ctrl_pending(static_cast<BIO*>(bio_));
}

// Utility functions
std::string tls_error_message(TlsError err) {
    switch (err) {
        case TlsError::ContextCreationFailed: return "TLS context creation failed";
        case TlsError::CertificateLoadFailed: return "Certificate load failed";
        case TlsError::KeyLoadFailed: return "Key load failed";
        case TlsError::HandshakeFailed: return "TLS handshake failed";
        case TlsError::ReadFailed: return "TLS read failed";
        case TlsError::WriteFailed: return "TLS write failed";
        case TlsError::VerificationFailed: return "Certificate verification failed";
        case TlsError::ConnectionClosed: return "Connection closed";
        case TlsError::WouldBlock: return "Operation would block";
        case TlsError::OpenSSLError: return "OpenSSL error";
        default: return "Unknown TLS error";
    }
}

std::string get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

}  // namespace tor::crypto
