#include "tor/crypto/keys.hpp"
#include "tor/crypto/hash.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace tor::crypto {

// Secure memory zeroing
void secure_zero(void* ptr, size_t len) {
    OPENSSL_cleanse(ptr, len);
}

// Generate random bytes
std::vector<uint8_t> random_bytes(size_t len) {
    std::vector<uint8_t> result(len);
    if (RAND_bytes(result.data(), static_cast<int>(len)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return result;
}

// Ed25519PublicKey implementation
Ed25519PublicKey::Ed25519PublicKey(std::array<uint8_t, SIZE> data)
    : data_(data) {}

Ed25519PublicKey::Ed25519PublicKey(std::span<const uint8_t> data) {
    if (data.size() != SIZE) {
        throw std::invalid_argument("Invalid Ed25519 public key length");
    }
    std::copy(data.begin(), data.end(), data_.begin());
}

std::string Ed25519PublicKey::to_base64() const {
    return tor::crypto::to_base64(data_);
}

std::string Ed25519PublicKey::fingerprint() const {
    auto hash = sha256(data_);
    if (!hash) {
        return "";
    }
    return to_hex(*hash);
}

bool Ed25519PublicKey::verify(
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature
) const {
    if (signature.size() != ED25519_SIGNATURE_LEN) {
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, data_.data(), data_.size());
    if (!pkey) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool result = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        result = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                  message.data(), message.size()) == 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

std::expected<Ed25519PublicKey, KeyError>
Ed25519PublicKey::from_base64(const std::string& encoded) {
    auto decoded = tor::crypto::from_base64(encoded);
    if (!decoded) {
        return std::unexpected(KeyError::ParseError);
    }
    if (decoded->size() != SIZE) {
        return std::unexpected(KeyError::InvalidKeyLength);
    }

    std::array<uint8_t, SIZE> data;
    std::copy(decoded->begin(), decoded->end(), data.begin());
    return Ed25519PublicKey(data);
}

// Ed25519SecretKey implementation
Ed25519SecretKey::~Ed25519SecretKey() {
    clear();
}

Ed25519SecretKey::Ed25519SecretKey(Ed25519SecretKey&& other) noexcept
    : data_(other.data_)
    , public_key_(std::move(other.public_key_))
    , initialized_(other.initialized_) {
    other.clear();
}

Ed25519SecretKey& Ed25519SecretKey::operator=(Ed25519SecretKey&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = other.data_;
        public_key_ = std::move(other.public_key_);
        initialized_ = other.initialized_;
        other.clear();
    }
    return *this;
}

void Ed25519SecretKey::clear() {
    secure_zero(data_.data(), data_.size());
    initialized_ = false;
}

std::expected<Ed25519SecretKey, KeyError> Ed25519SecretKey::generate() {
    Ed25519SecretKey key;

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        return std::unexpected(KeyError::GenerationFailed);
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::GenerationFailed);
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::GenerationFailed);
    }
    EVP_PKEY_CTX_free(ctx);

    // Extract private key
    size_t len = SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, key.data_.data(), &len) != 1) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::GenerationFailed);
    }

    // Extract public key
    std::array<uint8_t, ED25519_PUBLIC_KEY_LEN> pub_data;
    len = ED25519_PUBLIC_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_data.data(), &len) != 1) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::GenerationFailed);
    }

    EVP_PKEY_free(pkey);

    key.public_key_ = Ed25519PublicKey(pub_data);
    key.initialized_ = true;

    return key;
}

std::expected<Ed25519SecretKey, KeyError>
Ed25519SecretKey::from_seed(std::span<const uint8_t> seed) {
    if (seed.size() != SEED_SIZE) {
        return std::unexpected(KeyError::InvalidKeyLength);
    }

    Ed25519SecretKey key;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (!pkey) {
        return std::unexpected(KeyError::InvalidKey);
    }

    // Store seed as private key
    std::copy(seed.begin(), seed.end(), key.data_.begin());

    // Extract public key
    std::array<uint8_t, ED25519_PUBLIC_KEY_LEN> pub_data;
    size_t len = ED25519_PUBLIC_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_data.data(), &len) != 1) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::DerivationFailed);
    }

    EVP_PKEY_free(pkey);

    key.public_key_ = Ed25519PublicKey(pub_data);
    key.initialized_ = true;

    return key;
}

std::span<const uint8_t> Ed25519SecretKey::seed() const {
    return std::span<const uint8_t>(data_.data(), SEED_SIZE);
}

std::expected<std::array<uint8_t, ED25519_SIGNATURE_LEN>, KeyError>
Ed25519SecretKey::sign(std::span<const uint8_t> message) const {
    if (!initialized_) {
        return std::unexpected(KeyError::InvalidKey);
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, data_.data(), SEED_SIZE);
    if (!pkey) {
        return std::unexpected(KeyError::SigningFailed);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::SigningFailed);
    }

    std::array<uint8_t, ED25519_SIGNATURE_LEN> signature;
    size_t sig_len = signature.size();

    bool success = false;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        if (EVP_DigestSign(ctx, signature.data(), &sig_len,
                          message.data(), message.size()) == 1) {
            success = true;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (!success) {
        return std::unexpected(KeyError::SigningFailed);
    }

    return signature;
}

// Curve25519PublicKey implementation
Curve25519PublicKey::Curve25519PublicKey(std::array<uint8_t, SIZE> data)
    : data_(data) {}

Curve25519PublicKey::Curve25519PublicKey(std::span<const uint8_t> data) {
    if (data.size() != SIZE) {
        throw std::invalid_argument("Invalid Curve25519 public key length");
    }
    std::copy(data.begin(), data.end(), data_.begin());
}

std::string Curve25519PublicKey::to_base64() const {
    return tor::crypto::to_base64(data_);
}

std::expected<Curve25519PublicKey, KeyError>
Curve25519PublicKey::from_base64(const std::string& encoded) {
    auto decoded = tor::crypto::from_base64(encoded);
    if (!decoded) {
        return std::unexpected(KeyError::ParseError);
    }
    if (decoded->size() != SIZE) {
        return std::unexpected(KeyError::InvalidKeyLength);
    }

    std::array<uint8_t, SIZE> data;
    std::copy(decoded->begin(), decoded->end(), data.begin());
    return Curve25519PublicKey(data);
}

bool Curve25519PublicKey::is_low_order() const {
    // Check for known low-order points (must reject these in X25519)
    static const std::array<std::array<uint8_t, 32>, 5> LOW_ORDER_POINTS = {{
        {0},  // Point at infinity
        {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // (1, 0)
        {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
         0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
         0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
        {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
         0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
         0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
    }};

    for (const auto& point : LOW_ORDER_POINTS) {
        if (data_ == point) {
            return true;
        }
    }
    return false;
}

// Curve25519SecretKey implementation
Curve25519SecretKey::~Curve25519SecretKey() {
    clear();
}

Curve25519SecretKey::Curve25519SecretKey(Curve25519SecretKey&& other) noexcept
    : data_(other.data_)
    , public_key_(std::move(other.public_key_))
    , initialized_(other.initialized_) {
    other.clear();
}

Curve25519SecretKey& Curve25519SecretKey::operator=(Curve25519SecretKey&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = other.data_;
        public_key_ = std::move(other.public_key_);
        initialized_ = other.initialized_;
        other.clear();
    }
    return *this;
}

void Curve25519SecretKey::clear() {
    secure_zero(data_.data(), data_.size());
    initialized_ = false;
}

std::expected<Curve25519SecretKey, KeyError> Curve25519SecretKey::generate() {
    Curve25519SecretKey key;

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        return std::unexpected(KeyError::GenerationFailed);
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::GenerationFailed);
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::GenerationFailed);
    }
    EVP_PKEY_CTX_free(ctx);

    // Extract private key
    size_t len = SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, key.data_.data(), &len) != 1) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::GenerationFailed);
    }

    // Extract public key
    std::array<uint8_t, CURVE25519_KEY_LEN> pub_data;
    len = CURVE25519_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_data.data(), &len) != 1) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::GenerationFailed);
    }

    EVP_PKEY_free(pkey);

    key.public_key_ = Curve25519PublicKey(pub_data);
    key.initialized_ = true;

    return key;
}

std::expected<Curve25519SecretKey, KeyError>
Curve25519SecretKey::from_bytes(std::span<const uint8_t> data) {
    if (data.size() != SIZE) {
        return std::unexpected(KeyError::InvalidKeyLength);
    }

    Curve25519SecretKey key;
    std::copy(data.begin(), data.end(), key.data_.begin());

    // Derive public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, key.data_.data(), SIZE);
    if (!pkey) {
        return std::unexpected(KeyError::InvalidKey);
    }

    std::array<uint8_t, CURVE25519_KEY_LEN> pub_data;
    size_t len = CURVE25519_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_data.data(), &len) != 1) {
        EVP_PKEY_free(pkey);
        return std::unexpected(KeyError::DerivationFailed);
    }

    EVP_PKEY_free(pkey);

    key.public_key_ = Curve25519PublicKey(pub_data);
    key.initialized_ = true;

    return key;
}

std::expected<std::array<uint8_t, Curve25519SecretKey::SIZE>, KeyError>
Curve25519SecretKey::diffie_hellman(const Curve25519PublicKey& peer_public) const {
    if (!initialized_) {
        return std::unexpected(KeyError::InvalidKey);
    }

    // Check for low-order points
    if (peer_public.is_low_order()) {
        return std::unexpected(KeyError::InvalidKey);
    }

    EVP_PKEY* our_key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, data_.data(), SIZE);
    if (!our_key) {
        return std::unexpected(KeyError::DerivationFailed);
    }

    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, peer_public.data().data(), peer_public.data().size());
    if (!peer_key) {
        EVP_PKEY_free(our_key);
        return std::unexpected(KeyError::DerivationFailed);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(our_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(our_key);
        EVP_PKEY_free(peer_key);
        return std::unexpected(KeyError::DerivationFailed);
    }

    std::array<uint8_t, SIZE> shared_secret;
    size_t secret_len = SIZE;

    bool success = false;
    if (EVP_PKEY_derive_init(ctx) == 1) {
        if (EVP_PKEY_derive_set_peer(ctx, peer_key) == 1) {
            if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) == 1) {
                success = true;
            }
        }
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(our_key);
    EVP_PKEY_free(peer_key);

    if (!success) {
        return std::unexpected(KeyError::DerivationFailed);
    }

    return shared_secret;
}

// Rsa1024Identity implementation
Rsa1024Identity::~Rsa1024Identity() {
    if (pkey_) {
        EVP_PKEY_free(pkey_);
    }
}

Rsa1024Identity::Rsa1024Identity(Rsa1024Identity&& other) noexcept
    : pkey_(other.pkey_) {
    other.pkey_ = nullptr;
}

Rsa1024Identity& Rsa1024Identity::operator=(Rsa1024Identity&& other) noexcept {
    if (this != &other) {
        if (pkey_) {
            EVP_PKEY_free(pkey_);
        }
        pkey_ = other.pkey_;
        other.pkey_ = nullptr;
    }
    return *this;
}

std::expected<Rsa1024Identity, KeyError> Rsa1024Identity::generate() {
    Rsa1024Identity key;
    key.pkey_ = EVP_RSA_gen(1024);
    if (!key.pkey_) {
        return std::unexpected(KeyError::GenerationFailed);
    }
    return key;
}

std::expected<Rsa1024Identity, KeyError>
Rsa1024Identity::from_der_private(std::span<const uint8_t> der) {
    Rsa1024Identity key;
    const unsigned char* p = der.data();
    key.pkey_ = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p,
                                static_cast<long>(der.size()));
    if (!key.pkey_) {
        return std::unexpected(KeyError::ParseError);
    }
    return key;
}

std::vector<uint8_t> Rsa1024Identity::private_key_der() const {
    if (!pkey_) return {};
    int len = i2d_PrivateKey(pkey_, nullptr);
    if (len <= 0) return {};
    std::vector<uint8_t> der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_PrivateKey(pkey_, &p);
    return der;
}

std::vector<uint8_t> Rsa1024Identity::public_key_der() const {
    if (!pkey_) return {};
    int len = i2d_PUBKEY(pkey_, nullptr);
    if (len <= 0) return {};
    std::vector<uint8_t> der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_PUBKEY(pkey_, &p);
    return der;
}

std::expected<std::vector<uint8_t>, KeyError>
Rsa1024Identity::sign_sha256(std::span<const uint8_t> data) const {
    if (!pkey_) {
        return std::unexpected(KeyError::InvalidKey);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return std::unexpected(KeyError::SigningFailed);
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey_) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    EVP_MD_CTX_free(ctx);
    sig.resize(sig_len);
    return sig;
}

std::expected<std::vector<uint8_t>, KeyError>
Rsa1024Identity::create_identity_cert() const {
    if (!pkey_) {
        return std::unexpected(KeyError::InvalidKey);
    }

    X509* x509 = X509_new();
    if (!x509) {
        return std::unexpected(KeyError::OpenSSLError);
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);
    X509_set_pubkey(x509, pkey_);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Tor relay"), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey_, EVP_sha256()) == 0) {
        X509_free(x509);
        return std::unexpected(KeyError::SigningFailed);
    }

    int der_len = i2d_X509(x509, nullptr);
    if (der_len <= 0) {
        X509_free(x509);
        return std::unexpected(KeyError::OpenSSLError);
    }

    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    unsigned char* p = der.data();
    i2d_X509(x509, &p);
    X509_free(x509);

    return der;
}

std::expected<std::vector<uint8_t>, KeyError>
Rsa1024Identity::create_link_cert(EVP_PKEY* tls_pkey) const {
    if (!pkey_ || !tls_pkey) {
        return std::unexpected(KeyError::InvalidKey);
    }

    X509* x509 = X509_new();
    if (!x509) {
        return std::unexpected(KeyError::OpenSSLError);
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 2);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);

    // Set the TLS public key as the subject key
    X509_set_pubkey(x509, tls_pkey);

    X509_NAME* subject = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Tor relay"), -1, -1, 0);

    // Issuer is the RSA identity key
    X509_NAME* issuer = X509_NAME_new();
    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Tor relay"), -1, -1, 0);
    X509_set_issuer_name(x509, issuer);
    X509_NAME_free(issuer);

    // Sign with RSA identity key
    if (X509_sign(x509, pkey_, EVP_sha256()) == 0) {
        X509_free(x509);
        return std::unexpected(KeyError::SigningFailed);
    }

    int der_len = i2d_X509(x509, nullptr);
    if (der_len <= 0) {
        X509_free(x509);
        return std::unexpected(KeyError::OpenSSLError);
    }

    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    unsigned char* p = der.data();
    i2d_X509(x509, &p);
    X509_free(x509);

    return der;
}

std::expected<std::vector<uint8_t>, KeyError>
Rsa1024Identity::sign_raw(std::span<const uint8_t> data) const {
    if (!pkey_) {
        return std::unexpected(KeyError::InvalidKey);
    }

    // Raw RSA signing with PKCS1 padding (no digest wrapping).
    // Equivalent to Tor's crypto_pk_private_sign which calls
    // RSA_private_encrypt(data, RSA_PKCS1_PADDING).
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
    if (!ctx) {
        return std::unexpected(KeyError::SigningFailed);
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    // No digest set — signs the raw data directly

    // Get required signature length
    size_t sig_len = 0;
    if (EVP_PKEY_sign(ctx, nullptr, &sig_len, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    std::vector<uint8_t> sig(sig_len);
    if (EVP_PKEY_sign(ctx, sig.data(), &sig_len, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return std::unexpected(KeyError::SigningFailed);
    }

    EVP_PKEY_CTX_free(ctx);
    sig.resize(sig_len);
    return sig;
}

std::expected<std::vector<uint8_t>, KeyError>
Rsa1024Identity::create_ed25519_cross_cert(const Ed25519PublicKey& ed_pub) const {
    if (!pkey_) {
        return std::unexpected(KeyError::InvalidKey);
    }

    // Binary format per cert-spec.txt:
    // ED25519_KEY (32 bytes) || EXPIRATION_DATE (4 bytes, hours since epoch)
    // || SIGLEN (1 byte) || RSA_SIG (variable, 128 bytes for 1024-bit key)
    //
    // Tor signs SHA256(prefix || ED25519_KEY || EXPIRATION) with raw RSA
    // (RSA_private_encrypt of the 32-byte hash, NOT RSA-SHA256 DigestInfo).

    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    uint32_t exp_hours = static_cast<uint32_t>((secs / 3600) + 24);

    // Build the data to hash
    const std::string prefix = "Tor TLS RSA/Ed25519 cross-certificate";
    std::vector<uint8_t> to_hash;
    to_hash.insert(to_hash.end(), prefix.begin(), prefix.end());
    auto ed_data = ed_pub.as_span();
    to_hash.insert(to_hash.end(), ed_data.begin(), ed_data.end());
    // Expiration in network byte order (big-endian)
    to_hash.push_back(static_cast<uint8_t>((exp_hours >> 24) & 0xFF));
    to_hash.push_back(static_cast<uint8_t>((exp_hours >> 16) & 0xFF));
    to_hash.push_back(static_cast<uint8_t>((exp_hours >> 8) & 0xFF));
    to_hash.push_back(static_cast<uint8_t>(exp_hours & 0xFF));

    // Compute SHA256 digest
    std::array<uint8_t, 32> digest;
    SHA256(to_hash.data(), to_hash.size(), digest.data());

    // Raw RSA signature of the 32-byte SHA256 hash
    // (matches Tor's crypto_pk_private_sign which uses RSA_private_encrypt)
    auto sig = sign_raw(digest);
    if (!sig) {
        return std::unexpected(sig.error());
    }

    // Build the cross-cert
    std::vector<uint8_t> cert;
    // ED25519_KEY (32 bytes)
    cert.insert(cert.end(), ed_data.begin(), ed_data.end());
    // EXPIRATION_DATE (4 bytes, big-endian)
    cert.push_back(static_cast<uint8_t>((exp_hours >> 24) & 0xFF));
    cert.push_back(static_cast<uint8_t>((exp_hours >> 16) & 0xFF));
    cert.push_back(static_cast<uint8_t>((exp_hours >> 8) & 0xFF));
    cert.push_back(static_cast<uint8_t>(exp_hours & 0xFF));
    // SIGLEN (1 byte)
    cert.push_back(static_cast<uint8_t>(sig->size()));
    // RSA_SIG
    cert.insert(cert.end(), sig->begin(), sig->end());

    return cert;
}

// RelayKeyPair implementation
std::expected<RelayKeyPair, KeyError> RelayKeyPair::generate() {
    auto identity = Ed25519SecretKey::generate();
    if (!identity) {
        return std::unexpected(identity.error());
    }

    auto onion = Curve25519SecretKey::generate();
    if (!onion) {
        return std::unexpected(onion.error());
    }

    auto rsa = Rsa1024Identity::generate();
    if (!rsa) {
        return std::unexpected(rsa.error());
    }

    return RelayKeyPair{std::move(*identity), std::move(*onion), std::move(*rsa)};
}

// NodeId implementation
NodeId::NodeId(std::array<uint8_t, SIZE> data) : data_(data) {}

NodeId::NodeId(const Ed25519PublicKey& identity_key) {
    auto hash = sha1(identity_key.as_span());
    if (hash) {
        data_ = *hash;
    }
}

NodeId::NodeId(std::span<const uint8_t> rsa_public_key_der) {
    auto hash = sha1(rsa_public_key_der);
    if (hash) {
        data_ = *hash;
    }
}

std::string NodeId::to_hex() const {
    return tor::crypto::to_hex(data_);
}

std::string NodeId::to_base64() const {
    return tor::crypto::to_base64(data_);
}

std::expected<NodeId, KeyError> NodeId::from_hex(const std::string& hex) {
    auto decoded = tor::crypto::from_hex(hex);
    if (!decoded) {
        return std::unexpected(KeyError::ParseError);
    }
    if (decoded->size() != SIZE) {
        return std::unexpected(KeyError::InvalidKeyLength);
    }

    std::array<uint8_t, SIZE> data;
    std::copy(decoded->begin(), decoded->end(), data.begin());
    return NodeId(data);
}

std::expected<NodeId, KeyError> NodeId::from_base64(const std::string& b64) {
    auto decoded = tor::crypto::from_base64(b64);
    if (!decoded) {
        return std::unexpected(KeyError::ParseError);
    }
    if (decoded->size() != SIZE) {
        return std::unexpected(KeyError::InvalidKeyLength);
    }

    std::array<uint8_t, SIZE> data;
    std::copy(decoded->begin(), decoded->end(), data.begin());
    return NodeId(data);
}

// Utility
std::string key_error_message(KeyError err) {
    switch (err) {
        case KeyError::GenerationFailed: return "Key generation failed";
        case KeyError::InvalidKeyLength: return "Invalid key length";
        case KeyError::InvalidKey: return "Invalid key";
        case KeyError::SigningFailed: return "Signing failed";
        case KeyError::VerificationFailed: return "Verification failed";
        case KeyError::DerivationFailed: return "Key derivation failed";
        case KeyError::ParseError: return "Parse error";
        case KeyError::OpenSSLError: return "OpenSSL error";
        default: return "Unknown key error";
    }
}

}  // namespace tor::crypto
