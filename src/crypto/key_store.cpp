#include "tor/crypto/key_store.hpp"
#include <openssl/sha.h>
#include <fstream>

namespace tor::crypto {

static constexpr const char* ED25519_KEY_FILE = "ed25519_identity_secret_key";
static constexpr const char* CURVE25519_KEY_FILE = "curve25519_onion_secret_key";
static constexpr const char* RSA1024_KEY_FILE = "rsa1024_identity_secret_key";
static constexpr const char* FINGERPRINT_FILE = "fingerprint";

KeyStore::KeyStore(std::filesystem::path data_dir)
    : data_dir_(std::move(data_dir))
    , keys_dir_(data_dir_ / "keys") {}

bool KeyStore::keys_exist() const {
    return std::filesystem::exists(keys_dir_ / ED25519_KEY_FILE) &&
           std::filesystem::exists(keys_dir_ / CURVE25519_KEY_FILE);
}

std::expected<RelayKeyPair, KeyStoreError> KeyStore::load_or_generate() {
    if (keys_exist()) {
        auto keys = load_keys();
        if (!keys) return keys;

        // Migration: generate RSA key if it doesn't exist yet
        if (!keys->rsa_identity.is_valid()) {
            auto rsa = Rsa1024Identity::generate();
            if (!rsa) {
                return std::unexpected(KeyStoreError::KeyGenerationFailed);
            }
            keys->rsa_identity = std::move(*rsa);

            // Save the new RSA key
            auto rsa_path = keys_dir_ / RSA1024_KEY_FILE;
            auto der = keys->rsa_identity.private_key_der();
            std::ofstream rsa_file(rsa_path, std::ios::binary | std::ios::trunc);
            if (!rsa_file) {
                return std::unexpected(KeyStoreError::IoError);
            }
            rsa_file.write(reinterpret_cast<const char*>(der.data()),
                           static_cast<std::streamsize>(der.size()));
            if (!rsa_file) {
                return std::unexpected(KeyStoreError::IoError);
            }
            rsa_file.close();

            std::error_code ec;
            std::filesystem::permissions(rsa_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, ec);
        }

        return std::move(*keys);
    }

    // Generate new keys
    auto keys = RelayKeyPair::generate();
    if (!keys) {
        return std::unexpected(KeyStoreError::KeyGenerationFailed);
    }

    auto save_result = save_keys(*keys);
    if (!save_result) {
        return std::unexpected(save_result.error());
    }

    return std::move(*keys);
}

std::expected<RelayKeyPair, KeyStoreError> KeyStore::load_keys() {
    // Read Ed25519 seed
    auto ed_path = keys_dir_ / ED25519_KEY_FILE;
    std::ifstream ed_file(ed_path, std::ios::binary);
    if (!ed_file) {
        return std::unexpected(KeyStoreError::IoError);
    }

    std::array<uint8_t, Ed25519SecretKey::SEED_SIZE> ed_seed;
    ed_file.read(reinterpret_cast<char*>(ed_seed.data()), ed_seed.size());
    if (!ed_file || ed_file.gcount() != static_cast<std::streamsize>(ed_seed.size())) {
        return std::unexpected(KeyStoreError::InvalidKeyData);
    }

    auto identity = Ed25519SecretKey::from_seed(ed_seed);
    if (!identity) {
        return std::unexpected(KeyStoreError::InvalidKeyData);
    }

    // Read Curve25519 private key
    auto curve_path = keys_dir_ / CURVE25519_KEY_FILE;
    std::ifstream curve_file(curve_path, std::ios::binary);
    if (!curve_file) {
        return std::unexpected(KeyStoreError::IoError);
    }

    std::array<uint8_t, Curve25519SecretKey::SIZE> curve_bytes;
    curve_file.read(reinterpret_cast<char*>(curve_bytes.data()), curve_bytes.size());
    if (!curve_file || curve_file.gcount() != static_cast<std::streamsize>(curve_bytes.size())) {
        return std::unexpected(KeyStoreError::InvalidKeyData);
    }

    auto onion = Curve25519SecretKey::from_bytes(curve_bytes);
    if (!onion) {
        return std::unexpected(KeyStoreError::InvalidKeyData);
    }

    // Securely zero the stack buffers
    secure_zero(ed_seed.data(), ed_seed.size());
    secure_zero(curve_bytes.data(), curve_bytes.size());

    // Try to read RSA 1024-bit identity key (may not exist yet - migration case)
    Rsa1024Identity rsa;
    auto rsa_path = keys_dir_ / RSA1024_KEY_FILE;
    if (std::filesystem::exists(rsa_path)) {
        std::ifstream rsa_file(rsa_path, std::ios::binary | std::ios::ate);
        if (rsa_file) {
            auto size = rsa_file.tellg();
            rsa_file.seekg(0);
            std::vector<uint8_t> rsa_der(static_cast<size_t>(size));
            rsa_file.read(reinterpret_cast<char*>(rsa_der.data()),
                          static_cast<std::streamsize>(size));
            if (rsa_file) {
                auto rsa_result = Rsa1024Identity::from_der_private(rsa_der);
                if (rsa_result) {
                    rsa = std::move(*rsa_result);
                }
                secure_zero(rsa_der.data(), rsa_der.size());
            }
        }
    }

    // Generate linked Ed25519/Curve25519 onion key pair for crosscerts.
    // The loaded Curve25519 key is overridden because we need the Ed25519
    // counterpart for ntor-onion-key-crosscert signing.
    auto onion_ed = Ed25519SecretKey::generate();
    if (!onion_ed) {
        return std::unexpected(KeyStoreError::KeyGenerationFailed);
    }
    auto ed_seed2 = onion_ed->seed();
    uint8_t hash2[64];
    SHA512(ed_seed2.data(), ed_seed2.size(), hash2);
    hash2[0] &= 248;
    hash2[31] &= 127;
    hash2[31] |= 64;
    auto onion_linked = Curve25519SecretKey::from_bytes(
        std::span<const uint8_t>(hash2, 32));
    if (!onion_linked) {
        return std::unexpected(KeyStoreError::InvalidKeyData);
    }
    auto ed_pub2 = onion_ed->public_key().as_span();
    uint8_t sign_bit2 = ed_pub2[31] >> 7;

    RelayKeyPair kp;
    kp.identity_key = std::move(*identity);
    kp.onion_key = std::move(*onion_linked);
    kp.rsa_identity = std::move(rsa);
    kp.onion_ed_key = std::move(*onion_ed);
    kp.onion_ed_sign_bit = sign_bit2;
    return kp;
}

std::expected<void, KeyStoreError> KeyStore::save_keys(const RelayKeyPair& keys) {
    // Create directories
    std::error_code ec;
    std::filesystem::create_directories(keys_dir_, ec);
    if (ec) {
        return std::unexpected(KeyStoreError::IoError);
    }

    // Write Ed25519 seed
    auto ed_path = keys_dir_ / ED25519_KEY_FILE;
    {
        std::ofstream ed_file(ed_path, std::ios::binary | std::ios::trunc);
        if (!ed_file) {
            return std::unexpected(KeyStoreError::IoError);
        }

        auto seed = keys.identity_key.seed();
        ed_file.write(reinterpret_cast<const char*>(seed.data()), seed.size());
        if (!ed_file) {
            return std::unexpected(KeyStoreError::IoError);
        }
    }

    // Set 0600 permissions on secret key file
    std::filesystem::permissions(ed_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    if (ec) {
        return std::unexpected(KeyStoreError::PermissionError);
    }

    // Write Curve25519 private key
    auto curve_path = keys_dir_ / CURVE25519_KEY_FILE;
    {
        std::ofstream curve_file(curve_path, std::ios::binary | std::ios::trunc);
        if (!curve_file) {
            return std::unexpected(KeyStoreError::IoError);
        }

        auto bytes = keys.onion_key.as_bytes();
        curve_file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!curve_file) {
            return std::unexpected(KeyStoreError::IoError);
        }
    }

    // Set 0600 permissions
    std::filesystem::permissions(curve_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    if (ec) {
        return std::unexpected(KeyStoreError::PermissionError);
    }

    // Write RSA 1024-bit identity private key (DER)
    if (keys.rsa_identity.is_valid()) {
        auto rsa_path = keys_dir_ / RSA1024_KEY_FILE;
        {
            auto der = keys.rsa_identity.private_key_der();
            std::ofstream rsa_file(rsa_path, std::ios::binary | std::ios::trunc);
            if (!rsa_file) {
                return std::unexpected(KeyStoreError::IoError);
            }

            rsa_file.write(reinterpret_cast<const char*>(der.data()),
                           static_cast<std::streamsize>(der.size()));
            if (!rsa_file) {
                return std::unexpected(KeyStoreError::IoError);
            }
        }

        std::filesystem::permissions(rsa_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, ec);
        if (ec) {
            return std::unexpected(KeyStoreError::PermissionError);
        }
    }

    return {};
}

std::expected<void, KeyStoreError>
KeyStore::write_fingerprint(const std::string& nickname, const NodeId& node_id) {
    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);
    if (ec) {
        return std::unexpected(KeyStoreError::IoError);
    }

    auto fp_path = data_dir_ / FINGERPRINT_FILE;
    std::ofstream fp_file(fp_path, std::ios::trunc);
    if (!fp_file) {
        return std::unexpected(KeyStoreError::IoError);
    }

    fp_file << nickname << " " << node_id.to_hex() << "\n";
    if (!fp_file) {
        return std::unexpected(KeyStoreError::IoError);
    }

    return {};
}

std::string key_store_error_message(KeyStoreError err) {
    switch (err) {
        case KeyStoreError::IoError:              return "I/O error";
        case KeyStoreError::InvalidKeyData:       return "Invalid key data";
        case KeyStoreError::PermissionError:      return "Permission error";
        case KeyStoreError::KeyGenerationFailed:  return "Key generation failed";
        default:                                  return "Unknown key store error";
    }
}

}  // namespace tor::crypto
