#pragma once

#include "tor/crypto/keys.hpp"
#include <expected>
#include <filesystem>
#include <string>

namespace tor::crypto {

// Error types for key store operations
enum class KeyStoreError {
    IoError,
    InvalidKeyData,
    PermissionError,
    KeyGenerationFailed,
};

[[nodiscard]] std::string key_store_error_message(KeyStoreError err);

// Persistent key storage for relay identity and onion keys
class KeyStore {
public:
    explicit KeyStore(std::filesystem::path data_dir);

    // Load existing keys or generate and save new ones
    [[nodiscard]] std::expected<RelayKeyPair, KeyStoreError> load_or_generate();

    // Write fingerprint file: "{data_dir}/fingerprint" with "nickname HEX"
    [[nodiscard]] std::expected<void, KeyStoreError>
    write_fingerprint(const std::string& nickname, const NodeId& node_id);

private:
    std::filesystem::path data_dir_;
    std::filesystem::path keys_dir_;

    [[nodiscard]] std::expected<RelayKeyPair, KeyStoreError> load_keys();
    [[nodiscard]] std::expected<void, KeyStoreError> save_keys(const RelayKeyPair& keys);

    [[nodiscard]] bool keys_exist() const;
};

}  // namespace tor::crypto
