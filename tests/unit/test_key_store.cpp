#include <catch2/catch_all.hpp>
#include "tor/crypto/key_store.hpp"
#include <filesystem>
#include <fstream>

using namespace tor::crypto;
namespace fs = std::filesystem;

namespace {

// RAII helper for temporary test directories
struct TempDir {
    fs::path path;

    TempDir() {
        path = fs::temp_directory_path() / ("tor_test_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        fs::create_directories(path);
    }

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

}  // namespace

TEST_CASE("KeyStore generates keys on first run", "[crypto][keystore][unit]") {
    TempDir tmp;
    KeyStore store(tmp.path);

    auto result = store.load_or_generate();
    REQUIRE(result.has_value());

    // Key files should exist
    CHECK(fs::exists(tmp.path / "keys" / "ed25519_identity_secret_key"));
    CHECK(fs::exists(tmp.path / "keys" / "curve25519_onion_secret_key"));

    // Key files should be 32 bytes each
    CHECK(fs::file_size(tmp.path / "keys" / "ed25519_identity_secret_key") == 32);
    CHECK(fs::file_size(tmp.path / "keys" / "curve25519_onion_secret_key") == 32);
}

TEST_CASE("KeyStore loads existing keys", "[crypto][keystore][unit]") {
    TempDir tmp;

    // First run: generate
    Ed25519PublicKey first_pubkey;
    {
        KeyStore store(tmp.path);
        auto result = store.load_or_generate();
        REQUIRE(result.has_value());
        first_pubkey = result->identity_key.public_key();
    }

    // Second run: load
    {
        KeyStore store(tmp.path);
        auto result = store.load_or_generate();
        REQUIRE(result.has_value());

        // Same identity key should be loaded
        CHECK(result->identity_key.public_key().data() == first_pubkey.data());
    }
}

TEST_CASE("KeyStore writes fingerprint file", "[crypto][keystore][unit]") {
    TempDir tmp;
    KeyStore store(tmp.path);

    auto keys = store.load_or_generate();
    REQUIRE(keys.has_value());

    NodeId node_id(keys->identity_key.public_key());
    auto result = store.write_fingerprint("TestRelay", node_id);
    REQUIRE(result.has_value());

    // Read and verify fingerprint file
    auto fp_path = tmp.path / "fingerprint";
    REQUIRE(fs::exists(fp_path));

    std::ifstream fp_file(fp_path);
    std::string nickname, hex;
    fp_file >> nickname >> hex;

    CHECK(nickname == "TestRelay");
    CHECK(hex == node_id.to_hex());
}

TEST_CASE("KeyStore sets secure permissions", "[crypto][keystore][unit]") {
    TempDir tmp;
    KeyStore store(tmp.path);

    auto result = store.load_or_generate();
    REQUIRE(result.has_value());

    auto ed_perms = fs::status(tmp.path / "keys" / "ed25519_identity_secret_key").permissions();
    auto curve_perms = fs::status(tmp.path / "keys" / "curve25519_onion_secret_key").permissions();

    // Owner read+write only (0600)
    auto expected = fs::perms::owner_read | fs::perms::owner_write;
    CHECK(ed_perms == expected);
    CHECK(curve_perms == expected);
}

TEST_CASE("KeyStore handles missing directory gracefully", "[crypto][keystore][unit]") {
    TempDir tmp;
    auto nested = tmp.path / "deeply" / "nested" / "data";

    KeyStore store(nested);
    auto result = store.load_or_generate();
    REQUIRE(result.has_value());

    CHECK(fs::exists(nested / "keys" / "ed25519_identity_secret_key"));
}

TEST_CASE("KeyStore rejects corrupt key files", "[crypto][keystore][unit]") {
    TempDir tmp;

    // Create corrupt key files
    auto keys_dir = tmp.path / "keys";
    fs::create_directories(keys_dir);

    // Write truncated Ed25519 key (only 16 bytes instead of 32)
    {
        std::ofstream f(keys_dir / "ed25519_identity_secret_key", std::ios::binary);
        std::array<uint8_t, 16> bad_data{};
        f.write(reinterpret_cast<const char*>(bad_data.data()), bad_data.size());
    }

    // Write valid-length Curve25519 key
    {
        std::ofstream f(keys_dir / "curve25519_onion_secret_key", std::ios::binary);
        std::array<uint8_t, 32> data{};
        f.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    KeyStore store(tmp.path);
    auto result = store.load_or_generate();
    CHECK_FALSE(result.has_value());
    CHECK(result.error() == KeyStoreError::InvalidKeyData);
}

TEST_CASE("NodeId from fingerprint file matches generated key", "[crypto][keystore][unit]") {
    TempDir tmp;
    KeyStore store(tmp.path);

    auto keys = store.load_or_generate();
    REQUIRE(keys.has_value());

    NodeId expected_id(keys->identity_key.public_key());
    auto fp_result = store.write_fingerprint("MyRelay", expected_id);
    REQUIRE(fp_result.has_value());

    // Parse hex back from file
    std::ifstream fp_file(tmp.path / "fingerprint");
    std::string nickname, hex;
    fp_file >> nickname >> hex;

    auto parsed_id = NodeId::from_hex(hex);
    REQUIRE(parsed_id.has_value());
    CHECK(*parsed_id == expected_id);
}
