#include <catch2/catch_test_macros.hpp>
#include "tor/crypto/secretbox.hpp"
#include <array>
#include <cstring>

using namespace tor::crypto;

TEST_CASE("Secretbox seal/open round-trip", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 0x42;
    key[15] = 0x13;

    std::array<uint8_t, 24> nonce{};
    nonce[0] = 0x01;
    nonce[23] = 0xff;

    std::vector<uint8_t> plaintext = {
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'
    };

    auto sealed = Secretbox::seal(key, nonce, plaintext);
    REQUIRE(sealed.size() == plaintext.size() + Secretbox::OVERHEAD);

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE(opened.has_value());
    REQUIRE(*opened == plaintext);
}

TEST_CASE("Secretbox open detects tampered ciphertext", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 0x42;

    std::array<uint8_t, 24> nonce{};
    nonce[0] = 0x01;

    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};

    auto sealed = Secretbox::seal(key, nonce, plaintext);

    // Tamper with ciphertext
    sealed[Secretbox::TAG_LEN + 1] ^= 0x01;

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE_FALSE(opened.has_value());
    REQUIRE(opened.error() == SecretboxError::DecryptionFailed);
}

TEST_CASE("Secretbox open detects tampered tag", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 0x42;

    std::array<uint8_t, 24> nonce{};
    nonce[0] = 0x01;

    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};

    auto sealed = Secretbox::seal(key, nonce, plaintext);

    // Tamper with tag
    sealed[0] ^= 0x01;

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE_FALSE(opened.has_value());
}

TEST_CASE("Secretbox open rejects too-short input", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> nonce{};
    std::vector<uint8_t> short_ct(10);  // Less than TAG_LEN

    auto opened = Secretbox::open(key, nonce, short_ct);
    REQUIRE_FALSE(opened.has_value());
    REQUIRE(opened.error() == SecretboxError::MessageTooShort);
}

TEST_CASE("Secretbox wrong key fails decryption", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key1{};
    key1[0] = 1;
    std::array<uint8_t, 32> key2{};
    key2[0] = 2;

    std::array<uint8_t, 24> nonce{};

    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};
    auto sealed = Secretbox::seal(key1, nonce, plaintext);

    auto opened = Secretbox::open(key2, nonce, sealed);
    REQUIRE_FALSE(opened.has_value());
}

TEST_CASE("Secretbox wrong nonce fails decryption", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 1;

    std::array<uint8_t, 24> nonce1{};
    nonce1[0] = 1;
    std::array<uint8_t, 24> nonce2{};
    nonce2[0] = 2;

    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};
    auto sealed = Secretbox::seal(key, nonce1, plaintext);

    auto opened = Secretbox::open(key, nonce2, sealed);
    REQUIRE_FALSE(opened.has_value());
}

TEST_CASE("Secretbox empty plaintext", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 0x42;

    std::array<uint8_t, 24> nonce{};
    nonce[0] = 0x01;

    std::vector<uint8_t> plaintext{};

    auto sealed = Secretbox::seal(key, nonce, plaintext);
    REQUIRE(sealed.size() == Secretbox::OVERHEAD);

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE(opened.has_value());
    REQUIRE(opened->empty());
}

TEST_CASE("Secretbox large message", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);

    std::array<uint8_t, 24> nonce{};
    for (int i = 0; i < 24; ++i)
        nonce[i] = static_cast<uint8_t>(i + 32);

    // 4096 byte message
    std::vector<uint8_t> plaintext(4096);
    for (size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<uint8_t>(i & 0xff);

    auto sealed = Secretbox::seal(key, nonce, plaintext);
    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE(opened.has_value());
    REQUIRE(*opened == plaintext);
}

// --- HSalsa20 test vector from NaCl/TweetNaCl ---

TEST_CASE("HSalsa20 test vector", "[unit][crypto][secretbox]") {
    // From the NaCl documentation / TweetNaCl test vectors
    // Key: first key from DJB's test
    std::array<uint8_t, 32> key = {
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
    };
    std::array<uint8_t, 16> nonce = {
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6
    };
    // Expected output from HSalsa20(key, nonce)
    std::array<uint8_t, 32> expected = {
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
    };

    std::array<uint8_t, 32> output;
    hsalsa20(output, key, nonce);

    REQUIRE(std::memcmp(output.data(), expected.data(), 32) == 0);
}

TEST_CASE("Poly1305 basic test", "[unit][crypto][secretbox]") {
    // Test that poly1305 produces a 16-byte tag
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};

    std::array<uint8_t, 16> tag;
    poly1305(tag, message, key);

    // Verify it's not all zeros
    bool all_zero = true;
    for (auto b : tag)
        if (b != 0) { all_zero = false; break; }
    REQUIRE_FALSE(all_zero);

    // Verify tag
    REQUIRE(poly1305_verify(tag, message, key));
}

TEST_CASE("Poly1305 different messages produce different tags", "[unit][crypto][secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 1;

    std::vector<uint8_t> msg1 = {'a'};
    std::vector<uint8_t> msg2 = {'b'};

    std::array<uint8_t, 16> tag1, tag2;
    poly1305(tag1, msg1, key);
    poly1305(tag2, msg2, key);

    REQUIRE(std::memcmp(tag1.data(), tag2.data(), 16) != 0);
}
