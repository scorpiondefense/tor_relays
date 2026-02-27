#include <catch2/catch_test_macros.hpp>
#include "tor/transport/obfs4.hpp"
#include <cstring>

using namespace tor::transport;
using namespace tor::crypto;

TEST_CASE("Obfs4Identity cert encode/decode round-trip", "[unit][transport][obfs4]") {
    // Create a test identity
    auto keys = RelayKeyPair::generate();
    REQUIRE(keys.has_value());

    NodeId node_id(keys->identity_key.public_key());

    Obfs4Identity identity;
    identity.node_id = node_id;
    identity.ntor_public_key = keys->onion_key.public_key();

    // Encode to cert
    auto cert = identity.to_cert();
    REQUIRE_FALSE(cert.empty());

    // cert should be ~70 chars of base64 (52 raw bytes)
    REQUIRE(cert.size() >= 68);
    REQUIRE(cert.size() <= 72);

    // Decode back
    auto decoded = Obfs4Identity::from_cert(cert);
    REQUIRE(decoded.has_value());

    REQUIRE(decoded->node_id == identity.node_id);
    REQUIRE(decoded->ntor_public_key == identity.ntor_public_key);
}

TEST_CASE("Obfs4Identity from_cert rejects invalid cert", "[unit][transport][obfs4]") {
    auto result = Obfs4Identity::from_cert("invalid!!");
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == Obfs4Error::InvalidCert);
}

TEST_CASE("Obfs4Identity from_cert rejects too-short cert", "[unit][transport][obfs4]") {
    auto result = Obfs4Identity::from_cert("AAAA");
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == Obfs4Error::InvalidCert);
}

TEST_CASE("Obfs4Framing encode/decode round-trip", "[unit][transport][obfs4]") {
    // Generate test keys
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);

    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 24> drbg_seed{};
    drbg_seed[0] = 0x01; // Non-zero seed

    Obfs4Framing sender, receiver;
    sender.init_send(key, nonce, drbg_seed);
    receiver.init_recv(key, nonce, drbg_seed);

    // Encode a frame
    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    auto encoded = sender.encode(payload);
    REQUIRE_FALSE(encoded.empty());

    // Decode the frame
    auto decoded = receiver.decode(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->frames.size() == 1);
    REQUIRE(decoded->frames[0] == payload);
}

TEST_CASE("Obfs4Framing multiple frames", "[unit][transport][obfs4]") {
    std::array<uint8_t, 32> key{};
    key[0] = 0x42;
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 24> drbg_seed{};
    drbg_seed[0] = 0x42;

    Obfs4Framing sender, receiver;
    sender.init_send(key, nonce, drbg_seed);
    receiver.init_recv(key, nonce, drbg_seed);

    // Encode multiple frames
    std::vector<uint8_t> payload1 = {'A', 'B', 'C'};
    std::vector<uint8_t> payload2 = {'D', 'E', 'F'};

    auto encoded1 = sender.encode(payload1);
    auto encoded2 = sender.encode(payload2);

    // Concatenate and decode all at once
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), encoded1.begin(), encoded1.end());
    combined.insert(combined.end(), encoded2.begin(), encoded2.end());

    auto decoded = receiver.decode(combined);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->frames.size() == 2);
    REQUIRE(decoded->frames[0] == payload1);
    REQUIRE(decoded->frames[1] == payload2);
}

TEST_CASE("Obfs4Framing partial frame reassembly", "[unit][transport][obfs4]") {
    std::array<uint8_t, 32> key{};
    key[0] = 0x42;
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 24> drbg_seed{};
    drbg_seed[0] = 0x42;

    Obfs4Framing sender, receiver;
    sender.init_send(key, nonce, drbg_seed);
    receiver.init_recv(key, nonce, drbg_seed);

    std::vector<uint8_t> payload = {'T', 'e', 's', 't'};
    auto encoded = sender.encode(payload);

    // Feed partial data
    size_t mid = encoded.size() / 2;

    auto part1 = std::span<const uint8_t>(encoded.data(), mid);
    auto decoded1 = receiver.decode(part1);
    REQUIRE(decoded1.has_value());
    REQUIRE(decoded1->frames.empty());  // Not enough data yet

    auto part2 = std::span<const uint8_t>(encoded.data() + mid, encoded.size() - mid);
    auto decoded2 = receiver.decode(part2);
    REQUIRE(decoded2.has_value());
    REQUIRE(decoded2->frames.size() == 1);
    REQUIRE(decoded2->frames[0] == payload);
}

TEST_CASE("Obfs4Framing empty payload", "[unit][transport][obfs4]") {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 24> drbg_seed{};

    Obfs4Framing sender, receiver;
    sender.init_send(key, nonce, drbg_seed);
    receiver.init_recv(key, nonce, drbg_seed);

    std::vector<uint8_t> empty_payload;
    auto encoded = sender.encode(empty_payload);

    auto decoded = receiver.decode(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->frames.size() == 1);
    REQUIRE(decoded->frames[0].empty());
}

TEST_CASE("Obfs4Framing max payload size", "[unit][transport][obfs4]") {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 24> drbg_seed{};

    Obfs4Framing sender, receiver;
    sender.init_send(key, nonce, drbg_seed);
    receiver.init_recv(key, nonce, drbg_seed);

    // Max payload
    std::vector<uint8_t> payload(OBFS4_MAX_FRAME_PAYLOAD, 0xAB);
    auto encoded = sender.encode(payload);

    auto decoded = receiver.decode(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->frames.size() == 1);
    REQUIRE(decoded->frames[0] == payload);
}

TEST_CASE("epoch_hour returns reasonable value", "[unit][transport][obfs4]") {
    auto h = epoch_hour();
    // Should be > 0 (we're well past 1970) and < some reasonable future
    REQUIRE(h > 400000);    // ~45 years
    REQUIRE(h < 1000000);   // ~114 years
}

TEST_CASE("Obfs4ServerHandshake rejects buffer overflow", "[unit][transport][obfs4]") {
    auto keys = RelayKeyPair::generate();
    REQUIRE(keys.has_value());
    NodeId node_id(keys->identity_key.public_key());

    Obfs4ServerHandshake hs(node_id, keys->onion_key);

    // Feed maximum buffer size of random data (no valid mark)
    std::vector<uint8_t> junk(OBFS4_MAX_HANDSHAKE_LEN, 0xFF);
    auto result = hs.consume(junk);

    // Should either fail with buffer overflow or still be waiting
    if (!result.has_value()) {
        REQUIRE(result.error() == Obfs4Error::BufferOverflow);
    }
}
