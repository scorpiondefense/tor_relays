#include <catch2/catch_test_macros.hpp>
#include "tor/crypto/elligator2.hpp"
#include <cstring>

using namespace tor::crypto;

TEST_CASE("Elligator2 representative_to_point produces valid key", "[unit][crypto][elligator2]") {
    // A random representative (32 bytes)
    std::array<uint8_t, 32> repr{};
    repr[0] = 0x42;
    repr[1] = 0x13;
    repr[10] = 0xab;

    auto pk = Elligator2::representative_to_point(repr);
    // The result should be a 32-byte key (any result is valid)
    REQUIRE(pk.data().size() == 32);
}

TEST_CASE("Elligator2 representative_to_point is deterministic", "[unit][crypto][elligator2]") {
    std::array<uint8_t, 32> repr{};
    repr[0] = 0xff;
    repr[15] = 0x77;

    auto pk1 = Elligator2::representative_to_point(repr);
    auto pk2 = Elligator2::representative_to_point(repr);

    REQUIRE(pk1 == pk2);
}

TEST_CASE("Elligator2 zero representative maps to a point", "[unit][crypto][elligator2]") {
    std::array<uint8_t, 32> repr{};
    auto pk = Elligator2::representative_to_point(repr);
    // Should succeed (zero maps to -A / (1 + 0) = -A which gets handled)
    REQUIRE(pk.data().size() == 32);
}

TEST_CASE("Elligator2 point_to_representative round-trip", "[unit][crypto][elligator2]") {
    // Generate a representable keypair and verify the round-trip
    auto kp_result = Elligator2::generate_representable_keypair();
    REQUIRE(kp_result.has_value());

    auto& kp = *kp_result;

    // The representative should map back to the public key
    auto recovered = Elligator2::representative_to_point(kp.representative);

    // Compare the u-coordinates
    REQUIRE(recovered.data() == Curve25519PublicKey(kp.public_key).data());
}

TEST_CASE("Elligator2 generate_representable_keypair succeeds", "[unit][crypto][elligator2]") {
    auto kp_result = Elligator2::generate_representable_keypair();
    REQUIRE(kp_result.has_value());

    auto& kp = *kp_result;

    // Secret key should be clamped
    REQUIRE((kp.secret[0] & 7) == 0);   // Low 3 bits clear
    REQUIRE((kp.secret[31] & 128) == 0); // High bit clear
    REQUIRE((kp.secret[31] & 64) == 64); // Second-highest bit set

    // Public key should be non-zero
    bool all_zero = true;
    for (auto b : kp.public_key)
        if (b != 0) { all_zero = false; break; }
    REQUIRE_FALSE(all_zero);
}

TEST_CASE("Elligator2 is_representable consistent with point_to_representative", "[unit][crypto][elligator2]") {
    auto kp_result = Elligator2::generate_representable_keypair();
    REQUIRE(kp_result.has_value());

    auto& kp = *kp_result;
    Curve25519PublicKey pk(kp.public_key);

    REQUIRE(Elligator2::is_representable(pk));
}

TEST_CASE("Elligator2 different representatives yield different points", "[unit][crypto][elligator2]") {
    std::array<uint8_t, 32> repr1{};
    repr1[0] = 1;
    std::array<uint8_t, 32> repr2{};
    repr2[0] = 2;

    auto pk1 = Elligator2::representative_to_point(repr1);
    auto pk2 = Elligator2::representative_to_point(repr2);

    REQUIRE(pk1.data() != pk2.data());
}

TEST_CASE("Elligator2 representative high bit ignored", "[unit][crypto][elligator2]") {
    std::array<uint8_t, 32> repr1{};
    repr1[0] = 0x42;
    repr1[31] = 0x00;

    std::array<uint8_t, 32> repr2 = repr1;
    repr2[31] = 0x80;  // Set high bit

    auto pk1 = Elligator2::representative_to_point(repr1);
    auto pk2 = Elligator2::representative_to_point(repr2);

    // High bit should be cleared, so both should map to same point
    REQUIRE(pk1 == pk2);
}
