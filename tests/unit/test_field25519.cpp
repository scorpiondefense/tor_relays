#include <catch2/catch_test_macros.hpp>
#include "tor/crypto/field25519.hpp"
#include <array>
#include <cstring>

using namespace tor::crypto;

TEST_CASE("FieldElement zero and one", "[unit][crypto][field25519]") {
    auto zero = FieldElement::zero();
    auto one = FieldElement::one();

    REQUIRE(zero.is_zero());
    REQUIRE_FALSE(one.is_zero());
    REQUIRE(zero != one);
}

TEST_CASE("FieldElement from_bytes/to_bytes round-trip", "[unit][crypto][field25519]") {
    // Test round-trip with a known value
    std::array<uint8_t, 32> input{};
    input[0] = 42;
    input[31] = 0x7f;  // Top bit clear (valid field element)

    auto fe = FieldElement::from_bytes(input);
    auto output = fe.to_bytes();

    REQUIRE(std::memcmp(input.data(), output.data(), 32) == 0);
}

TEST_CASE("FieldElement from_bytes/to_bytes zero", "[unit][crypto][field25519]") {
    std::array<uint8_t, 32> zero_bytes{};
    auto fe = FieldElement::from_bytes(zero_bytes);
    REQUIRE(fe.is_zero());
    auto output = fe.to_bytes();
    REQUIRE(std::memcmp(zero_bytes.data(), output.data(), 32) == 0);
}

TEST_CASE("FieldElement from_bytes/to_bytes one", "[unit][crypto][field25519]") {
    std::array<uint8_t, 32> one_bytes{};
    one_bytes[0] = 1;
    auto fe = FieldElement::from_bytes(one_bytes);
    REQUIRE(fe == FieldElement::one());
    auto output = fe.to_bytes();
    REQUIRE(std::memcmp(one_bytes.data(), output.data(), 32) == 0);
}

TEST_CASE("FieldElement addition", "[unit][crypto][field25519]") {
    auto one = FieldElement::one();
    auto two = one + one;
    auto three = two + one;

    std::array<uint8_t, 32> bytes{};
    bytes[0] = 3;
    auto three_expected = FieldElement::from_bytes(bytes);

    REQUIRE(three == three_expected);
}

TEST_CASE("FieldElement subtraction", "[unit][crypto][field25519]") {
    auto one = FieldElement::one();
    auto two = one + one;
    auto result = two - one;

    REQUIRE(result == one);
}

TEST_CASE("FieldElement subtraction to zero", "[unit][crypto][field25519]") {
    auto a = FieldElement::A();  // 486662
    auto result = a - a;
    REQUIRE(result.is_zero());
}

TEST_CASE("FieldElement multiplication", "[unit][crypto][field25519]") {
    auto two = FieldElement::one() + FieldElement::one();
    auto three = two + FieldElement::one();
    auto six = two * three;

    std::array<uint8_t, 32> bytes{};
    bytes[0] = 6;
    auto six_expected = FieldElement::from_bytes(bytes);

    REQUIRE(six == six_expected);
}

TEST_CASE("FieldElement squaring equals self-multiply", "[unit][crypto][field25519]") {
    auto a = FieldElement::A();  // 486662
    auto sq = a.square();
    auto mul = a * a;

    REQUIRE(sq == mul);
}

TEST_CASE("FieldElement inversion", "[unit][crypto][field25519]") {
    auto a = FieldElement::A();  // 486662
    auto inv = a.invert();
    auto product = a * inv;

    REQUIRE(product == FieldElement::one());
}

TEST_CASE("FieldElement inversion of one", "[unit][crypto][field25519]") {
    auto one = FieldElement::one();
    auto inv = one.invert();

    REQUIRE(inv == one);
}

TEST_CASE("FieldElement sqrt(-1) squared equals -1", "[unit][crypto][field25519]") {
    auto sqrtm1 = FieldElement::sqrt_m1();
    auto sq = sqrtm1.square();
    auto neg_one = -FieldElement::one();

    REQUIRE(sq == neg_one);
}

TEST_CASE("FieldElement sqrt of perfect square", "[unit][crypto][field25519]") {
    auto three = FieldElement::one() + FieldElement::one() + FieldElement::one();
    auto nine = three.square();
    auto [root, exists] = nine.sqrt();

    REQUIRE(exists);
    REQUIRE(root.square() == nine);
}

TEST_CASE("FieldElement is_negative", "[unit][crypto][field25519]") {
    auto one = FieldElement::one();
    auto neg_one = -one;

    // One of them should be negative, the other not
    REQUIRE(one.is_negative() != neg_one.is_negative());
}

TEST_CASE("FieldElement conditional_negate", "[unit][crypto][field25519]") {
    auto a = FieldElement::A();
    auto same = a.conditional_negate(false);
    auto negated = a.conditional_negate(true);

    REQUIRE(same == a);
    REQUIRE(negated == -a);
}

TEST_CASE("FieldElement conditional_select", "[unit][crypto][field25519]") {
    auto a = FieldElement::one();
    auto b = FieldElement::A();

    REQUIRE(FieldElement::conditional_select(a, b, false) == a);
    REQUIRE(FieldElement::conditional_select(a, b, true) == b);
}

TEST_CASE("FieldElement conditional_swap", "[unit][crypto][field25519]") {
    auto a = FieldElement::one();
    auto b = FieldElement::A();
    auto orig_a = a;
    auto orig_b = b;

    FieldElement::conditional_swap(a, b, false);
    REQUIRE(a == orig_a);
    REQUIRE(b == orig_b);

    FieldElement::conditional_swap(a, b, true);
    REQUIRE(a == orig_b);
    REQUIRE(b == orig_a);
}

TEST_CASE("FieldElement A constant", "[unit][crypto][field25519]") {
    auto a_const = FieldElement::A();
    std::array<uint8_t, 32> bytes{};
    // 486662 = 0x76D06 in little-endian
    bytes[0] = 0x06;
    bytes[1] = 0x6D;
    bytes[2] = 0x07;
    auto expected = FieldElement::from_bytes(bytes);

    REQUIRE(a_const == expected);
}

TEST_CASE("FieldElement large random-ish round-trip", "[unit][crypto][field25519]") {
    // Test with a value close to p
    std::array<uint8_t, 32> bytes{};
    for (int i = 0; i < 32; ++i)
        bytes[i] = 0xff;
    bytes[31] = 0x7f;  // Clear top bit -> this is >= p, so reduction should happen

    auto fe = FieldElement::from_bytes(bytes);
    auto out = fe.to_bytes();
    auto fe2 = FieldElement::from_bytes(out);

    REQUIRE(fe == fe2);
}
