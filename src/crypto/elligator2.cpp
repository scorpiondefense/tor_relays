#include "tor/crypto/elligator2.hpp"
#include <cstring>

namespace tor::crypto {

// Non-square constant for Elligator2: u = 2
// (2 is a non-square in GF(p) for p = 5 mod 8)
static const FieldElement ELLIGATOR_U = FieldElement(2, 0, 0, 0, 0);

// --- Forward map: representative -> point ---

FieldElement Elligator2::map_to_u(const FieldElement& r) {
    // Elligator2 map for Montgomery curve y^2 = x^3 + A*x^2 + x
    // where A = 486662
    //
    // Given r (representative as field element):
    // 1. v = -A / (1 + u * r^2)  [where u = 2 is non-square]
    // 2. e = legendre(v^3 + A*v^2 + v)
    // 3. x = e*v - (1-e)*A/2
    // i.e., if e=1: x = v, else x = -v - A

    auto A = FieldElement::A();
    auto one = FieldElement::one();

    auto r2 = r.square();
    auto ur2 = ELLIGATOR_U * r2;           // u * r^2
    auto denom = one + ur2;                 // 1 + u*r^2

    // If denom == 0, use denom = 1 (constant-time)
    bool denom_is_zero = denom.is_zero();
    denom = FieldElement::conditional_select(denom, one, denom_is_zero);

    auto denom_inv = denom.invert();
    auto v = -(A * denom_inv);              // v = -A / (1 + u*r^2)

    // Compute v^3 + A*v^2 + v (the curve equation RHS)
    auto v2 = v.square();
    auto v3 = v2 * v;
    auto rhs = v3 + A * v2 + v;            // v^3 + A*v^2 + v

    // Check if rhs is a square (Euler criterion)
    auto [_, is_square] = rhs.sqrt();

    // If is_square: x = v
    // Else: x = -v - A
    auto x_if_square = v;
    auto x_if_not = -v - A;
    auto x = FieldElement::conditional_select(x_if_not, x_if_square, is_square);

    return x;
}

Curve25519PublicKey Elligator2::representative_to_point(
    std::span<const uint8_t, 32> representative) {

    // Clear high bit of representative (field element is mod 2^255-19)
    std::array<uint8_t, 32> clamped;
    std::memcpy(clamped.data(), representative.data(), 32);
    clamped[31] &= 0x7f;

    auto r = FieldElement::from_bytes(clamped);
    auto u = map_to_u(r);
    auto bytes = u.to_bytes();

    Curve25519PublicKey pk(bytes);
    return pk;
}

// --- Inverse map: point -> representative ---

std::optional<FieldElement> Elligator2::u_to_representative(const FieldElement& u_coord) {
    // Inverse Elligator2: given x on the curve, find r such that map(r) = x
    //
    // From x = -A / (1 + u*r^2):
    //   1 + u*r^2 = -A/x
    //   u*r^2 = -A/x - 1 = -(A + x)/x
    //   r^2 = -(A + x) / (u * x)
    //
    // This has a solution iff -(A + x) / (u * x) is a square.
    // Additionally, x must not be 0 and x must be on the curve (first branch).

    auto A = FieldElement::A();

    // x must not be zero
    if (u_coord.is_zero()) {
        return std::nullopt;
    }

    // Check that x is on the "first branch": the curve point at x must have
    // a square y-coordinate. Compute x^3 + A*x^2 + x
    auto x2 = u_coord.square();
    auto x3 = x2 * u_coord;
    auto rhs = x3 + A * x2 + u_coord;

    // rhs must be a square for x to be on the curve's first branch
    auto [_, rhs_is_square] = rhs.sqrt();
    if (!rhs_is_square) {
        return std::nullopt;
    }

    // Compute r^2 = -(A + x) / (u * x)
    auto numerator = -(A + u_coord);
    auto denominator = ELLIGATOR_U * u_coord;
    auto r_squared = numerator * denominator.invert();

    // r_squared must be a square
    auto [r, r_sq_is_square] = r_squared.sqrt();
    if (!r_sq_is_square) {
        return std::nullopt;
    }

    return r;
}

std::expected<std::array<uint8_t, 32>, ElligatorError>
Elligator2::point_to_representative(const Curve25519PublicKey& pubkey, uint8_t tweak) {
    auto u_coord = FieldElement::from_bytes(
        std::span<const uint8_t, 32>(pubkey.data().data(), 32));

    auto r_opt = u_to_representative(u_coord);
    if (!r_opt) {
        return std::unexpected(ElligatorError::NotRepresentable);
    }

    auto r = *r_opt;

    // Apply tweak: negate r if tweak bit is set and r is negative
    // This provides one bit of randomness in the representative
    bool negate = (tweak & 1) != 0;
    r = r.conditional_negate(negate != r.is_negative());

    auto bytes = r.to_bytes();

    // Set the high bit randomly from tweak for additional randomness
    bytes[31] |= static_cast<uint8_t>((tweak & 2) << 6);

    return bytes;
}

bool Elligator2::is_representable(const Curve25519PublicKey& pubkey) {
    auto u_coord = FieldElement::from_bytes(
        std::span<const uint8_t, 32>(pubkey.data().data(), 32));
    return u_to_representative(u_coord).has_value();
}

// --- Keypair generation ---

void Elligator2::clamp_secret(std::array<uint8_t, 32>& key) {
    key[0] &= 248;   // Clear low 3 bits
    key[31] &= 127;  // Clear high bit
    key[31] |= 64;   // Set second-highest bit
}

FieldElement Elligator2::scalar_base_mult(std::span<const uint8_t, 32> scalar) {
    // Montgomery ladder scalar multiplication on Curve25519
    // Basepoint u = 9
    auto u = FieldElement(9, 0, 0, 0, 0);

    // Montgomery ladder
    auto x_0 = FieldElement::one();  // u-coordinate of 0*G = point at infinity
    auto x_1 = u;         // u-coordinate of 1*G = basepoint
    auto z_0 = FieldElement::zero();
    auto z_1 = FieldElement::one();

    // Process bits from high to low
    for (int i = 254; i >= 0; --i) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        bool bit = (scalar[byte_idx] >> bit_idx) & 1;

        FieldElement::conditional_swap(x_0, x_1, bit);
        FieldElement::conditional_swap(z_0, z_1, bit);

        // Differential addition
        auto a = x_0 + z_0;
        auto aa = a.square();
        auto b = x_0 - z_0;
        auto bb = b.square();
        auto e = aa - bb;
        auto c = x_1 + z_1;
        auto d = x_1 - z_1;
        auto da = d * a;
        auto cb = c * b;
        x_1 = (da + cb).square();
        z_1 = u * (da - cb).square();
        x_0 = aa * bb;
        // (A + 2) / 4 = 121666
        auto a24 = FieldElement(121666, 0, 0, 0, 0);
        z_0 = e * (aa + a24 * e);

        FieldElement::conditional_swap(x_0, x_1, bit);
        FieldElement::conditional_swap(z_0, z_1, bit);
    }

    // Result: x_0 / z_0
    return x_0 * z_0.invert();
}

std::expected<RepresentableKeypair, ElligatorError>
Elligator2::generate_representable_keypair() {
    // Retry loop: ~50% of keys are representable, so ~2 attempts on average
    for (int attempt = 0; attempt < 256; ++attempt) {
        auto secret_bytes = random_bytes(32);
        std::array<uint8_t, 32> secret;
        std::memcpy(secret.data(), secret_bytes.data(), 32);
        clamp_secret(secret);

        // Compute public key via Montgomery ladder
        auto u_coord = scalar_base_mult(secret);
        auto pub_bytes = u_coord.to_bytes();

        // Check if representable
        auto r_opt = u_to_representative(u_coord);
        if (!r_opt) {
            continue;  // Not representable, try again
        }

        auto r = *r_opt;

        // Canonicalize representative: make it non-negative
        r = r.conditional_negate(r.is_negative());
        auto repr = r.to_bytes();

        // Randomize the high bit
        auto extra_random = random_bytes(1);
        repr[31] |= static_cast<uint8_t>(extra_random[0] & 0x80);

        RepresentableKeypair kp;
        kp.secret = secret;
        kp.public_key = pub_bytes;
        kp.representative = repr;

        return kp;
    }

    return std::unexpected(ElligatorError::GenerationFailed);
}

std::string elligator_error_message(ElligatorError err) {
    switch (err) {
        case ElligatorError::NotRepresentable:
            return "Point is not Elligator2-representable";
        case ElligatorError::InvalidRepresentative:
            return "Invalid Elligator2 representative";
        case ElligatorError::GenerationFailed:
            return "Failed to generate representable keypair";
        default:
            return "Unknown Elligator2 error";
    }
}

}  // namespace tor::crypto
