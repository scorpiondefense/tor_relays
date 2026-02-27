#pragma once

#include "tor/crypto/field25519.hpp"
#include "tor/crypto/keys.hpp"
#include <array>
#include <cstdint>
#include <expected>
#include <optional>

namespace tor::crypto {

// Error types for Elligator2 operations
enum class ElligatorError {
    NotRepresentable,    // Point has no Elligator2 representative (~50% of points)
    InvalidRepresentative,
    GenerationFailed,
};

// Representable keypair: a Curve25519 keypair whose public key has an
// Elligator2 representative (indistinguishable from random bytes)
struct RepresentableKeypair {
    std::array<uint8_t, 32> secret;        // Curve25519 secret key
    std::array<uint8_t, 32> public_key;    // Curve25519 public key
    std::array<uint8_t, 32> representative; // Elligator2 representative
};

// Elligator2 mapping for Curve25519
// Maps between Curve25519 public keys and uniform random 32-byte representatives.
// This is essential for obfs4: the client's initial handshake bytes must be
// indistinguishable from random to defeat DPI censorship.
class Elligator2 {
public:
    // Map a 32-byte representative to a Curve25519 public key.
    // This always succeeds - every 32-byte string maps to a valid point.
    static Curve25519PublicKey representative_to_point(
        std::span<const uint8_t, 32> representative);

    // Map a Curve25519 public key to a 32-byte representative.
    // Only succeeds ~50% of the time (when the point is in the image of the map).
    // tweak: the high bit of the representative (0 or 1), providing one bit
    // of randomness in the representative.
    static std::expected<std::array<uint8_t, 32>, ElligatorError>
    point_to_representative(const Curve25519PublicKey& pubkey, uint8_t tweak);

    // Generate a Curve25519 keypair that has an Elligator2 representative.
    // Retries key generation until a representable key is found (~2 attempts avg).
    static std::expected<RepresentableKeypair, ElligatorError>
    generate_representable_keypair();

    // Check if a Curve25519 public key is representable
    // (i.e., point_to_representative would succeed)
    static bool is_representable(const Curve25519PublicKey& pubkey);

private:
    // Internal: compute the Montgomery u-coordinate from a representative
    // using the Elligator2 map: r -> u
    static FieldElement map_to_u(const FieldElement& r);

    // Internal: compute the representative from a Montgomery u-coordinate
    // Returns nullopt if not in the image of the map
    static std::optional<FieldElement> u_to_representative(const FieldElement& u);

    // Internal: clamp a Curve25519 secret key (set/clear required bits)
    static void clamp_secret(std::array<uint8_t, 32>& key);

    // Internal: compute X25519 public key from secret key using field arithmetic
    // (bypassing OpenSSL to get the raw u-coordinate)
    static FieldElement scalar_base_mult(std::span<const uint8_t, 32> scalar);
};

[[nodiscard]] std::string elligator_error_message(ElligatorError err);

}  // namespace tor::crypto
