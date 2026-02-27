#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace tor::crypto {

// Error types for secretbox operations
enum class SecretboxError {
    InvalidKeyLength,
    InvalidNonceLength,
    DecryptionFailed,   // Authentication tag mismatch
    MessageTooShort,
};

// NaCl Secretbox: XSalsa20-Poly1305 authenticated encryption
// obfs4 mandates NaCl secretbox. OpenSSL has ChaCha20-Poly1305
// but NOT XSalsa20, so we implement from scratch.
class Secretbox {
public:
    static constexpr size_t KEY_LEN = 32;
    static constexpr size_t NONCE_LEN = 24;    // XSalsa20 uses 24-byte nonce
    static constexpr size_t TAG_LEN = 16;      // Poly1305 MAC
    static constexpr size_t OVERHEAD = TAG_LEN; // Ciphertext is plaintext + 16

    // Encrypt and authenticate (seal)
    // Output: tag[16] || ciphertext[plaintext.size()]
    // Total output size: plaintext.size() + OVERHEAD
    static std::vector<uint8_t> seal(
        std::span<const uint8_t, KEY_LEN> key,
        std::span<const uint8_t, NONCE_LEN> nonce,
        std::span<const uint8_t> plaintext);

    // Decrypt and verify (open)
    // Input: tag[16] || ciphertext[N]
    // Returns plaintext or error if authentication fails
    static std::expected<std::vector<uint8_t>, SecretboxError> open(
        std::span<const uint8_t, KEY_LEN> key,
        std::span<const uint8_t, NONCE_LEN> nonce,
        std::span<const uint8_t> ciphertext);
};

// --- Low-level primitives (exposed for testing and obfs4 framing) ---

// Salsa20 quarter-round
void salsa20_quarterround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);

// Salsa20 core (20 rounds): 64 bytes in, 64 bytes out
void salsa20_core(uint8_t out[64], const uint8_t in[64]);

// HSalsa20: subkey derivation for XSalsa20
// key[32], nonce[16] -> subkey[32]
void hsalsa20(
    std::span<uint8_t, 32> out,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 16> nonce);

// XSalsa20 stream cipher (24-byte nonce)
// Encrypts/decrypts in place (XOR with keystream)
void xsalsa20_xor(
    std::span<uint8_t> data,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 24> nonce);

// Generate XSalsa20 keystream (for Poly1305 key derivation)
void xsalsa20_stream(
    std::span<uint8_t> stream,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 24> nonce);

// Poly1305 one-time authenticator
// key[32] (one-time key), message -> tag[16]
void poly1305(
    std::span<uint8_t, 16> out,
    std::span<const uint8_t> message,
    std::span<const uint8_t, 32> key);

// Poly1305 verify (constant-time)
bool poly1305_verify(
    std::span<const uint8_t, 16> tag,
    std::span<const uint8_t> message,
    std::span<const uint8_t, 32> key);

[[nodiscard]] std::string secretbox_error_message(SecretboxError err);

}  // namespace tor::crypto
