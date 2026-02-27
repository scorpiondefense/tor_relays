#include "tor/crypto/secretbox.hpp"
#include <cstring>

namespace tor::crypto {

// --- Utility ---

static inline uint32_t load32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// --- Salsa20 quarter-round ---

void salsa20_quarterround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    b ^= rotl32(a + d, 7);
    c ^= rotl32(b + a, 9);
    d ^= rotl32(c + b, 13);
    a ^= rotl32(d + c, 18);
}

// --- Salsa20 core (20 rounds) ---
// Input and output are 64 bytes (16 uint32_t words)

void salsa20_core(uint8_t out[64], const uint8_t in[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i)
        x[i] = load32_le(in + 4 * i);

    uint32_t w[16];
    std::memcpy(w, x, sizeof(w));

    // 20 rounds = 10 double-rounds
    for (int i = 0; i < 10; ++i) {
        // Column round
        salsa20_quarterround(w[0],  w[4],  w[8],  w[12]);
        salsa20_quarterround(w[5],  w[9],  w[13], w[1]);
        salsa20_quarterround(w[10], w[14], w[2],  w[6]);
        salsa20_quarterround(w[15], w[3],  w[7],  w[11]);
        // Row round
        salsa20_quarterround(w[0],  w[1],  w[2],  w[3]);
        salsa20_quarterround(w[5],  w[6],  w[7],  w[4]);
        salsa20_quarterround(w[10], w[11], w[8],  w[9]);
        salsa20_quarterround(w[15], w[12], w[13], w[14]);
    }

    for (int i = 0; i < 16; ++i)
        store32_le(out + 4 * i, w[i] + x[i]);
}

// --- HSalsa20: subkey derivation ---
// Takes key[32] and nonce[16], produces subkey[32]
// This is the "first half" of XSalsa20.

void hsalsa20(
    std::span<uint8_t, 32> out,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 16> nonce) {

    // Salsa20 input matrix:
    // sigma0  key0..3   sigma1
    // nonce0..3
    // sigma2  key4..7   sigma3
    // (but HSalsa20 uses the nonce differently)
    //
    // Input:
    // sigma[0]  key[0]    key[1]    key[2]
    // key[3]    sigma[1]  nonce[0]  nonce[1]
    // nonce[2]  nonce[3]  sigma[2]  key[4]
    // key[5]    key[6]    key[7]    sigma[3]

    static const uint8_t sigma[16] = {
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
        '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };

    uint32_t x[16];
    x[0]  = load32_le(sigma);
    x[1]  = load32_le(key.data());
    x[2]  = load32_le(key.data() + 4);
    x[3]  = load32_le(key.data() + 8);
    x[4]  = load32_le(key.data() + 12);
    x[5]  = load32_le(sigma + 4);
    x[6]  = load32_le(nonce.data());
    x[7]  = load32_le(nonce.data() + 4);
    x[8]  = load32_le(nonce.data() + 8);
    x[9]  = load32_le(nonce.data() + 12);
    x[10] = load32_le(sigma + 8);
    x[11] = load32_le(key.data() + 16);
    x[12] = load32_le(key.data() + 20);
    x[13] = load32_le(key.data() + 24);
    x[14] = load32_le(key.data() + 28);
    x[15] = load32_le(sigma + 12);

    // 20 rounds (no final addition for HSalsa20)
    for (int i = 0; i < 10; ++i) {
        salsa20_quarterround(x[0],  x[4],  x[8],  x[12]);
        salsa20_quarterround(x[5],  x[9],  x[13], x[1]);
        salsa20_quarterround(x[10], x[14], x[2],  x[6]);
        salsa20_quarterround(x[15], x[3],  x[7],  x[11]);
        salsa20_quarterround(x[0],  x[1],  x[2],  x[3]);
        salsa20_quarterround(x[5],  x[6],  x[7],  x[4]);
        salsa20_quarterround(x[10], x[11], x[8],  x[9]);
        salsa20_quarterround(x[15], x[12], x[13], x[14]);
    }

    // Output: words 0, 5, 10, 15, 6, 7, 8, 9
    store32_le(out.data(),      x[0]);
    store32_le(out.data() + 4,  x[5]);
    store32_le(out.data() + 8,  x[10]);
    store32_le(out.data() + 12, x[15]);
    store32_le(out.data() + 16, x[6]);
    store32_le(out.data() + 20, x[7]);
    store32_le(out.data() + 24, x[8]);
    store32_le(out.data() + 28, x[9]);
}

// --- Salsa20 stream cipher (8-byte nonce, for use by XSalsa20) ---

static void salsa20_xor_internal(
    std::span<uint8_t> data,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 8> nonce,
    uint64_t counter) {

    static const uint8_t sigma[16] = {
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
        '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };

    size_t remaining = data.size();
    size_t offset = 0;

    while (remaining > 0) {
        uint8_t input[64];
        store32_le(input,      load32_le(sigma));
        store32_le(input + 4,  load32_le(key.data()));
        store32_le(input + 8,  load32_le(key.data() + 4));
        store32_le(input + 12, load32_le(key.data() + 8));
        store32_le(input + 16, load32_le(key.data() + 12));
        store32_le(input + 20, load32_le(sigma + 4));
        store32_le(input + 24, load32_le(nonce.data()));
        store32_le(input + 28, load32_le(nonce.data() + 4));
        store32_le(input + 32, static_cast<uint32_t>(counter));
        store32_le(input + 36, static_cast<uint32_t>(counter >> 32));
        store32_le(input + 40, load32_le(sigma + 8));
        store32_le(input + 44, load32_le(key.data() + 16));
        store32_le(input + 48, load32_le(key.data() + 20));
        store32_le(input + 52, load32_le(key.data() + 24));
        store32_le(input + 56, load32_le(key.data() + 28));
        store32_le(input + 60, load32_le(sigma + 12));

        uint8_t block[64];
        salsa20_core(block, input);

        size_t chunk = (remaining < 64) ? remaining : 64;
        for (size_t i = 0; i < chunk; ++i) {
            data[offset + i] ^= block[i];
        }

        offset += chunk;
        remaining -= chunk;
        counter++;
    }
}

// --- Salsa20 stream generation (8-byte nonce) ---

static void salsa20_stream_internal(
    std::span<uint8_t> stream,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 8> nonce,
    uint64_t counter) {

    std::memset(stream.data(), 0, stream.size());
    salsa20_xor_internal(stream, key, nonce, counter);
}

// --- XSalsa20 ---

void xsalsa20_xor(
    std::span<uint8_t> data,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 24> nonce) {

    // Step 1: derive subkey via HSalsa20(key, nonce[0:16])
    std::array<uint8_t, 32> subkey;
    std::span<const uint8_t, 16> nonce_prefix(nonce.data(), 16);
    hsalsa20(subkey, key, nonce_prefix);

    // Step 2: encrypt with Salsa20(subkey, nonce[16:24])
    std::span<const uint8_t, 8> nonce_suffix(nonce.data() + 16, 8);
    salsa20_xor_internal(data, subkey, nonce_suffix, 0);

    // Wipe subkey
    std::memset(subkey.data(), 0, 32);
}

void xsalsa20_stream(
    std::span<uint8_t> stream,
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 24> nonce) {

    std::array<uint8_t, 32> subkey;
    std::span<const uint8_t, 16> nonce_prefix(nonce.data(), 16);
    hsalsa20(subkey, key, nonce_prefix);

    std::span<const uint8_t, 8> nonce_suffix(nonce.data() + 16, 8);
    salsa20_stream_internal(stream, subkey, nonce_suffix, 0);

    std::memset(subkey.data(), 0, 32);
}

// --- Poly1305 ---

void poly1305(
    std::span<uint8_t, 16> out,
    std::span<const uint8_t> message,
    std::span<const uint8_t, 32> key) {

    using u128 = __extension__ unsigned __int128;

    // Clamp r (first 16 bytes of key)
    uint32_t r0 = load32_le(key.data())      & 0x0fffffff;
    uint32_t r1 = load32_le(key.data() + 4)  & 0x0ffffffc;
    uint32_t r2 = load32_le(key.data() + 8)  & 0x0ffffffc;
    uint32_t r3 = load32_le(key.data() + 12) & 0x0ffffffc;

    // s (last 16 bytes of key, used for final addition)
    uint32_t s0 = load32_le(key.data() + 16);
    uint32_t s1 = load32_le(key.data() + 20);
    uint32_t s2 = load32_le(key.data() + 24);
    uint32_t s3 = load32_le(key.data() + 28);

    // Use 130-bit state (5 x 26-bit limbs -> actually use 44-bit limbs with u64)
    // For simplicity and correctness, use u128 arithmetic
    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    // Convert r to 5 x 26-bit limbs for modular arithmetic
    uint64_t t0 = r0 & 0x3ffffff;
    uint64_t t1 = ((static_cast<uint64_t>(r0) >> 26) | (static_cast<uint64_t>(r1) << 6)) & 0x3ffffff;
    uint64_t t2 = ((static_cast<uint64_t>(r1) >> 20) | (static_cast<uint64_t>(r2) << 12)) & 0x3ffffff;
    uint64_t t3 = ((static_cast<uint64_t>(r2) >> 14) | (static_cast<uint64_t>(r3) << 18)) & 0x3ffffff;
    uint64_t t4 = (static_cast<uint64_t>(r3) >> 8);

    uint64_t rr0 = t0, rr1 = t1, rr2 = t2, rr3 = t3, rr4 = t4;
    uint64_t s1_mul = rr1 * 5, s2_mul = rr2 * 5, s3_mul = rr3 * 5, s4_mul = rr4 * 5;

    size_t remaining = message.size();
    size_t offset = 0;

    while (remaining > 0) {
        // Read 16-byte block and add high bit
        uint8_t block[17] = {};
        size_t chunk = (remaining < 16) ? remaining : 16;
        std::memcpy(block, message.data() + offset, chunk);
        block[chunk] = 1;  // High bit

        // Convert to 5 x 26-bit limbs
        uint64_t m0 = load32_le(block) & 0x3ffffff;
        uint64_t m1 = (load32_le(block + 3) >> 2) & 0x3ffffff;
        uint64_t m2 = (load32_le(block + 6) >> 4) & 0x3ffffff;
        uint64_t m3 = (load32_le(block + 9) >> 6) & 0x3ffffff;
        uint64_t m4 = 0;
        if (chunk >= 13) {
            m4 = load32_le(block + 12) >> 8;
        } else if (chunk >= 12) {
            m4 = (static_cast<uint64_t>(block[12]) |
                  (static_cast<uint64_t>(block[13]) << 8) |
                  (static_cast<uint64_t>(block[14]) << 16) |
                  (static_cast<uint64_t>(block[15]) << 24) |
                  (static_cast<uint64_t>(block[16]) << 32)) >> 8;
        }
        // For short blocks, recompute from the padded buffer
        if (chunk < 16) {
            m0 = (static_cast<uint64_t>(block[0]) |
                  (static_cast<uint64_t>(block[1]) << 8) |
                  (static_cast<uint64_t>(block[2]) << 16) |
                  (static_cast<uint64_t>(block[3]) << 24)) & 0x3ffffff;
            m1 = (static_cast<uint64_t>(block[3]) >> 2 |
                  (static_cast<uint64_t>(block[4]) << 6) |
                  (static_cast<uint64_t>(block[5]) << 14) |
                  (static_cast<uint64_t>(block[6]) << 22)) & 0x3ffffff;
            m2 = (static_cast<uint64_t>(block[6]) >> 4 |
                  (static_cast<uint64_t>(block[7]) << 4) |
                  (static_cast<uint64_t>(block[8]) << 12) |
                  (static_cast<uint64_t>(block[9]) << 20)) & 0x3ffffff;
            m3 = (static_cast<uint64_t>(block[9]) >> 6 |
                  (static_cast<uint64_t>(block[10]) << 2) |
                  (static_cast<uint64_t>(block[11]) << 10) |
                  (static_cast<uint64_t>(block[12]) << 18)) & 0x3ffffff;
            m4 = (static_cast<uint64_t>(block[13]) |
                  (static_cast<uint64_t>(block[14]) << 8) |
                  (static_cast<uint64_t>(block[15]) << 16) |
                  (static_cast<uint64_t>(block[16]) << 24));
        }

        // h += m
        h0 += m0;
        h1 += m1;
        h2 += m2;
        h3 += m3;
        h4 += m4;

        // h *= r (mod 2^130 - 5)
        u128 d0 = (u128)h0 * rr0 + (u128)h1 * s4_mul + (u128)h2 * s3_mul + (u128)h3 * s2_mul + (u128)h4 * s1_mul;
        u128 d1 = (u128)h0 * rr1 + (u128)h1 * rr0 + (u128)h2 * s4_mul + (u128)h3 * s3_mul + (u128)h4 * s2_mul;
        u128 d2 = (u128)h0 * rr2 + (u128)h1 * rr1 + (u128)h2 * rr0 + (u128)h3 * s4_mul + (u128)h4 * s3_mul;
        u128 d3 = (u128)h0 * rr3 + (u128)h1 * rr2 + (u128)h2 * rr1 + (u128)h3 * rr0 + (u128)h4 * s4_mul;
        u128 d4 = (u128)h0 * rr4 + (u128)h1 * rr3 + (u128)h2 * rr2 + (u128)h3 * rr1 + (u128)h4 * rr0;

        // Carry
        uint64_t c;
        h0 = static_cast<uint64_t>(d0) & 0x3ffffff; c = static_cast<uint64_t>(d0 >> 26);
        d1 += c; h1 = static_cast<uint64_t>(d1) & 0x3ffffff; c = static_cast<uint64_t>(d1 >> 26);
        d2 += c; h2 = static_cast<uint64_t>(d2) & 0x3ffffff; c = static_cast<uint64_t>(d2 >> 26);
        d3 += c; h3 = static_cast<uint64_t>(d3) & 0x3ffffff; c = static_cast<uint64_t>(d3 >> 26);
        d4 += c; h4 = static_cast<uint64_t>(d4) & 0x3ffffff; c = static_cast<uint64_t>(d4 >> 26);
        h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        offset += chunk;
        remaining -= chunk;
    }

    // Final reduction
    uint64_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // Compute h + -p = h - (2^130 - 5)
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);

    // Select h or g based on whether g < 2^130
    uint64_t mask = (g4 >> 63) - 1;  // 0 if g4 < 0 (select h), all-1s if g4 >= 0 (select g)
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Pack h into 128 bits and add s
    uint64_t f0 = h0 | (h1 << 26);
    uint64_t f1 = (h1 >> 6) | (h2 << 20);
    uint64_t f2 = (h2 >> 12) | (h3 << 14);
    uint64_t f3 = (h3 >> 18) | (h4 << 8);

    // Add s
    u128 acc = static_cast<u128>(f0) + s0;
    store32_le(out.data(), static_cast<uint32_t>(acc));
    acc = (acc >> 32) + f1 + s1;
    store32_le(out.data() + 4, static_cast<uint32_t>(acc));
    acc = (acc >> 32) + f2 + s2;
    store32_le(out.data() + 8, static_cast<uint32_t>(acc));
    acc = (acc >> 32) + f3 + s3;
    store32_le(out.data() + 12, static_cast<uint32_t>(acc));
}

bool poly1305_verify(
    std::span<const uint8_t, 16> tag,
    std::span<const uint8_t> message,
    std::span<const uint8_t, 32> key) {

    std::array<uint8_t, 16> computed;
    poly1305(computed, message, key);

    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i)
        diff |= computed[i] ^ tag[i];
    return diff == 0;
}

// --- Secretbox: XSalsa20-Poly1305 ---

std::vector<uint8_t> Secretbox::seal(
    std::span<const uint8_t, KEY_LEN> key,
    std::span<const uint8_t, NONCE_LEN> nonce,
    std::span<const uint8_t> plaintext) {

    // Generate Poly1305 key: first 32 bytes of XSalsa20 stream
    std::array<uint8_t, 32> poly_key{};
    // We need 32 bytes of keystream for poly key, then encrypt starting at byte 32
    // NaCl uses the first 32 bytes of the stream as the Poly1305 one-time key

    // Allocate output: tag[16] + ciphertext[plaintext.size()]
    size_t ct_len = plaintext.size();
    std::vector<uint8_t> output(TAG_LEN + ct_len);

    // Create a buffer with 32 zero bytes + plaintext
    // Encrypt with XSalsa20, extract poly key from first 32 bytes
    std::vector<uint8_t> padded(32 + ct_len, 0);
    std::memcpy(padded.data() + 32, plaintext.data(), ct_len);
    xsalsa20_xor(padded, key, nonce);

    // First 32 bytes are the Poly1305 one-time key
    std::memcpy(poly_key.data(), padded.data(), 32);

    // Ciphertext is bytes 32..end
    std::memcpy(output.data() + TAG_LEN, padded.data() + 32, ct_len);

    // Compute Poly1305 tag over ciphertext
    std::array<uint8_t, 16> tag;
    std::span<const uint8_t> ct_span(output.data() + TAG_LEN, ct_len);
    poly1305(tag, ct_span, poly_key);

    // Prepend tag
    std::memcpy(output.data(), tag.data(), TAG_LEN);

    // Wipe sensitive data
    std::memset(poly_key.data(), 0, 32);
    std::memset(padded.data(), 0, padded.size());

    return output;
}

std::expected<std::vector<uint8_t>, SecretboxError> Secretbox::open(
    std::span<const uint8_t, KEY_LEN> key,
    std::span<const uint8_t, NONCE_LEN> nonce,
    std::span<const uint8_t> ciphertext) {

    if (ciphertext.size() < TAG_LEN) {
        return std::unexpected(SecretboxError::MessageTooShort);
    }

    size_t ct_len = ciphertext.size() - TAG_LEN;
    auto tag_span = std::span<const uint8_t, 16>(ciphertext.data(), 16);
    auto ct_data = std::span<const uint8_t>(ciphertext.data() + TAG_LEN, ct_len);

    // Generate Poly1305 key from first 32 bytes of keystream
    std::vector<uint8_t> padded(32 + ct_len, 0);
    xsalsa20_stream(std::span<uint8_t>(padded.data(), 32), key, nonce);

    std::array<uint8_t, 32> poly_key;
    std::memcpy(poly_key.data(), padded.data(), 32);

    // Verify tag
    if (!poly1305_verify(tag_span, ct_data, poly_key)) {
        std::memset(poly_key.data(), 0, 32);
        return std::unexpected(SecretboxError::DecryptionFailed);
    }

    // Decrypt: reconstruct padded buffer and XOR with stream
    std::memset(padded.data(), 0, 32);
    std::memcpy(padded.data() + 32, ct_data.data(), ct_len);
    xsalsa20_xor(padded, key, nonce);

    std::vector<uint8_t> plaintext(ct_len);
    std::memcpy(plaintext.data(), padded.data() + 32, ct_len);

    // Wipe
    std::memset(poly_key.data(), 0, 32);
    std::memset(padded.data(), 0, padded.size());

    return plaintext;
}

std::string secretbox_error_message(SecretboxError err) {
    switch (err) {
        case SecretboxError::InvalidKeyLength: return "Invalid key length";
        case SecretboxError::InvalidNonceLength: return "Invalid nonce length";
        case SecretboxError::DecryptionFailed: return "Decryption failed (authentication tag mismatch)";
        case SecretboxError::MessageTooShort: return "Ciphertext too short";
        default: return "Unknown secretbox error";
    }
}

}  // namespace tor::crypto
