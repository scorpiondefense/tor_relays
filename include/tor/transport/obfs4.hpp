#pragma once

#include "tor/crypto/keys.hpp"
#include "tor/crypto/hash.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

// Forward declarations for obfs4_cpp types (avoid exposing internals)
namespace obfs4::transport {
class ServerHandshake;
class Encoder;
class Decoder;
}
namespace obfs4::common {
class ReplayFilter;
class HashDrbg;
}

namespace tor::transport {

// obfs4 constants
constexpr size_t OBFS4_NODE_ID_LEN = 20;       // Tor node ID (SHA-1 of identity key)
constexpr size_t OBFS4_PUBKEY_LEN = 32;        // Curve25519 public key
constexpr size_t OBFS4_REPR_LEN = 32;          // Elligator2 representative
constexpr size_t OBFS4_MARK_LEN = 16;          // HMAC mark (truncated)
constexpr size_t OBFS4_MAC_LEN = 16;           // Epoch-hour MAC (HMAC-SHA256-128)
constexpr size_t OBFS4_AUTH_LEN = 32;          // Server authentication (ntor AUTH)
constexpr size_t OBFS4_CERT_RAW_LEN = 52;      // node_id[20] + pubkey[32]
constexpr size_t OBFS4_MAX_HANDSHAKE_LEN = 8192; // Max bytes to buffer for handshake
constexpr size_t OBFS4_MAX_FRAME_PAYLOAD = 1430; // Max frame payload (1448 segment - 18 overhead)
constexpr size_t OBFS4_FRAME_HDR_LEN = 2;        // Obfuscated length (DRBG XOR)
constexpr size_t OBFS4_FRAME_OVERHEAD = OBFS4_FRAME_HDR_LEN + 16; // 2 + poly1305 tag = 18
constexpr size_t OBFS4_MIN_CLIENT_HANDSHAKE = OBFS4_REPR_LEN + OBFS4_MARK_LEN + OBFS4_MAC_LEN; // 64
constexpr size_t OBFS4_MIN_SERVER_HANDSHAKE = OBFS4_REPR_LEN + OBFS4_AUTH_LEN + OBFS4_MARK_LEN + OBFS4_MAC_LEN; // 96

// IAT (Inter-Arrival Time) modes
enum class IatMode : uint8_t {
    Off = 0,      // No IAT obfuscation
    Enabled = 1,  // Add random padding to packets
    Paranoid = 2, // Add random padding + delay
};

// obfs4 error types
enum class Obfs4Error {
    HandshakeFailed,
    AuthenticationFailed,
    InvalidCert,
    MarkNotFound,
    MacVerificationFailed,
    EpochHourMismatch,
    FrameDecryptFailed,
    FrameTooLarge,
    BufferOverflow,
    KeyGenerationFailed,
    InternalError,
};

// --- obfs4 Identity ---

// Server identity for obfs4: combines node ID + ntor public key into a cert
struct Obfs4Identity {
    crypto::NodeId node_id;
    crypto::Curve25519PublicKey ntor_public_key;

    // Generate cert string: base64url_nopad(node_id[20] || pubkey[32])
    [[nodiscard]] std::string to_cert() const;

    // Parse cert string back to identity
    [[nodiscard]] static std::expected<Obfs4Identity, Obfs4Error>
    from_cert(const std::string& cert);
};

// --- obfs4 Server Handshake ---

// Handshake state machine for the server side of obfs4.
// Thin wrapper around obfs4::transport::ServerHandshake.
class Obfs4ServerHandshake {
public:
    enum class State {
        WaitingForMark,    // Accumulating bytes, scanning for HMAC mark
        WaitingForMac,     // Mark found, waiting for epoch-hour MAC
        Completed,         // Handshake done, session keys derived
        Failed,
    };

    Obfs4ServerHandshake(
        const crypto::NodeId& node_id,
        const crypto::Curve25519SecretKey& identity_key);

    ~Obfs4ServerHandshake();

    // Move-only (pimpl)
    Obfs4ServerHandshake(Obfs4ServerHandshake&&) noexcept;
    Obfs4ServerHandshake& operator=(Obfs4ServerHandshake&&) noexcept;

    // Feed incoming data. Returns:
    // - bytes consumed (may be less than input if handshake completes mid-buffer)
    // - use state() to check progress
    [[nodiscard]] std::expected<size_t, Obfs4Error>
    consume(std::span<const uint8_t> data);

    // Generate server hello message to send back to client
    [[nodiscard]] std::expected<std::vector<uint8_t>, Obfs4Error>
    generate_server_hello();

    // Current state
    [[nodiscard]] State state() const { return state_; }

    // Session keys (available after Completed state)
    // Each direction: secretbox_key[32] | nonce_prefix[16] | drbg_seed[24]
    struct SessionKeys {
        std::array<uint8_t, 32> send_key;       // Server -> Client secretbox key
        std::array<uint8_t, 32> recv_key;       // Client -> Server secretbox key
        std::array<uint8_t, 24> send_nonce;     // Initial send nonce (prefix[16] || counter[8])
        std::array<uint8_t, 24> recv_nonce;     // Initial recv nonce (prefix[16] || counter[8])
        std::array<uint8_t, 24> send_drbg_seed; // SipHash DRBG seed for send length obfuscation
        std::array<uint8_t, 24> recv_drbg_seed; // SipHash DRBG seed for recv length deobfuscation
    };

    [[nodiscard]] const SessionKeys& session_keys() const { return session_keys_; }

private:
    State state_{State::WaitingForMark};
    SessionKeys session_keys_{};

    // Pimpl: obfs4_cpp ServerHandshake + ReplayFilter
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// --- SipHash-2-4 DRBG ---

// Deterministic random bit generator using SipHash-2-4 in OFB mode.
// Thin wrapper around obfs4::common::HashDrbg.
class Obfs4Drbg {
public:
    Obfs4Drbg();
    ~Obfs4Drbg();

    // Move-only (pimpl)
    Obfs4Drbg(Obfs4Drbg&&) noexcept;
    Obfs4Drbg& operator=(Obfs4Drbg&&) noexcept;

    // Initialize from 24-byte seed: siphash_key[16] || initial_ofb[8]
    void init(std::span<const uint8_t, 24> seed);

    // Generate next 8-byte block of DRBG output
    [[nodiscard]] std::array<uint8_t, 8> next_block();

    // Generate a 2-byte length mask for frame length obfuscation
    [[nodiscard]] uint16_t next_length_mask();

private:
    std::unique_ptr<obfs4::common::HashDrbg> impl_;
};

// --- obfs4 Framing ---

// Encrypt/decrypt obfs4 frames per the obfs4 spec.
// Thin wrapper around obfs4::transport::Encoder + Decoder.
class Obfs4Framing {
public:
    Obfs4Framing();
    ~Obfs4Framing();

    // Move-only (pimpl)
    Obfs4Framing(Obfs4Framing&&) noexcept;
    Obfs4Framing& operator=(Obfs4Framing&&) noexcept;

    // Initialize with session keys and DRBG seeds
    void init_send(std::span<const uint8_t, 32> key,
                   std::span<const uint8_t, 24> initial_nonce,
                   std::span<const uint8_t, 24> drbg_seed);
    void init_recv(std::span<const uint8_t, 32> key,
                   std::span<const uint8_t, 24> initial_nonce,
                   std::span<const uint8_t, 24> drbg_seed);

    // Encode a frame: returns obfuscated_length[2] || secretbox_seal(payload)
    [[nodiscard]] std::vector<uint8_t> encode(std::span<const uint8_t> payload);

    // Decode frames from incoming data.
    // Returns decoded payloads and consumes bytes from the buffer.
    struct DecodeResult {
        std::vector<std::vector<uint8_t>> frames; // Decoded frame payloads
        size_t consumed;                           // Bytes consumed from input
    };

    [[nodiscard]] std::expected<DecodeResult, Obfs4Error>
    decode(std::span<const uint8_t> data);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// --- Utility ---

[[nodiscard]] std::string obfs4_error_message(Obfs4Error err);

// Compute epoch hour (hours since Unix epoch)
[[nodiscard]] int64_t epoch_hour();
[[nodiscard]] int64_t epoch_hour(std::chrono::system_clock::time_point tp);

}  // namespace tor::transport
