#pragma once

#include "tor/crypto/elligator2.hpp"
#include "tor/crypto/keys.hpp"
#include "tor/crypto/hash.hpp"
#include "tor/crypto/secretbox.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

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
constexpr size_t OBFS4_MAX_FRAME_PAYLOAD = 1448; // Max frame payload (MTU-friendly)
constexpr size_t OBFS4_FRAME_HDR_LEN = 2;        // Obfuscated length (DRBG XOR)
constexpr size_t OBFS4_FRAME_OVERHEAD = OBFS4_FRAME_HDR_LEN + crypto::Secretbox::OVERHEAD; // 2 + 16 = 18
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

// Handshake state machine for the server side of obfs4
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
    const crypto::NodeId& node_id_;
    const crypto::Curve25519SecretKey& identity_key_;

    // Handshake buffer
    std::vector<uint8_t> buffer_;

    // Parsed from client handshake
    std::array<uint8_t, OBFS4_REPR_LEN> client_representative_{};
    crypto::Curve25519PublicKey client_public_key_;

    // Server ephemeral key (generated during handshake)
    std::optional<crypto::RepresentableKeypair> server_ephemeral_;

    // Derived session keys
    SessionKeys session_keys_{};

    // ntor AUTH value (computed during key derivation, used in server hello)
    std::array<uint8_t, OBFS4_AUTH_LEN> auth_{};

    // Build the obfs4 HMAC key: identity_pub[32] || node_id[20]
    [[nodiscard]] std::vector<uint8_t> mac_key() const;

    // Scan buffer for HMAC mark
    [[nodiscard]] std::optional<size_t> find_mark() const;

    // Verify epoch-hour MAC
    [[nodiscard]] bool verify_epoch_mac(size_t mark_pos) const;

    // Derive session keys from ntor handshake outputs
    void derive_keys(
        std::span<const uint8_t, 32> exp_eph,     // DH(server_eph, client_eph)
        std::span<const uint8_t, 32> exp_id,       // DH(server_identity, client_eph)
        const crypto::Curve25519PublicKey& server_identity_pub,
        const crypto::Curve25519PublicKey& client_pub,
        const crypto::Curve25519PublicKey& server_eph_pub);
};

// --- SipHash-2-4 DRBG ---

// Deterministic random bit generator using SipHash-2-4 in OFB mode.
// Used for obfs4 frame length obfuscation per the obfs4 spec.
class Obfs4Drbg {
public:
    Obfs4Drbg() = default;

    // Initialize from 24-byte seed: siphash_key[16] || initial_ofb[8]
    void init(std::span<const uint8_t, 24> seed);

    // Generate next 8-byte block of DRBG output
    [[nodiscard]] std::array<uint8_t, 8> next_block();

    // Generate a 2-byte length mask for frame length obfuscation
    [[nodiscard]] uint16_t next_length_mask();

private:
    std::array<uint8_t, 16> key_{};
    std::array<uint8_t, 8> ofb_{};
    bool initialized_{false};
};

// --- obfs4 Framing ---

// Encrypt/decrypt obfs4 frames per the obfs4 spec:
// Frame = obfuscated_length[2] || secretbox_seal(payload)
// Length is XOR'd with SipHash-2-4 DRBG output for obfuscation.
class Obfs4Framing {
public:
    Obfs4Framing() = default;

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
    // Send state
    std::array<uint8_t, 32> send_key_{};
    std::array<uint8_t, 24> send_nonce_{};
    Obfs4Drbg send_drbg_;
    bool send_initialized_{false};

    // Receive state
    std::array<uint8_t, 32> recv_key_{};
    std::array<uint8_t, 24> recv_nonce_{};
    Obfs4Drbg recv_drbg_;
    bool recv_initialized_{false};

    // Receive buffer for partial frames
    std::vector<uint8_t> recv_buffer_;
    std::optional<uint16_t> pending_payload_len_;

    // Increment nonce (big-endian counter in last 8 bytes)
    static void increment_nonce(std::array<uint8_t, 24>& nonce);
};

// --- Utility ---

[[nodiscard]] std::string obfs4_error_message(Obfs4Error err);

// Compute epoch hour (hours since Unix epoch)
[[nodiscard]] int64_t epoch_hour();
[[nodiscard]] int64_t epoch_hour(std::chrono::system_clock::time_point tp);

}  // namespace tor::transport
