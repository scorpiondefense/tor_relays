#include "tor/transport/obfs4.hpp"
#include "obfs4/transport/handshake.hpp"
#include "obfs4/transport/framing.hpp"
#include "obfs4/transport/state.hpp"
#include "obfs4/common/replay_filter.hpp"
#include "obfs4/common/drbg.hpp"
#include "obfs4/common/ntor.hpp"
#include "obfs4/crypto/elligator2.hpp"
#include <algorithm>
#include <cstring>

namespace tor::transport {

// --- Utility ---

int64_t epoch_hour() {
    return epoch_hour(std::chrono::system_clock::now());
}

int64_t epoch_hour(std::chrono::system_clock::time_point tp) {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        tp.time_since_epoch()).count();
    return secs / 3600;
}

std::string obfs4_error_message(Obfs4Error err) {
    switch (err) {
        case Obfs4Error::HandshakeFailed: return "obfs4 handshake failed";
        case Obfs4Error::AuthenticationFailed: return "obfs4 authentication failed";
        case Obfs4Error::InvalidCert: return "Invalid obfs4 cert";
        case Obfs4Error::MarkNotFound: return "HMAC mark not found in handshake";
        case Obfs4Error::MacVerificationFailed: return "Epoch-hour MAC verification failed";
        case Obfs4Error::EpochHourMismatch: return "Epoch-hour mismatch";
        case Obfs4Error::FrameDecryptFailed: return "Frame decryption failed";
        case Obfs4Error::FrameTooLarge: return "Frame payload too large";
        case Obfs4Error::BufferOverflow: return "Handshake buffer overflow";
        case Obfs4Error::KeyGenerationFailed: return "Key generation failed";
        case Obfs4Error::InternalError: return "Internal obfs4 error";
        default: return "Unknown obfs4 error";
    }
}

// --- Type conversion helpers ---

static obfs4::common::NodeID to_obfs4_node_id(const crypto::NodeId& nid) {
    obfs4::common::NodeID result{};
    std::memcpy(result.data(), nid.data().data(), 20);
    return result;
}

static obfs4::crypto::PublicKey to_obfs4_pubkey(const crypto::Curve25519PublicKey& pk) {
    obfs4::crypto::PublicKey result{};
    std::memcpy(result.data(), pk.data().data(), 32);
    return result;
}

static obfs4::crypto::PrivateKey to_obfs4_privkey(const crypto::Curve25519SecretKey& sk) {
    obfs4::crypto::PrivateKey result{};
    auto bytes = sk.as_bytes();
    std::memcpy(result.data(), bytes.data(), 32);
    return result;
}

static obfs4::crypto::Keypair to_obfs4_keypair(const crypto::Curve25519SecretKey& sk) {
    obfs4::crypto::Keypair kp;
    kp.private_key = to_obfs4_privkey(sk);
    kp.public_key = to_obfs4_pubkey(sk.public_key());
    kp.representative = std::nullopt;
    return kp;
}

// Extract SessionKeys from obfs4::transport::HandshakeKeys
// HandshakeKeys has two 72-byte blocks:
//   encoder_key_material[72] = key[32] + nonce_prefix[16] + drbg_seed[24]
//   decoder_key_material[72] = key[32] + nonce_prefix[16] + drbg_seed[24]
// For the server:
//   encoder = server-send (okm[72:144] in the Go impl)
//   decoder = server-recv (okm[0:72] in the Go impl)
static Obfs4ServerHandshake::SessionKeys extract_session_keys(
    const obfs4::transport::HandshakeKeys& hk) {

    Obfs4ServerHandshake::SessionKeys sk{};

    // Server send = encoder_key_material
    std::memcpy(sk.send_key.data(), hk.encoder_key_material.data(), 32);
    // Build send nonce: prefix[16] || counter[8] with counter=1
    std::memcpy(sk.send_nonce.data(), hk.encoder_key_material.data() + 32, 16);
    sk.send_nonce[23] = 1; // Big-endian counter starts at 1
    // DRBG seed for send: bytes [48:72]
    std::memcpy(sk.send_drbg_seed.data(), hk.encoder_key_material.data() + 48, 24);

    // Server recv = decoder_key_material
    std::memcpy(sk.recv_key.data(), hk.decoder_key_material.data(), 32);
    // Build recv nonce: prefix[16] || counter[8] with counter=1
    std::memcpy(sk.recv_nonce.data(), hk.decoder_key_material.data() + 32, 16);
    sk.recv_nonce[23] = 1;
    // DRBG seed for recv: bytes [48:72]
    std::memcpy(sk.recv_drbg_seed.data(), hk.decoder_key_material.data() + 48, 24);

    return sk;
}

// --- Obfs4Identity ---

std::string Obfs4Identity::to_cert() const {
    auto obfs4_nid = to_obfs4_node_id(node_id);
    auto obfs4_pk = to_obfs4_pubkey(ntor_public_key);
    return obfs4::transport::encode_cert(obfs4_nid, obfs4_pk);
}

std::expected<Obfs4Identity, Obfs4Error>
Obfs4Identity::from_cert(const std::string& cert) {
    auto result = obfs4::transport::decode_cert(cert);
    if (!result) {
        return std::unexpected(Obfs4Error::InvalidCert);
    }

    auto& [nid, pk] = *result;

    Obfs4Identity id;
    id.node_id = crypto::NodeId(nid);
    id.ntor_public_key = crypto::Curve25519PublicKey(pk);
    return id;
}

// --- Obfs4ServerHandshake ---

struct Obfs4ServerHandshake::Impl {
    obfs4::common::ReplayFilter replay_filter;
    std::unique_ptr<obfs4::transport::ServerHandshake> handshake;

    Impl(const obfs4::crypto::Keypair& id_kp, const obfs4::common::NodeID& nid)
        : replay_filter()
        , handshake(std::make_unique<obfs4::transport::ServerHandshake>(
              id_kp, nid, replay_filter))
    {}
};

Obfs4ServerHandshake::Obfs4ServerHandshake(
    const crypto::NodeId& node_id,
    const crypto::Curve25519SecretKey& identity_key)
{
    auto obfs4_kp = to_obfs4_keypair(identity_key);
    auto obfs4_nid = to_obfs4_node_id(node_id);
    impl_ = std::make_unique<Impl>(obfs4_kp, obfs4_nid);
}

Obfs4ServerHandshake::~Obfs4ServerHandshake() = default;
Obfs4ServerHandshake::Obfs4ServerHandshake(Obfs4ServerHandshake&&) noexcept = default;
Obfs4ServerHandshake& Obfs4ServerHandshake::operator=(Obfs4ServerHandshake&&) noexcept = default;

std::expected<size_t, Obfs4Error>
Obfs4ServerHandshake::consume(std::span<const uint8_t> data) {
    if (state_ == State::Completed || state_ == State::Failed) {
        return 0;
    }

    auto result = impl_->handshake->consume(data);
    if (!result) {
        // Map obfs4_cpp errors to tor::transport errors
        switch (result.error()) {
            case obfs4::transport::HandshakeError::BufferOverflow:
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::BufferOverflow);
            case obfs4::transport::HandshakeError::MacVerificationFailed:
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::MacVerificationFailed);
            case obfs4::transport::HandshakeError::ReplayDetected:
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::AuthenticationFailed);
            case obfs4::transport::HandshakeError::NtorFailed:
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::HandshakeFailed);
            case obfs4::transport::HandshakeError::KeyGenerationFailed:
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::KeyGenerationFailed);
            case obfs4::transport::HandshakeError::NeedMore:
                // Not an error — just need more data
                return data.size();
            default:
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::InternalError);
        }
    }

    if (impl_->handshake->completed()) {
        state_ = State::Completed;
        session_keys_ = extract_session_keys(impl_->handshake->keys());
    }

    return *result;
}

std::expected<std::vector<uint8_t>, Obfs4Error>
Obfs4ServerHandshake::generate_server_hello() {
    if (state_ != State::Completed) {
        return std::unexpected(Obfs4Error::InternalError);
    }

    auto result = impl_->handshake->generate();
    if (!result) {
        return std::unexpected(Obfs4Error::InternalError);
    }

    return *result;
}

// --- Obfs4Drbg ---

Obfs4Drbg::Obfs4Drbg()
    : impl_(std::make_unique<obfs4::common::HashDrbg>()) {}

Obfs4Drbg::~Obfs4Drbg() = default;
Obfs4Drbg::Obfs4Drbg(Obfs4Drbg&&) noexcept = default;
Obfs4Drbg& Obfs4Drbg::operator=(Obfs4Drbg&&) noexcept = default;

void Obfs4Drbg::init(std::span<const uint8_t, 24> seed) {
    impl_->init(seed);
}

std::array<uint8_t, 8> Obfs4Drbg::next_block() {
    return impl_->next_block();
}

uint16_t Obfs4Drbg::next_length_mask() {
    return impl_->next_length_mask();
}

// --- Obfs4Framing ---

struct Obfs4Framing::Impl {
    obfs4::transport::Encoder encoder;
    obfs4::transport::Decoder decoder;
    bool send_initialized = false;
    bool recv_initialized = false;
};

Obfs4Framing::Obfs4Framing()
    : impl_(std::make_unique<Impl>()) {}

Obfs4Framing::~Obfs4Framing() = default;
Obfs4Framing::Obfs4Framing(Obfs4Framing&&) noexcept = default;
Obfs4Framing& Obfs4Framing::operator=(Obfs4Framing&&) noexcept = default;

void Obfs4Framing::init_send(std::span<const uint8_t, 32> key,
                              std::span<const uint8_t, 24> initial_nonce,
                              std::span<const uint8_t, 24> drbg_seed) {
    // The obfs4_cpp Encoder::init takes the 16-byte nonce prefix (not the full 24-byte nonce)
    std::array<uint8_t, 16> nonce_prefix{};
    std::memcpy(nonce_prefix.data(), initial_nonce.data(), 16);

    impl_->encoder.init(key, nonce_prefix, drbg_seed);
    impl_->send_initialized = true;
}

void Obfs4Framing::init_recv(std::span<const uint8_t, 32> key,
                              std::span<const uint8_t, 24> initial_nonce,
                              std::span<const uint8_t, 24> drbg_seed) {
    // Extract 16-byte nonce prefix from 24-byte nonce
    std::array<uint8_t, 16> nonce_prefix{};
    std::memcpy(nonce_prefix.data(), initial_nonce.data(), 16);

    impl_->decoder.init(key, nonce_prefix, drbg_seed);
    impl_->recv_initialized = true;
}

std::vector<uint8_t> Obfs4Framing::encode(std::span<const uint8_t> payload) {
    return impl_->encoder.encode(payload);
}

std::expected<Obfs4Framing::DecodeResult, Obfs4Error>
Obfs4Framing::decode(std::span<const uint8_t> data) {
    auto result = impl_->decoder.decode(data);
    if (!result) {
        switch (result.error()) {
            case obfs4::transport::FrameError::TagMismatch:
                return std::unexpected(Obfs4Error::FrameDecryptFailed);
            case obfs4::transport::FrameError::InvalidLength:
                return std::unexpected(Obfs4Error::FrameTooLarge);
            default:
                return std::unexpected(Obfs4Error::InternalError);
        }
    }

    DecodeResult dr;
    dr.consumed = result->consumed;
    for (auto& frame : result->frames) {
        dr.frames.push_back(std::move(frame.payload));
    }
    return dr;
}

}  // namespace tor::transport
