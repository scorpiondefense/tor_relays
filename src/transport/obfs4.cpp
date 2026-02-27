#include "tor/transport/obfs4.hpp"
#include "tor/util/logging.hpp"
#include <algorithm>
#include <cstring>

namespace tor::transport {

// --- ntor protocol constants ---
// These must match the obfs4proxy/lyrebird Go implementation exactly

static constexpr const char PROTO_ID[] = "ntor-curve25519-sha256-1";
static constexpr size_t PROTO_ID_LEN = 24; // strlen(PROTO_ID)

static constexpr const char T_MAC[] = "ntor-curve25519-sha256-1:mac";
static constexpr size_t T_MAC_LEN = 28;

static constexpr const char T_KEY[] = "ntor-curve25519-sha256-1:key_extract";
static constexpr size_t T_KEY_LEN = 37;

static constexpr const char T_VERIFY[] = "ntor-curve25519-sha256-1:key_verify";
static constexpr size_t T_VERIFY_LEN = 36;

static constexpr const char M_EXPAND[] = "ntor-curve25519-sha256-1:key_expand";
static constexpr size_t M_EXPAND_LEN = 36;

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

// --- Base64 (no padding) encoding/decoding ---

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode_nopad(std::span<const uint8_t> data) {
    std::string result;
    result.reserve((data.size() * 4 + 2) / 3);

    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        result += B64_CHARS[(n >> 18) & 63];
        result += B64_CHARS[(n >> 12) & 63];
        result += B64_CHARS[(n >> 6) & 63];
        result += B64_CHARS[n & 63];
        i += 3;
    }

    if (i + 1 == data.size()) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        result += B64_CHARS[(n >> 18) & 63];
        result += B64_CHARS[(n >> 12) & 63];
    } else if (i + 2 == data.size()) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8);
        result += B64_CHARS[(n >> 18) & 63];
        result += B64_CHARS[(n >> 12) & 63];
        result += B64_CHARS[(n >> 6) & 63];
    }

    return result;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::expected<std::vector<uint8_t>, Obfs4Error>
base64_decode_nopad(const std::string& encoded) {
    std::string padded = encoded;
    while (padded.size() % 4 != 0)
        padded += '=';

    std::vector<uint8_t> result;
    result.reserve(padded.size() * 3 / 4);

    for (size_t i = 0; i < padded.size(); i += 4) {
        int a = (padded[i] == '=') ? 0 : b64_decode_char(padded[i]);
        int b = (padded[i + 1] == '=') ? 0 : b64_decode_char(padded[i + 1]);
        int c_val = (padded[i + 2] == '=') ? 0 : b64_decode_char(padded[i + 2]);
        int d = (padded[i + 3] == '=') ? 0 : b64_decode_char(padded[i + 3]);

        if (a < 0 || b < 0 || c_val < 0 || d < 0)
            return std::unexpected(Obfs4Error::InvalidCert);

        uint32_t n = (static_cast<uint32_t>(a) << 18) |
                     (static_cast<uint32_t>(b) << 12) |
                     (static_cast<uint32_t>(c_val) << 6) |
                     static_cast<uint32_t>(d);

        result.push_back(static_cast<uint8_t>((n >> 16) & 0xff));
        if (padded[i + 2] != '=')
            result.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
        if (padded[i + 3] != '=')
            result.push_back(static_cast<uint8_t>(n & 0xff));
    }

    return result;
}

// --- Obfs4Identity ---

std::string Obfs4Identity::to_cert() const {
    // cert = base64_nopad(node_id[20] || ntor_public_key[32])
    std::array<uint8_t, OBFS4_CERT_RAW_LEN> raw{};
    std::memcpy(raw.data(), node_id.data().data(), OBFS4_NODE_ID_LEN);
    std::memcpy(raw.data() + OBFS4_NODE_ID_LEN,
                ntor_public_key.data().data(), OBFS4_PUBKEY_LEN);
    return base64_encode_nopad(raw);
}

std::expected<Obfs4Identity, Obfs4Error>
Obfs4Identity::from_cert(const std::string& cert) {
    auto decoded = base64_decode_nopad(cert);
    if (!decoded) {
        return std::unexpected(Obfs4Error::InvalidCert);
    }

    if (decoded->size() != OBFS4_CERT_RAW_LEN) {
        return std::unexpected(Obfs4Error::InvalidCert);
    }

    Obfs4Identity id;

    std::array<uint8_t, OBFS4_NODE_ID_LEN> nid_bytes{};
    std::memcpy(nid_bytes.data(), decoded->data(), OBFS4_NODE_ID_LEN);
    id.node_id = crypto::NodeId(nid_bytes);

    std::array<uint8_t, OBFS4_PUBKEY_LEN> pk_bytes{};
    std::memcpy(pk_bytes.data(), decoded->data() + OBFS4_NODE_ID_LEN, OBFS4_PUBKEY_LEN);
    id.ntor_public_key = crypto::Curve25519PublicKey(pk_bytes);

    return id;
}

// --- Obfs4ServerHandshake ---

Obfs4ServerHandshake::Obfs4ServerHandshake(
    const crypto::NodeId& node_id,
    const crypto::Curve25519SecretKey& identity_key)
    : node_id_(node_id)
    , identity_key_(identity_key) {}

// Build the obfs4 HMAC key: identity_pub[32] || node_id[20]
// This is used for mark scanning and epoch-hour MAC verification.
// Must match the Go implementation: append(serverIdentity.Public().Bytes(), nodeID.Bytes()...)
std::vector<uint8_t> Obfs4ServerHandshake::mac_key() const {
    std::vector<uint8_t> key;
    key.reserve(32 + 20);
    auto pub = identity_key_.public_key();
    key.insert(key.end(), pub.data().begin(), pub.data().end());
    key.insert(key.end(), node_id_.data().begin(), node_id_.data().end());
    return key;
}

std::expected<size_t, Obfs4Error>
Obfs4ServerHandshake::consume(std::span<const uint8_t> data) {
    if (state_ == State::Completed || state_ == State::Failed) {
        return 0;
    }

    size_t consumed = 0;

    // Append to buffer
    size_t space = OBFS4_MAX_HANDSHAKE_LEN - buffer_.size();
    size_t to_copy = std::min(data.size(), space);
    buffer_.insert(buffer_.end(), data.begin(), data.begin() + to_copy);
    consumed = to_copy;

    if (buffer_.size() >= OBFS4_MAX_HANDSHAKE_LEN && state_ == State::WaitingForMark) {
        state_ = State::Failed;
        return std::unexpected(Obfs4Error::BufferOverflow);
    }

    // Helper lambda to complete the handshake once mark+MAC are verified
    auto complete_handshake = [&](size_t mark_pos) -> std::expected<size_t, Obfs4Error> {
        // Generate server ephemeral representable keypair
        auto eph_result = crypto::Elligator2::generate_representable_keypair();
        if (!eph_result) {
            state_ = State::Failed;
            return std::unexpected(Obfs4Error::KeyGenerationFailed);
        }
        server_ephemeral_ = std::move(*eph_result);

        auto eph_sk = crypto::Curve25519SecretKey::from_bytes(server_ephemeral_->secret);
        if (!eph_sk) {
            state_ = State::Failed;
            return std::unexpected(Obfs4Error::KeyGenerationFailed);
        }

        // Compute shared secrets per ntor spec:
        // EXP1 = DH(server_ephemeral, client_pub) — ephemeral-ephemeral
        auto exp_eph = eph_sk->diffie_hellman(client_public_key_);
        if (!exp_eph) {
            state_ = State::Failed;
            return std::unexpected(Obfs4Error::HandshakeFailed);
        }

        // EXP2 = DH(server_identity, client_pub) — identity-ephemeral
        auto exp_id = identity_key_.diffie_hellman(client_public_key_);
        if (!exp_id) {
            state_ = State::Failed;
            return std::unexpected(Obfs4Error::HandshakeFailed);
        }

        // Server ephemeral public key (Y)
        auto server_eph_pub = eph_sk->public_key();

        // Derive ntor keys: KEY_SEED, verify, auth, session keys
        derive_keys(*exp_eph, *exp_id,
                    identity_key_.public_key(), client_public_key_, server_eph_pub);

        state_ = State::Completed;

        // Calculate how many bytes were actually consumed for the handshake
        size_t mac_end = mark_pos + OBFS4_MARK_LEN + OBFS4_MAC_LEN;
        if (mac_end < buffer_.size()) {
            consumed = consumed - (buffer_.size() - mac_end);
        }

        return consumed;
    };

    if (state_ == State::WaitingForMark) {
        if (buffer_.size() < OBFS4_REPR_LEN + OBFS4_MARK_LEN) {
            return consumed;
        }

        auto mark_pos = find_mark();
        if (!mark_pos) {
            return consumed;
        }

        // Mark found — extract representative and recover client public key
        std::memcpy(client_representative_.data(), buffer_.data(), OBFS4_REPR_LEN);
        client_public_key_ = crypto::Elligator2::representative_to_point(
            client_representative_);

        state_ = State::WaitingForMac;

        // Check if we already have enough data for the MAC
        size_t mac_end = *mark_pos + OBFS4_MARK_LEN + OBFS4_MAC_LEN;
        if (buffer_.size() >= mac_end) {
            if (!verify_epoch_mac(*mark_pos)) {
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::MacVerificationFailed);
            }
            return complete_handshake(*mark_pos);
        }
    } else if (state_ == State::WaitingForMac) {
        auto mark_pos = find_mark();
        if (mark_pos) {
            size_t mac_end = *mark_pos + OBFS4_MARK_LEN + OBFS4_MAC_LEN;
            if (buffer_.size() >= mac_end) {
                if (!verify_epoch_mac(*mark_pos)) {
                    state_ = State::Failed;
                    return std::unexpected(Obfs4Error::MacVerificationFailed);
                }
                return complete_handshake(*mark_pos);
            }
        }
    }

    return consumed;
}

std::optional<size_t> Obfs4ServerHandshake::find_mark() const {
    // The mark is HMAC-SHA256-128(key, representative[0:32]) truncated to 16 bytes
    // where key = identity_pub[32] || node_id[20]
    // It appears after the representative + random padding in the client handshake

    if (buffer_.size() < OBFS4_REPR_LEN + OBFS4_MARK_LEN) {
        return std::nullopt;
    }

    // Build the HMAC key: identity_pub || node_id
    auto key = mac_key();

    // Compute expected mark: HMAC-SHA256(key, representative)
    auto hmac_result = crypto::hmac_sha256(
        key,
        std::span<const uint8_t>(buffer_.data(), OBFS4_REPR_LEN));

    if (!hmac_result) {
        return std::nullopt;
    }

    // Search for the 16-byte truncated mark in the buffer after the representative
    for (size_t pos = OBFS4_REPR_LEN; pos + OBFS4_MARK_LEN <= buffer_.size(); ++pos) {
        bool match = true;
        for (size_t j = 0; j < OBFS4_MARK_LEN; ++j) {
            if (buffer_[pos + j] != (*hmac_result)[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return pos;
        }
    }

    return std::nullopt;
}

bool Obfs4ServerHandshake::verify_epoch_mac(size_t mark_pos) const {
    // MAC = HMAC-SHA256-128(key, representative || padding || mark || epoch_hour_string)
    // where key = identity_pub[32] || node_id[20]
    // MAC is truncated to 16 bytes

    size_t mac_start = mark_pos + OBFS4_MARK_LEN;
    if (buffer_.size() < mac_start + OBFS4_MAC_LEN) {
        return false;
    }

    auto key = mac_key();
    auto current_hour = epoch_hour();

    // Try current hour and +/- 1 hour for clock skew tolerance
    for (int64_t offset = -1; offset <= 1; ++offset) {
        auto hour = current_hour + offset;
        auto hour_str = std::to_string(hour);

        // MAC input: buffer[0 : mark_pos + MARK_LEN] || epoch_hour_string
        // This includes: representative + padding + mark
        std::vector<uint8_t> mac_input;
        mac_input.insert(mac_input.end(), buffer_.begin(),
                         buffer_.begin() + mark_pos + OBFS4_MARK_LEN);
        mac_input.insert(mac_input.end(),
                         reinterpret_cast<const uint8_t*>(hour_str.data()),
                         reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

        auto expected_mac = crypto::hmac_sha256(key, mac_input);
        if (!expected_mac) continue;

        // Compare only first 16 bytes (HMAC-SHA256-128)
        if (crypto::constant_time_compare(
                std::span<const uint8_t>(buffer_.data() + mac_start, OBFS4_MAC_LEN),
                std::span<const uint8_t>(expected_mac->data(), OBFS4_MAC_LEN))) {
            return true;
        }
    }

    return false;
}

void Obfs4ServerHandshake::derive_keys(
    std::span<const uint8_t, 32> exp_eph,
    std::span<const uint8_t, 32> exp_id,
    const crypto::Curve25519PublicKey& server_identity_pub,
    const crypto::Curve25519PublicKey& client_pub,
    const crypto::Curve25519PublicKey& server_eph_pub) {

    // Build secret_input per obfs4 ntor spec (matches Go implementation):
    // secret_input = EXP1 | EXP2 | B | B | X | Y | PROTOID | ID
    // where:
    //   EXP1 = DH(server_eph, client_eph) — ephemeral-ephemeral
    //   EXP2 = DH(server_identity, client_eph) — identity-ephemeral
    //   B = server identity public key (appears TWICE)
    //   X = client ephemeral public key
    //   Y = server ephemeral public key
    //   PROTOID = "ntor-curve25519-sha256-1"
    //   ID = node ID (20 bytes)

    // Build secret_input using memcpy to avoid GCC -Werror=array-bounds false positive
    constexpr size_t SECRET_INPUT_LEN = 32 + 32 + 32 + 32 + 32 + 32 + PROTO_ID_LEN + 20; // 236
    std::vector<uint8_t> secret_input(SECRET_INPUT_LEN);
    size_t off = 0;

    // EXP1: DH(server_eph, client)
    std::memcpy(secret_input.data() + off, exp_eph.data(), 32); off += 32;
    // EXP2: DH(server_identity, client)
    std::memcpy(secret_input.data() + off, exp_id.data(), 32); off += 32;
    // B (server identity pub) — first copy
    std::memcpy(secret_input.data() + off, server_identity_pub.data().data(), 32); off += 32;
    // B (server identity pub) — second copy
    std::memcpy(secret_input.data() + off, server_identity_pub.data().data(), 32); off += 32;
    // X (client ephemeral pub)
    std::memcpy(secret_input.data() + off, client_pub.data().data(), 32); off += 32;
    // Y (server ephemeral pub)
    std::memcpy(secret_input.data() + off, server_eph_pub.data().data(), 32); off += 32;
    // PROTOID
    std::memcpy(secret_input.data() + off, PROTO_ID, PROTO_ID_LEN); off += PROTO_ID_LEN;
    // ID (node ID, 20 bytes)
    std::memcpy(secret_input.data() + off, node_id_.data().data(), 20);

    // Suffix = B | B | X | Y | PROTOID | ID starts at offset 64 in secret_input
    constexpr size_t SUFFIX_OFFSET = 64;
    constexpr size_t SUFFIX_LEN = SECRET_INPUT_LEN - SUFFIX_OFFSET; // 172 bytes

    // Step 1: KEY_SEED = HMAC-SHA256(key=t_key, message=secret_input)
    auto t_key_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(T_KEY), T_KEY_LEN);
    auto key_seed = crypto::hmac_sha256(t_key_span, secret_input);
    if (!key_seed) return;

    // Step 2: verify = HMAC-SHA256(key=t_verify, message=secret_input)
    auto t_verify_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(T_VERIFY), T_VERIFY_LEN);
    auto verify = crypto::hmac_sha256(t_verify_span, secret_input);
    if (!verify) return;

    // Step 3: auth = HMAC-SHA256(key=t_mac, message=(verify | suffix | "Server"))
    auto t_mac_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(T_MAC), T_MAC_LEN);

    // Build auth_input = verify[32] | suffix[172] | "Server"[6] = 210 bytes
    constexpr size_t AUTH_INPUT_LEN = 32 + SUFFIX_LEN + 6; // 210
    std::vector<uint8_t> auth_input(AUTH_INPUT_LEN);
    size_t aoff = 0;
    std::memcpy(auth_input.data() + aoff, verify->data(), 32); aoff += 32;
    std::memcpy(auth_input.data() + aoff, secret_input.data() + SUFFIX_OFFSET, SUFFIX_LEN); aoff += SUFFIX_LEN;
    static constexpr const char SERVER_STR[] = "Server";
    std::memcpy(auth_input.data() + aoff, SERVER_STR, 6);

    auto auth_result = crypto::hmac_sha256(t_mac_span, auth_input);
    if (!auth_result) return;
    std::memcpy(auth_.data(), auth_result->data(), 32);

    // Step 4: Expand KEY_SEED into 144 bytes of session key material
    // Using HKDF-SHA256: Extract(salt=t_key, IKM=KEY_SEED) then Expand(info=m_expand, len=144)
    auto m_expand_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(M_EXPAND), M_EXPAND_LEN);
    auto key_material = crypto::hkdf_sha256(
        t_key_span,       // salt
        *key_seed,        // IKM
        m_expand_span,    // info
        144);             // output length

    if (!key_material) return;

    auto& km = *key_material;

    // Split 144 bytes into two 72-byte halves:
    // okm[0:72]   = client encoder key / server decoder key
    // okm[72:144] = client decoder key / server encoder key
    //
    // Each 72-byte block: secretbox_key[32] | nonce_prefix[16] | drbg_seed[24]
    // For now, map into current SessionKeys format (32-byte key + 24-byte nonce)

    // Server recv (client encoder) = okm[0:72]
    std::memcpy(session_keys_.recv_key.data(), km.data(), 32);
    // Build recv nonce: prefix[16] || counter[8] with counter=1
    std::array<uint8_t, 24> recv_nonce{};
    std::memcpy(recv_nonce.data(), km.data() + 32, 16);
    // Counter starts at 1 (big-endian)
    recv_nonce[23] = 1;
    std::memcpy(session_keys_.recv_nonce.data(), recv_nonce.data(), 24);

    // Server send (client decoder) = okm[72:144]
    std::memcpy(session_keys_.send_key.data(), km.data() + 72, 32);
    // Build send nonce: prefix[16] || counter[8] with counter=1
    std::array<uint8_t, 24> send_nonce{};
    std::memcpy(send_nonce.data(), km.data() + 72 + 32, 16);
    send_nonce[23] = 1;
    std::memcpy(session_keys_.send_nonce.data(), send_nonce.data(), 24);

    // Wipe sensitive data
    std::memset(secret_input.data(), 0, secret_input.size());
}

std::expected<std::vector<uint8_t>, Obfs4Error>
Obfs4ServerHandshake::generate_server_hello() {
    if (state_ != State::Completed || !server_ephemeral_) {
        return std::unexpected(Obfs4Error::InternalError);
    }

    // Server hello format (matches Go obfs4proxy):
    // Y_repr[32] | AUTH[32] | padding[variable] | mark[16] | mac[16]

    auto key = mac_key();
    std::vector<uint8_t> hello;

    // 1. Server representative Y_repr (32 bytes)
    hello.insert(hello.end(),
                 server_ephemeral_->representative.begin(),
                 server_ephemeral_->representative.end());

    // 2. ntor AUTH (32 bytes) — computed during derive_keys
    hello.insert(hello.end(), auth_.begin(), auth_.end());

    // 3. Random padding (between auth and mark)
    auto pad_len_bytes = crypto::random_bytes(2);
    uint16_t pad_len = (static_cast<uint16_t>(pad_len_bytes[0]) |
                       (static_cast<uint16_t>(pad_len_bytes[1]) << 8)) % 512;
    auto padding = crypto::random_bytes(pad_len);
    hello.insert(hello.end(), padding.begin(), padding.end());

    // 4. Mark: HMAC-SHA256-128(key, Y_repr) truncated to 16 bytes
    auto mark_hmac = crypto::hmac_sha256(
        key,
        server_ephemeral_->representative);
    if (!mark_hmac) {
        return std::unexpected(Obfs4Error::InternalError);
    }
    hello.insert(hello.end(), mark_hmac->begin(), mark_hmac->begin() + OBFS4_MARK_LEN);

    // 5. Epoch-hour MAC: HMAC-SHA256-128(key, Y_repr || AUTH || padding || mark || epoch_str)
    //    truncated to 16 bytes
    auto hour_str = std::to_string(epoch_hour());
    std::vector<uint8_t> mac_input(hello.begin(), hello.end());
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(hour_str.data()),
                     reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

    auto epoch_mac = crypto::hmac_sha256(key, mac_input);
    if (!epoch_mac) {
        return std::unexpected(Obfs4Error::InternalError);
    }
    // Truncate MAC to 16 bytes
    hello.insert(hello.end(), epoch_mac->begin(), epoch_mac->begin() + OBFS4_MAC_LEN);

    return hello;
}

// --- Obfs4Framing ---

void Obfs4Framing::init_send(std::span<const uint8_t, 32> key,
                              std::span<const uint8_t, 24> initial_nonce) {
    std::memcpy(send_key_.data(), key.data(), 32);
    std::memcpy(send_nonce_.data(), initial_nonce.data(), 24);
    send_initialized_ = true;
}

void Obfs4Framing::init_recv(std::span<const uint8_t, 32> key,
                              std::span<const uint8_t, 24> initial_nonce) {
    std::memcpy(recv_key_.data(), key.data(), 32);
    std::memcpy(recv_nonce_.data(), initial_nonce.data(), 24);
    recv_initialized_ = true;
}

void Obfs4Framing::increment_nonce(std::array<uint8_t, 24>& nonce) {
    // Big-endian increment of the last 8 bytes (counter portion)
    // Nonce format: prefix[16] || counter[8] (big-endian)
    for (int i = 23; i >= 16; --i) {
        if (++nonce[i] != 0) break;
    }
}

std::vector<uint8_t> Obfs4Framing::encode(std::span<const uint8_t> payload) {
    // Frame format:
    // secretbox_seal(length[2]) || secretbox_seal(payload)
    // where length is big-endian uint16
    // NOTE: Real obfs4 uses SipHash XOR for length, not secretbox.
    // This will be fixed in a follow-up commit.

    std::vector<uint8_t> output;

    uint16_t len = static_cast<uint16_t>(payload.size());
    std::array<uint8_t, 2> len_bytes = {
        static_cast<uint8_t>(len >> 8),
        static_cast<uint8_t>(len & 0xff)
    };

    auto sealed_len = crypto::Secretbox::seal(send_key_, send_nonce_, len_bytes);
    increment_nonce(send_nonce_);

    auto sealed_payload = crypto::Secretbox::seal(send_key_, send_nonce_, payload);
    increment_nonce(send_nonce_);

    output.insert(output.end(), sealed_len.begin(), sealed_len.end());
    output.insert(output.end(), sealed_payload.begin(), sealed_payload.end());

    return output;
}

std::expected<Obfs4Framing::DecodeResult, Obfs4Error>
Obfs4Framing::decode(std::span<const uint8_t> data) {
    DecodeResult result;
    result.consumed = 0;

    recv_buffer_.insert(recv_buffer_.end(), data.begin(), data.end());

    while (true) {
        if (!pending_payload_len_) {
            constexpr size_t SEALED_LEN_SIZE = 2 + crypto::Secretbox::OVERHEAD;
            if (recv_buffer_.size() < SEALED_LEN_SIZE) {
                break;
            }

            auto len_ct = std::span<const uint8_t>(recv_buffer_.data(), SEALED_LEN_SIZE);
            auto len_pt = crypto::Secretbox::open(recv_key_, recv_nonce_, len_ct);
            if (!len_pt) {
                return std::unexpected(Obfs4Error::FrameDecryptFailed);
            }
            increment_nonce(recv_nonce_);

            uint16_t payload_len = (static_cast<uint16_t>((*len_pt)[0]) << 8) |
                                    static_cast<uint16_t>((*len_pt)[1]);
            if (payload_len > OBFS4_MAX_FRAME_PAYLOAD) {
                return std::unexpected(Obfs4Error::FrameTooLarge);
            }

            pending_payload_len_ = payload_len;
            recv_buffer_.erase(recv_buffer_.begin(),
                              recv_buffer_.begin() + SEALED_LEN_SIZE);
            result.consumed += SEALED_LEN_SIZE;
        }

        size_t sealed_payload_size = *pending_payload_len_ + crypto::Secretbox::OVERHEAD;
        if (recv_buffer_.size() < sealed_payload_size) {
            break;
        }

        auto payload_ct = std::span<const uint8_t>(
            recv_buffer_.data(), sealed_payload_size);
        auto payload_pt = crypto::Secretbox::open(recv_key_, recv_nonce_, payload_ct);
        if (!payload_pt) {
            return std::unexpected(Obfs4Error::FrameDecryptFailed);
        }
        increment_nonce(recv_nonce_);

        result.frames.push_back(std::move(*payload_pt));
        recv_buffer_.erase(recv_buffer_.begin(),
                          recv_buffer_.begin() + sealed_payload_size);
        result.consumed += sealed_payload_size;
        pending_payload_len_.reset();
    }

    return result;
}

}  // namespace tor::transport
