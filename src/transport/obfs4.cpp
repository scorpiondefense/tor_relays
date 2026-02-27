#include "tor/transport/obfs4.hpp"
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

// --- Base64url (no padding) encoding/decoding ---

static const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64url_encode_nopad(std::span<const uint8_t> data) {
    // Use standard base64 but with +/ (obfs4 spec uses standard base64, not URL-safe)
    std::string result;
    result.reserve((data.size() * 4 + 2) / 3);

    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        result += B64URL_CHARS[(n >> 18) & 63];
        result += B64URL_CHARS[(n >> 12) & 63];
        result += B64URL_CHARS[(n >> 6) & 63];
        result += B64URL_CHARS[n & 63];
        i += 3;
    }

    if (i + 1 == data.size()) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        result += B64URL_CHARS[(n >> 18) & 63];
        result += B64URL_CHARS[(n >> 12) & 63];
    } else if (i + 2 == data.size()) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8);
        result += B64URL_CHARS[(n >> 18) & 63];
        result += B64URL_CHARS[(n >> 12) & 63];
        result += B64URL_CHARS[(n >> 6) & 63];
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
base64url_decode_nopad(const std::string& encoded) {
    // Add padding if needed
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
    return base64url_encode_nopad(raw);
}

std::expected<Obfs4Identity, Obfs4Error>
Obfs4Identity::from_cert(const std::string& cert) {
    auto decoded = base64url_decode_nopad(cert);
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

    if (state_ == State::WaitingForMark) {
        // Need at least representative[32] + mark[16]
        if (buffer_.size() < OBFS4_REPR_LEN + OBFS4_MARK_LEN) {
            return consumed;
        }

        auto mark_pos = find_mark();
        if (!mark_pos) {
            // Haven't found mark yet, keep waiting
            return consumed;
        }

        // Mark found at position *mark_pos
        // Extract representative (first 32 bytes)
        std::memcpy(client_representative_.data(), buffer_.data(), OBFS4_REPR_LEN);

        // Recover client public key via Elligator2
        client_public_key_ = crypto::Elligator2::representative_to_point(
            client_representative_);

        state_ = State::WaitingForMac;

        // Check if we have enough data for the MAC too
        size_t mac_start = *mark_pos + OBFS4_MARK_LEN;
        size_t mac_end = mac_start + OBFS4_MAC_LEN;

        if (buffer_.size() >= mac_end) {
            if (!verify_epoch_mac(*mark_pos)) {
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::MacVerificationFailed);
            }

            // Compute shared secrets
            auto shared_eph = identity_key_.diffie_hellman(client_public_key_);
            if (!shared_eph) {
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::HandshakeFailed);
            }

            // For the server handshake, we also need an ephemeral key
            auto eph_result = crypto::Elligator2::generate_representable_keypair();
            if (!eph_result) {
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::KeyGenerationFailed);
            }
            server_ephemeral_ = std::move(*eph_result);

            // Second shared secret: ephemeral DH
            auto eph_sk = crypto::Curve25519SecretKey::from_bytes(server_ephemeral_->secret);
            if (!eph_sk) {
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::KeyGenerationFailed);
            }

            auto shared_id = eph_sk->diffie_hellman(client_public_key_);
            if (!shared_id) {
                state_ = State::Failed;
                return std::unexpected(Obfs4Error::HandshakeFailed);
            }

            derive_keys(*shared_eph, *shared_id);

            state_ = State::Completed;

            // Calculate how many bytes were actually consumed for the handshake
            // Any bytes after mac_end are post-handshake data
            size_t handshake_len = mac_end;
            if (handshake_len < buffer_.size()) {
                // Some bytes in buffer are post-handshake, adjust consumed
                consumed = consumed - (buffer_.size() - handshake_len);
            }
        }
    } else if (state_ == State::WaitingForMac) {
        // We already found the mark, just waiting for MAC bytes
        auto mark_pos = find_mark();
        if (mark_pos) {
            size_t mac_end = *mark_pos + OBFS4_MARK_LEN + OBFS4_MAC_LEN;
            if (buffer_.size() >= mac_end) {
                if (!verify_epoch_mac(*mark_pos)) {
                    state_ = State::Failed;
                    return std::unexpected(Obfs4Error::MacVerificationFailed);
                }

                auto shared_eph = identity_key_.diffie_hellman(client_public_key_);
                if (!shared_eph) {
                    state_ = State::Failed;
                    return std::unexpected(Obfs4Error::HandshakeFailed);
                }

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

                auto shared_id = eph_sk->diffie_hellman(client_public_key_);
                if (!shared_id) {
                    state_ = State::Failed;
                    return std::unexpected(Obfs4Error::HandshakeFailed);
                }

                derive_keys(*shared_eph, *shared_id);
                state_ = State::Completed;
            }
        }
    }

    return consumed;
}

std::optional<size_t> Obfs4ServerHandshake::find_mark() const {
    // The mark is HMAC-SHA256(node_id, representative[0:32]) truncated to 16 bytes
    // It appears immediately after the representative in the client handshake

    if (buffer_.size() < OBFS4_REPR_LEN + OBFS4_MARK_LEN) {
        return std::nullopt;
    }

    // Compute expected mark
    auto hmac_result = crypto::hmac_sha256(
        node_id_.as_span(),
        std::span<const uint8_t>(buffer_.data(), OBFS4_REPR_LEN));

    if (!hmac_result) {
        return std::nullopt;
    }

    // Search for the 16-byte mark in the buffer starting after the representative
    std::span<const uint8_t> expected_mark(hmac_result->data(), OBFS4_MARK_LEN);

    for (size_t pos = OBFS4_REPR_LEN; pos + OBFS4_MARK_LEN <= buffer_.size(); ++pos) {
        bool match = true;
        for (size_t j = 0; j < OBFS4_MARK_LEN; ++j) {
            if (buffer_[pos + j] != expected_mark[j]) {
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
    // The MAC covers: representative || mark || epoch_hour_string
    // MAC key is the node ID

    size_t mac_start = mark_pos + OBFS4_MARK_LEN;
    if (buffer_.size() < mac_start + OBFS4_MAC_LEN) {
        return false;
    }

    auto current_hour = epoch_hour();

    // Try current hour and +/- 1 hour for clock skew tolerance
    for (int64_t offset = -1; offset <= 1; ++offset) {
        auto hour = current_hour + offset;
        auto hour_str = std::to_string(hour);

        // Construct MAC input: representative[0:32] || mark[16] || epoch_hour_string
        std::vector<uint8_t> mac_input;
        mac_input.insert(mac_input.end(), buffer_.begin(),
                         buffer_.begin() + mark_pos + OBFS4_MARK_LEN);
        mac_input.insert(mac_input.end(),
                         reinterpret_cast<const uint8_t*>(hour_str.data()),
                         reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

        auto expected_mac = crypto::hmac_sha256(node_id_.as_span(), mac_input);
        if (!expected_mac) continue;

        if (crypto::constant_time_compare(
                std::span<const uint8_t>(buffer_.data() + mac_start, OBFS4_MAC_LEN),
                std::span<const uint8_t>(expected_mac->data(), OBFS4_MAC_LEN))) {
            return true;
        }
    }

    return false;
}

void Obfs4ServerHandshake::derive_keys(
    std::span<const uint8_t, 32> shared_secret_eph,
    std::span<const uint8_t, 32> shared_secret_id) {

    // Concatenate shared secrets for key derivation
    std::vector<uint8_t> ikm;
    ikm.insert(ikm.end(), shared_secret_eph.begin(), shared_secret_eph.end());
    ikm.insert(ikm.end(), shared_secret_id.begin(), shared_secret_id.end());

    // Use HKDF-SHA256 to derive session keys
    // Salt: node_id
    // Info: "obfs4-session-keys"
    static const uint8_t info[] = "obfs4-session-keys";

    // Derive 2*32 + 2*24 = 112 bytes of key material
    auto key_material = crypto::hkdf_sha256(
        node_id_.as_span(),
        ikm,
        std::span<const uint8_t>(info, sizeof(info) - 1),
        112);

    if (!key_material) {
        return;
    }

    auto& km = *key_material;

    // Server send key (key[0:32])
    std::memcpy(session_keys_.send_key.data(), km.data(), 32);
    // Server recv key (key[32:64])
    std::memcpy(session_keys_.recv_key.data(), km.data() + 32, 32);
    // Server send nonce (key[64:88])
    std::memcpy(session_keys_.send_nonce.data(), km.data() + 64, 24);
    // Server recv nonce (key[88:112])
    std::memcpy(session_keys_.recv_nonce.data(), km.data() + 88, 24);

    // Wipe IKM
    std::memset(ikm.data(), 0, ikm.size());
}

std::expected<std::vector<uint8_t>, Obfs4Error>
Obfs4ServerHandshake::generate_server_hello() {
    if (state_ != State::Completed || !server_ephemeral_) {
        return std::unexpected(Obfs4Error::InternalError);
    }

    // Server hello: representative[32] || auth[32] || mark[16] || mac[32] || padding
    std::vector<uint8_t> hello;

    // 1. Server representative (32 bytes)
    hello.insert(hello.end(),
                 server_ephemeral_->representative.begin(),
                 server_ephemeral_->representative.end());

    // 2. Auth: HMAC-SHA256(shared_secret, server_repr || client_repr)
    std::vector<uint8_t> auth_input;
    auth_input.insert(auth_input.end(),
                      server_ephemeral_->representative.begin(),
                      server_ephemeral_->representative.end());
    auth_input.insert(auth_input.end(),
                      client_representative_.begin(),
                      client_representative_.end());

    // Use first shared secret as auth key
    auto auth_mac = crypto::hmac_sha256(
        session_keys_.send_key,
        auth_input);
    if (!auth_mac) {
        return std::unexpected(Obfs4Error::InternalError);
    }
    hello.insert(hello.end(), auth_mac->begin(), auth_mac->end());

    // 3. Mark: HMAC-SHA256(node_id, server_repr) truncated to 16 bytes
    auto mark_hmac = crypto::hmac_sha256(
        node_id_.as_span(),
        server_ephemeral_->representative);
    if (!mark_hmac) {
        return std::unexpected(Obfs4Error::InternalError);
    }
    hello.insert(hello.end(), mark_hmac->begin(), mark_hmac->begin() + OBFS4_MARK_LEN);

    // 4. Epoch-hour MAC
    auto hour_str = std::to_string(epoch_hour());
    std::vector<uint8_t> mac_input(hello.begin(), hello.end());
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(hour_str.data()),
                     reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

    auto epoch_mac = crypto::hmac_sha256(node_id_.as_span(), mac_input);
    if (!epoch_mac) {
        return std::unexpected(Obfs4Error::InternalError);
    }
    hello.insert(hello.end(), epoch_mac->begin(), epoch_mac->end());

    // 5. Random padding (0-8192 bytes, but keep it small for now)
    auto pad_len_bytes = crypto::random_bytes(2);
    uint16_t pad_len = (static_cast<uint16_t>(pad_len_bytes[0]) |
                       (static_cast<uint16_t>(pad_len_bytes[1]) << 8)) % 512;
    auto padding = crypto::random_bytes(pad_len);
    hello.insert(hello.end(), padding.begin(), padding.end());

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
    // Little-endian increment
    for (size_t i = 0; i < nonce.size(); ++i) {
        if (++nonce[i] != 0) break;
    }
}

std::vector<uint8_t> Obfs4Framing::encode(std::span<const uint8_t> payload) {
    // Frame format:
    // secretbox_seal(length[2]) || secretbox_seal(payload)
    // where length is big-endian uint16

    std::vector<uint8_t> output;

    // Encrypt length (2 bytes, big-endian)
    uint16_t len = static_cast<uint16_t>(payload.size());
    std::array<uint8_t, 2> len_bytes = {
        static_cast<uint8_t>(len >> 8),
        static_cast<uint8_t>(len & 0xff)
    };

    auto sealed_len = crypto::Secretbox::seal(send_key_, send_nonce_, len_bytes);
    increment_nonce(send_nonce_);

    // Encrypt payload
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

    // Add incoming data to buffer
    recv_buffer_.insert(recv_buffer_.end(), data.begin(), data.end());

    while (true) {
        if (!pending_payload_len_) {
            // Need to decrypt the length header
            // sealed length = 2 + 16 = 18 bytes
            constexpr size_t SEALED_LEN_SIZE = 2 + crypto::Secretbox::OVERHEAD;
            if (recv_buffer_.size() < SEALED_LEN_SIZE) {
                break; // Need more data
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

        // We have a pending payload length, try to read the payload
        size_t sealed_payload_size = *pending_payload_len_ + crypto::Secretbox::OVERHEAD;
        if (recv_buffer_.size() < sealed_payload_size) {
            break; // Need more data
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
