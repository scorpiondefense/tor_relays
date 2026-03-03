#include "tor/core/relay.hpp"
#include "tor/core/circuit.hpp"
#include "tor/crypto/aes_ctr.hpp"
#include "tor/crypto/hash.hpp"
#include "tor/crypto/key_store.hpp"
#include "tor/crypto/ntor.hpp"
#include "tor/crypto/tls.hpp"
#include "tor/modes/bridge_relay.hpp"
#include "tor/net/acceptor.hpp"
#include "tor/protocol/link_protocol.hpp"
#include "tor/transport/obfs4_listener.hpp"
#include "tor/util/config.hpp"
#include "tor/util/logging.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include <chrono>
#include <thread>
#include <algorithm>
#include <deque>
#include <unordered_map>
#include <arpa/inet.h>

namespace tor::core {

// --- KDF-TOR for CREATE_FAST ---
// K = SHA1(K0|[0x00]) || SHA1(K0|[0x01]) || ...
// Produces: Df(20) || Db(20) || Kf(16) || Kb(16) || KH(20) = 92 bytes
static std::vector<uint8_t> kdf_tor(const uint8_t* k0, size_t k0_len) {
    std::vector<uint8_t> result;
    result.reserve(100); // 5 * 20
    for (uint8_t i = 0; i < 5; ++i) {
        uint8_t digest[20];
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, k0, k0_len);
        SHA1_Update(&ctx, &i, 1);
        SHA1_Final(digest, &ctx);
        result.insert(result.end(), digest, digest + 20);
    }
    return result; // 100 bytes, use first 92
}

// Helper: base64 encode binary data
static std::string base64_encode(const uint8_t* data, size_t len, bool no_newline = false) {
    BIO* b64_bio = BIO_new(BIO_f_base64());
    BIO* mem_bio = BIO_new(BIO_s_mem());
    BIO_push(b64_bio, mem_bio);
    if (no_newline) BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64_bio, data, static_cast<int>(len));
    BIO_flush(b64_bio);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64_bio, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64_bio);
    return result;
}

// Helper: Build Ed25519 cert (same format as link_protocol.cpp)
static std::vector<uint8_t> build_descriptor_ed_cert(
    uint8_t cert_type,
    const crypto::Ed25519PublicKey& certified_key,
    const crypto::Ed25519SecretKey& signing_key,
    const crypto::Ed25519PublicKey& signer_pub)
{
    // Build cert body
    std::vector<uint8_t> body;

    // VERSION
    body.push_back(1);
    // CERT_TYPE
    body.push_back(cert_type);
    // EXPIRATION_DATE (hours since epoch, 24 hours from now)
    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    uint32_t exp_hours = static_cast<uint32_t>((secs / 3600) + 24);
    body.push_back(static_cast<uint8_t>((exp_hours >> 24) & 0xFF));
    body.push_back(static_cast<uint8_t>((exp_hours >> 16) & 0xFF));
    body.push_back(static_cast<uint8_t>((exp_hours >> 8) & 0xFF));
    body.push_back(static_cast<uint8_t>(exp_hours & 0xFF));
    // CERT_KEY_TYPE (0x01 = Ed25519)
    body.push_back(0x01);
    // CERTIFIED_KEY
    auto ck = certified_key.as_span();
    body.insert(body.end(), ck.begin(), ck.end());
    // N_EXTENSIONS = 1
    body.push_back(1);
    // Extension: SignedWithEd25519Key (type 4)
    body.push_back(0x00); body.push_back(0x20); // ExtLength = 32
    body.push_back(0x04); // ExtType = SignedWithEd25519Key
    body.push_back(0x00); // ExtFlags = 0
    auto sk = signer_pub.as_span();
    body.insert(body.end(), sk.begin(), sk.end());

    // Sign
    auto sig = signing_key.sign(
        std::span<const uint8_t>(body.data(), body.size()));
    if (sig) {
        body.insert(body.end(), sig->begin(), sig->end());
    } else {
        body.resize(body.size() + 64, 0); // placeholder
    }

    return body;
}

// Helper: Build a minimal bridge server descriptor
static std::string build_bridge_descriptor(
    const std::string& nickname,
    const std::string& address,
    uint16_t or_port,
    const crypto::Rsa1024Identity& rsa_identity,
    const crypto::Ed25519SecretKey& ed_identity_key,
    const crypto::Ed25519PublicKey& ed_identity_pub,
    const crypto::Curve25519PublicKey& onion_key,
    const crypto::Ed25519SecretKey& onion_ed_key,
    uint8_t onion_ed_sign_bit,
    const crypto::NodeId& fingerprint)
{
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now;
    gmtime_r(&time_t_now, &tm_now);

    char time_buf[32];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_now);

    // Format fingerprint with spaces every 4 hex chars
    std::string fp_hex = fingerprint.to_hex();
    std::string fp_spaced;
    for (size_t i = 0; i < fp_hex.size(); i += 4) {
        if (i > 0) fp_spaced += ' ';
        fp_spaced += fp_hex.substr(i, 4);
    }
    for (auto& c : fp_spaced) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    // RSA public key base64
    auto rsa_pkcs1_der = rsa_identity.rsa_public_key_der();
    std::string rsa_key_b64 = base64_encode(rsa_pkcs1_der.data(), rsa_pkcs1_der.size());

    // Helper: strip base64 padding (Tor uses base64 without '=' padding for inline values)
    auto strip_padding = [](std::string& s) {
        while (!s.empty() && s.back() == '=') s.pop_back();
    };

    // ntor onion key base64 (no newlines, no padding)
    auto onion_span = onion_key.as_span();
    std::string ntor_key_b64 = base64_encode(onion_span.data(), onion_span.size(), true);
    strip_padding(ntor_key_b64);

    // Ed25519 identity public key base64 (no newlines, no padding)
    auto ed_pub_span = ed_identity_pub.as_span();
    std::string ed_pub_b64 = base64_encode(ed_pub_span.data(), ed_pub_span.size(), true);
    strip_padding(ed_pub_b64);

    // Build Ed25519 signing cert (Type 4: identity certifies signing key)
    // For simplicity, we use the identity key as the signing key too
    auto ed_cert = build_descriptor_ed_cert(
        0x04, // ED25519_SIGNING cert type
        ed_identity_pub,  // certified key = signing key = identity key
        ed_identity_key,  // signer = identity key
        ed_identity_pub); // signer pub for extension
    std::string ed_cert_b64 = base64_encode(ed_cert.data(), ed_cert.size());

    // Build descriptor body
    std::ostringstream desc;
    desc << "router " << nickname << " " << address << " " << or_port << " 0 0\n";
    desc << "identity-ed25519\n";
    desc << "-----BEGIN ED25519 CERT-----\n";
    desc << ed_cert_b64;
    if (ed_cert_b64.back() != '\n') desc << "\n";
    desc << "-----END ED25519 CERT-----\n";
    desc << "master-key-ed25519 " << ed_pub_b64 << "\n";
    desc << "platform Tor 0.4.9.5 on Linux\n";
    desc << "proto Cons=1-2 Desc=1-2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n";
    desc << "published " << time_buf << "\n";
    desc << "fingerprint " << fp_spaced << "\n";
    desc << "uptime 3600\n";
    desc << "bandwidth 1073741824 1073741824 0\n";
    desc << "onion-key\n";
    desc << "-----BEGIN RSA PUBLIC KEY-----\n";
    desc << rsa_key_b64;
    if (rsa_key_b64.back() != '\n') desc << "\n";
    desc << "-----END RSA PUBLIC KEY-----\n";
    desc << "signing-key\n";
    desc << "-----BEGIN RSA PUBLIC KEY-----\n";
    desc << rsa_key_b64;
    if (rsa_key_b64.back() != '\n') desc << "\n";
    desc << "-----END RSA PUBLIC KEY-----\n";
    // onion-key-crosscert: RSA signature by onion-key over
    // SHA1(RSA_identity_key_DER) || Ed25519_identity_key (52 bytes)
    {
        // Build the 52-byte data to sign
        auto rsa_id_der = rsa_identity.rsa_public_key_der();
        uint8_t rsa_id_hash[20];
        SHA1(rsa_id_der.data(), rsa_id_der.size(), rsa_id_hash);

        std::vector<uint8_t> crosscert_data(52, 0);
        std::memcpy(crosscert_data.data(), rsa_id_hash, 20);
        auto ed_id_span = ed_identity_pub.as_span();
        std::memcpy(crosscert_data.data() + 20, ed_id_span.data(), 32);

        // Sign with the onion key (RSA) - we use the same RSA key for both
        auto crosscert_sig = rsa_identity.sign_raw(
            std::span<const uint8_t>(crosscert_data.data(), crosscert_data.size()));

        if (crosscert_sig) {
            std::string crosscert_b64 = base64_encode(
                crosscert_sig->data(), crosscert_sig->size());
            desc << "onion-key-crosscert\n";
            desc << "-----BEGIN CROSSCERT-----\n";
            desc << crosscert_b64;
            if (crosscert_b64.back() != '\n') desc << "\n";
            desc << "-----END CROSSCERT-----\n";
        } else {
            LOG_WARN("Failed to create onion-key-crosscert");
            ERR_clear_error();
        }
    }

    desc << "ntor-onion-key " << ntor_key_b64 << "\n";

    // ntor-onion-key-crosscert: Type 10 cert, signed by Ed25519 key
    // corresponding to the ntor onion key, certifying the identity key
    auto ntor_crosscert = build_descriptor_ed_cert(
        0x0A, // ONION_KEY_NTOR_CROSSCERT cert type (10)
        ed_identity_pub,   // certified key = identity public key
        onion_ed_key,      // signer = Ed25519 key from onion key
        onion_ed_key.public_key()); // signer pub for extension
    std::string ntor_crosscert_b64 = base64_encode(
        ntor_crosscert.data(), ntor_crosscert.size());
    desc << "ntor-onion-key-crosscert " << static_cast<int>(onion_ed_sign_bit) << "\n";
    desc << "-----BEGIN ED25519 CERT-----\n";
    desc << ntor_crosscert_b64;
    if (ntor_crosscert_b64.back() != '\n') desc << "\n";
    desc << "-----END ED25519 CERT-----\n";

    desc << "bridge-distribution-request any\n";
    desc << "reject *:*\n";

    // Ed25519 signature: SHA-256(PREFIX || body), then sign the 32-byte hash
    // PREFIX = "Tor router descriptor signature v1"
    // body = text from "router" to "router-sig-ed25519 " (with trailing space)
    desc << "router-sig-ed25519 ";
    std::string desc_before_ed_sig = desc.str();

    std::string ed_sig_prefix = "Tor router descriptor signature v1";
    // Compute SHA-256(prefix || descriptor_text_before_sig)
    uint8_t ed_hash[32];
    {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, ed_sig_prefix.data(), ed_sig_prefix.size());
        EVP_DigestUpdate(ctx, desc_before_ed_sig.data(), desc_before_ed_sig.size());
        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(ctx, ed_hash, &hash_len);
        EVP_MD_CTX_free(ctx);
    }

    auto ed_sig = ed_identity_key.sign(
        std::span<const uint8_t>(ed_hash, 32));

    std::string ed_sig_b64;
    if (ed_sig) {
        ed_sig_b64 = base64_encode(ed_sig->data(), ed_sig->size(), true);
        strip_padding(ed_sig_b64);
    } else {
        LOG_WARN("Failed to Ed25519-sign bridge descriptor");
        ed_sig_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }

    desc << ed_sig_b64 << "\n";
    desc << "router-signature\n";

    // RSA signature: SHA-1 hash of text from "router" to "router-signature\n"
    std::string desc_str = desc.str();
    uint8_t desc_hash[20];
    SHA1(reinterpret_cast<const uint8_t*>(desc_str.data()),
         desc_str.size(), desc_hash);

    auto rsa_sig = rsa_identity.sign_raw(
        std::span<const uint8_t>(desc_hash, 20));

    if (rsa_sig) {
        std::string sig_b64 = base64_encode(rsa_sig->data(), rsa_sig->size());
        desc_str += "-----BEGIN SIGNATURE-----\n";
        desc_str += sig_b64;
        if (sig_b64.back() != '\n') desc_str += "\n";
        desc_str += "-----END SIGNATURE-----\n";
    } else {
        LOG_WARN("Failed to RSA-sign bridge descriptor");
        ERR_clear_error();
        desc_str += "-----BEGIN SIGNATURE-----\n";
        desc_str += "AAAA\n";
        desc_str += "-----END SIGNATURE-----\n";
    }

    return desc_str;
}

// Per-circuit crypto state for connection handler
struct CircuitCrypto {
    crypto::AesCtr128 forward_cipher;   // decrypt incoming (Kf)
    crypto::AesCtr128 backward_cipher;  // encrypt outgoing (Kb)
    crypto::RunningDigest forward_digest;  // verify incoming (Df)
    crypto::RunningDigest backward_digest; // create outgoing (Db)
};

// Next-hop connection state for EXTEND2 circuits
struct NextHopState {
    std::shared_ptr<Channel> channel;
    std::atomic<bool> running{true};
    std::thread reader_thread;

    ~NextHopState() {
        running = false;
        if (channel) channel->close();
        if (reader_thread.joinable()) reader_thread.join();
    }
};

// Result of decrypting a relay cell at this hop
struct DecryptResult {
    enum class Type { ForUs, Forward, Error };
    Type type{Type::Error};
    std::array<uint8_t, PAYLOAD_LEN> decrypted_payload{};
    std::optional<RelayCell> relay;  // Set only if type == ForUs
};

// Decrypt one layer and determine if cell is for us or should be forwarded
static DecryptResult decrypt_relay_cell_or_forward(
    CircuitCrypto& crypto, const Cell& cell)
{
    DecryptResult result;
    result.decrypted_payload = cell.payload;

    // Decrypt with forward cipher (Kf) - always updates AES-CTR state
    auto dec = crypto.forward_cipher.process(
        std::span<uint8_t>(result.decrypted_payload.data(), PAYLOAD_LEN));
    if (!dec) {
        result.type = DecryptResult::Type::Error;
        return result;
    }

    auto& payload = result.decrypted_payload;

    // Check recognized field (bytes 1-2)
    uint16_t recognized = (static_cast<uint16_t>(payload[1]) << 8) |
                           static_cast<uint16_t>(payload[2]);
    if (recognized != 0) {
        // Not for us - forward to next hop (don't update running digest)
        result.type = DecryptResult::Type::Forward;
        return result;
    }

    // Clone digest state before updating (in case recognized=0 is coincidence)
    auto digest_save = crypto.forward_digest.clone();

    // Save and zero digest field
    uint32_t saved_digest = (static_cast<uint32_t>(payload[5]) << 24) |
                            (static_cast<uint32_t>(payload[6]) << 16) |
                            (static_cast<uint32_t>(payload[7]) << 8) |
                             static_cast<uint32_t>(payload[8]);
    payload[5] = payload[6] = payload[7] = payload[8] = 0;

    // Update forward running digest and verify
    auto computed = crypto.forward_digest.update_and_digest(
        std::span<const uint8_t>(payload.data(), PAYLOAD_LEN));
    if (!computed || *computed != saved_digest) {
        // Digest mismatch - recognized=0 was coincidence, forward the cell
        // Restore the digest state
        if (digest_save) {
            crypto.forward_digest = std::move(*digest_save);
        }
        // Restore the digest bytes in payload for forwarding
        payload[5] = static_cast<uint8_t>((saved_digest >> 24) & 0xFF);
        payload[6] = static_cast<uint8_t>((saved_digest >> 16) & 0xFF);
        payload[7] = static_cast<uint8_t>((saved_digest >> 8) & 0xFF);
        payload[8] = static_cast<uint8_t>(saved_digest & 0xFF);
        result.type = DecryptResult::Type::Forward;
        return result;
    }

    // Cell is for us - parse relay header
    result.type = DecryptResult::Type::ForUs;
    RelayCell relay;
    relay.command = static_cast<RelayCommand>(payload[0]);
    relay.recognized = recognized;
    relay.stream_id = (static_cast<uint16_t>(payload[3]) << 8) |
                       static_cast<uint16_t>(payload[4]);
    relay.digest = saved_digest;

    uint16_t data_len = (static_cast<uint16_t>(payload[9]) << 8) |
                         static_cast<uint16_t>(payload[10]);
    if (data_len > PAYLOAD_LEN - RELAY_HEADER_LEN) {
        result.type = DecryptResult::Type::Error;
        return result;
    }

    relay.data.assign(payload.begin() + RELAY_HEADER_LEN,
                      payload.begin() + RELAY_HEADER_LEN + data_len);
    result.relay = std::move(relay);

    return result;
}



// Helper: Build and encrypt an outgoing relay cell
static Cell encrypt_relay_cell(
    CircuitCrypto& crypto, CircuitId circ_id,
    RelayCommand cmd, StreamId stream_id,
    const std::vector<uint8_t>& data)
{
    Cell cell(circ_id, CellCommand::RELAY);
    auto& payload = cell.payload;
    payload.fill(0);

    // Build relay header
    payload[0] = static_cast<uint8_t>(cmd);
    // recognized = 0 (already zero)
    payload[3] = static_cast<uint8_t>(stream_id >> 8);
    payload[4] = static_cast<uint8_t>(stream_id & 0xFF);
    // digest placeholder at [5..8] = 0 (already zero)

    uint16_t data_len = static_cast<uint16_t>(
        std::min(data.size(), static_cast<size_t>(PAYLOAD_LEN - RELAY_HEADER_LEN)));
    payload[9] = static_cast<uint8_t>(data_len >> 8);
    payload[10] = static_cast<uint8_t>(data_len & 0xFF);

    // Copy data
    if (data_len > 0) {
        std::copy_n(data.begin(), data_len,
                    payload.begin() + RELAY_HEADER_LEN);
    }

    // Compute backward digest
    auto digest = crypto.backward_digest.update_and_digest(
        std::span<const uint8_t>(payload.data(), PAYLOAD_LEN));
    if (digest) {
        payload[5] = static_cast<uint8_t>((*digest >> 24) & 0xFF);
        payload[6] = static_cast<uint8_t>((*digest >> 16) & 0xFF);
        payload[7] = static_cast<uint8_t>((*digest >> 8) & 0xFF);
        payload[8] = static_cast<uint8_t>(*digest & 0xFF);
    }

    // Encrypt with backward cipher (Kb)
    (void)crypto.backward_cipher.process(
        std::span<uint8_t>(payload.data(), PAYLOAD_LEN));

    return cell;
}

// --- Relay implementation details ---

struct Relay::Impl {
    boost::asio::io_context io_context;
    crypto::TlsContext tls_ctx;
    std::vector<uint8_t> tls_cert_der;
    std::unique_ptr<net::TlsAcceptor> or_acceptor;
    std::unique_ptr<transport::Obfs4Listener> obfs4_listener;
    std::jthread io_thread;
};

// --- Relay ---

Relay::Relay()
    : channel_manager_(std::make_shared<ChannelManager>()) {}

Relay::~Relay() {
    if (running_) {
        auto result = stop();
        (void)result;  // Best-effort shutdown
    }
}

Relay::Relay(Relay&&) noexcept = default;
Relay& Relay::operator=(Relay&&) noexcept = default;

std::expected<void, RelayError> Relay::start() {
    if (running_) {
        return std::unexpected(RelayError::AlreadyRunning);
    }

    if (!config_) {
        return std::unexpected(RelayError::ConfigError);
    }

    // Create behavior based on mode
    behavior_ = modes::create_behavior(config_->relay.mode, config_);
    if (!behavior_) {
        return std::unexpected(RelayError::InternalError);
    }

    // Load or generate identity keys
    if (!config_->relay.data_dir.empty()) {
        crypto::KeyStore key_store(config_->relay.data_dir);

        auto keys_result = key_store.load_or_generate();
        if (!keys_result) {
            LOG_ERROR("Failed to load/generate keys: {}",
                      crypto::key_store_error_message(keys_result.error()));
            return std::unexpected(RelayError::KeyGenerationFailed);
        }

        fingerprint_ = crypto::NodeId(keys_result->rsa_identity.rsa_public_key_der());

        auto fp_result = key_store.write_fingerprint(
            config_->relay.nickname, fingerprint_);
        if (!fp_result) {
            LOG_WARN("Failed to write fingerprint file: {}",
                     crypto::key_store_error_message(fp_result.error()));
        }

        LOG_INFO("Relay fingerprint: {}", fingerprint_.to_hex());

        keys_ = std::make_unique<crypto::RelayKeyPair>(std::move(*keys_result));
    }

    // Initialize networking
    impl_ = std::make_unique<Impl>();

    // Generate self-signed TLS certificate
    if (!keys_) {
        LOG_ERROR("No identity keys available for TLS certificate generation");
        return std::unexpected(RelayError::KeyGenerationFailed);
    }

    auto cert_result = crypto::TlsContext::generate_self_signed_cert(keys_->identity_key);
    if (!cert_result) {
        LOG_ERROR("Failed to generate self-signed TLS certificate");
        return std::unexpected(RelayError::TlsInitFailed);
    }

    auto& [cert_pem, key_pem] = *cert_result;

    // Convert PEM certificate to DER for CERTS cell
    {
        BIO* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
        X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (x509) {
            int der_len = i2d_X509(x509, nullptr);
            if (der_len > 0) {
                impl_->tls_cert_der.resize(static_cast<size_t>(der_len));
                unsigned char* p = impl_->tls_cert_der.data();
                i2d_X509(x509, &p);
            }
            X509_free(x509);
        }

        if (impl_->tls_cert_der.empty()) {
            LOG_ERROR("Failed to convert TLS certificate to DER format");
            return std::unexpected(RelayError::TlsInitFailed);
        }
    }

    // Initialize TLS context with the generated certificate
    auto tls_init = impl_->tls_ctx.init_server(cert_pem, key_pem);
    if (!tls_init) {
        LOG_ERROR("Failed to initialize TLS context");
        return std::unexpected(RelayError::TlsInitFailed);
    }

    LOG_INFO("TLS context initialized with self-signed certificate");

    // Create TLS acceptor for OR port
    impl_->or_acceptor = std::make_unique<net::TlsAcceptor>(
        impl_->io_context, impl_->tls_ctx);

    auto listen_result = impl_->or_acceptor->listen("0.0.0.0", config_->relay.or_port);
    if (!listen_result) {
        return std::unexpected(RelayError::BindFailed);
    }

    LOG_INFO("OR port listening on 0.0.0.0:{} with TLS", config_->relay.or_port);

    // Start TLS accept loop with real connection handler
    auto keys_ptr = keys_.get();
    auto tls_cert_der_ref = &impl_->tls_cert_der;
    auto channel_mgr = channel_manager_;
    auto or_port = config_->relay.or_port;

    impl_->or_acceptor->start_accept_loop(
        [keys_ptr, tls_cert_der_ref, channel_mgr, or_port](auto result) {
        if (!result) {
            LOG_WARN("OR: TLS accept/handshake failed");
            return;
        }

        auto tls_conn = *result;
        LOG_INFO("OR: accepted TLS connection from {}:{}",
                 tls_conn->remote_address(), tls_conn->remote_port());

        // Create channel with TLS connection
        auto channel = std::make_shared<Channel>();
        channel->set_connection(tls_conn);
        channel->set_tls_cert_der(*tls_cert_der_ref);

        // Run link handshake + cell loop in a dedicated thread
        std::thread([channel, keys_ptr, channel_mgr, or_port]() {
            LOG_INFO("OR: starting link protocol handshake");

            protocol::LinkProtocolHandler handler;
            auto hs_result = handler.handshake_as_responder(
                *channel,
                keys_ptr->identity_key,
                keys_ptr->identity_key.public_key(),
                keys_ptr->rsa_identity);

            if (!hs_result) {
                LOG_WARN("OR: link handshake failed: {}",
                         protocol::link_protocol_error_message(hs_result.error()));
                channel->close();
                return;
            }

            LOG_INFO("OR: link protocol handshake completed (v{})",
                     channel->link_version());
            channel->set_state(ChannelState::Open);

            // Circuit crypto state per circuit ID
            std::unordered_map<CircuitId, CircuitCrypto> circuits;

            // Next-hop connections for extended circuits (EXTEND2)
            std::unordered_map<CircuitId, std::unique_ptr<NextHopState>> next_hops;

            // Per-stream buffered HTTP request data
            std::unordered_map<StreamId, std::string> stream_bufs;

            // Per-stream TCP sockets for BEGIN-connected streams
            std::unordered_map<StreamId, int> stream_sockets;

            // Flow control windows
            int circuit_package_window = 1000;

            // Per-stream package window (starts at 500 per Tor spec)
            std::unordered_map<StreamId, int> stream_package_windows;

            // Pending responses paused by flow control
            struct PendingResponse {
                CircuitId circ_id;
                StreamId stream_id;
                std::string data;
                size_t offset;
            };
            std::deque<PendingResponse> pending_responses;

            // Pre-build bridge descriptor for directory requests
            std::string bridge_desc = build_bridge_descriptor(
                "TorBridge", "127.0.0.1", or_port,
                keys_ptr->rsa_identity,
                keys_ptr->identity_key,
                keys_ptr->identity_key.public_key(),
                keys_ptr->onion_key.public_key(),
                keys_ptr->onion_ed_key,
                keys_ptr->onion_ed_sign_bit,
                crypto::NodeId(keys_ptr->rsa_identity.rsa_public_key_der()));

            // Debug: write descriptor to file for inspection
            {
                std::ofstream desc_file("/tmp/tor-bridge-test/descriptor.txt",
                                        std::ios::trunc);
                if (desc_file) desc_file << bridge_desc;
            }
            LOG_INFO("Descriptor written to /tmp/tor-bridge-test/descriptor.txt ({} bytes)",
                     bridge_desc.size());

            // Cell processing loop
            while (channel->is_open()) {
                LOG_DEBUG("OR: waiting for next cell...");
                auto cell = channel->receive_any();
                if (!cell) {
                    LOG_INFO("OR: connection closed (error={})",
                             channel_error_message(cell.error()));
                    break;
                }

                auto& [is_var, fixed, var] = *cell;
                if (is_var) {
                    if (var.command != CellCommand::VPADDING) {
                        LOG_DEBUG("OR: variable cell cmd={}",
                                 cell_command_name(var.command));
                    }
                    continue;
                }

                if (fixed.command == CellCommand::PADDING) {
                    continue;
                }

                LOG_DEBUG("OR: cell cmd={} circ={}",
                         cell_command_name(fixed.command),
                         fixed.circuit_id);

                // --- CREATE_FAST handling ---
                if (fixed.command == CellCommand::CREATE_FAST) {
                    CircuitId circ_id = fixed.circuit_id;

                    // Extract X (20 bytes of client key material)
                    uint8_t x[20];
                    std::memcpy(x, fixed.payload.data(), 20);

                    // Generate Y (20 bytes of our key material)
                    uint8_t y[20];
                    RAND_bytes(y, 20);

                    // K0 = X || Y (40 bytes)
                    uint8_t k0[40];
                    std::memcpy(k0, x, 20);
                    std::memcpy(k0 + 20, y, 20);

                    // KDF-TOR: derive key material
                    // K = SHA1(K0|0x00) || SHA1(K0|0x01) || ...
                    // Layout: KH(20) | Df(20) | Db(20) | Kf(16) | Kb(16)
                    auto km = kdf_tor(k0, 40);
                    auto* KH = km.data();
                    auto* Df = km.data() + 20;
                    auto* Db = km.data() + 40;
                    auto* Kf = km.data() + 60;
                    auto* Kb = km.data() + 76;

                    // Debug: log key material
                    {
                        auto hex = [](const uint8_t* d, size_t n) {
                            std::string s;
                            for (size_t i = 0; i < n; ++i) {
                                char buf[3];
                                snprintf(buf, sizeof(buf), "%02x", d[i]);
                                s += buf;
                            }
                            return s;
                        };
                        LOG_DEBUG("CREATE_FAST: X={}", hex(x, 20));
                        LOG_DEBUG("CREATE_FAST: Y={}", hex(y, 20));
                        LOG_DEBUG("CREATE_FAST: KH={}", hex(KH, 20));
                        LOG_DEBUG("CREATE_FAST: Kf={}", hex(Kf, 16));
                        LOG_DEBUG("CREATE_FAST: Kb={}", hex(Kb, 16));
                    }

                    // Send CREATED_FAST: Y(20) || KH(20)
                    Cell created(circ_id, CellCommand::CREATED_FAST);
                    created.payload.fill(0);
                    std::memcpy(created.payload.data(), y, 20);
                    std::memcpy(created.payload.data() + 20, KH, 20);

                    // Hex dump of first 40 bytes of CREATED_FAST payload
                    {
                        auto hex = [](const uint8_t* d, size_t n) {
                            std::string s;
                            for (size_t i = 0; i < n; ++i) {
                                char buf[3];
                                snprintf(buf, sizeof(buf), "%02x", d[i]);
                                s += buf;
                            }
                            return s;
                        };
                        LOG_DEBUG("CREATED_FAST payload[0:40]={}",
                                 hex(created.payload.data(), 40));
                        LOG_DEBUG("CREATED_FAST circ_id={} cmd={}",
                                 created.circuit_id,
                                 static_cast<int>(created.command));
                    }

                    auto send_res = channel->send(created);
                    if (!send_res) {
                        LOG_WARN("OR: failed to send CREATED_FAST");
                        continue;
                    }

                    // Initialize circuit crypto
                    CircuitCrypto cc;
                    auto kf_init = cc.forward_cipher.init(
                        std::span<const uint8_t>(Kf, 16));
                    auto kb_init = cc.backward_cipher.init(
                        std::span<const uint8_t>(Kb, 16));
                    auto df_init = cc.forward_digest.init(
                        std::span<const uint8_t>(Df, 20));
                    auto db_init = cc.backward_digest.init(
                        std::span<const uint8_t>(Db, 20));

                    if (!kf_init || !kb_init || !df_init || !db_init) {
                        LOG_ERROR("OR: failed to initialize circuit crypto");
                        Cell destroy(circ_id, CellCommand::DESTROY);
                        destroy.payload[0] = static_cast<uint8_t>(
                            DestroyReason::INTERNAL);
                        (void)channel->send(destroy);
                        continue;
                    }

                    circuits.emplace(circ_id, std::move(cc));
                    LOG_INFO("OR: circuit {} created (CREATE_FAST)", circ_id);
                    continue;
                }

                // --- RELAY / RELAY_EARLY cell handling ---
                if (fixed.command == CellCommand::RELAY ||
                    fixed.command == CellCommand::RELAY_EARLY) {

                    auto it = circuits.find(fixed.circuit_id);
                    if (it == circuits.end()) {
                        LOG_WARN("OR: relay cell for unknown circuit {}",
                                 fixed.circuit_id);
                        continue;
                    }

                    CircuitId circ_id = fixed.circuit_id;
                    auto& cc = it->second;

                    // Decrypt one layer and decide: for us or forward?
                    auto dr = decrypt_relay_cell_or_forward(cc, fixed);

                    if (dr.type == DecryptResult::Type::Error) {
                        LOG_WARN("OR: failed to decrypt relay cell on circuit {}",
                                 circ_id);
                        continue;
                    }

                    if (dr.type == DecryptResult::Type::Forward) {
                        // Cell is not for us - forward to next hop
                        auto nh_it = next_hops.find(circ_id);
                        if (nh_it != next_hops.end() && nh_it->second->channel &&
                            nh_it->second->channel->is_open()) {
                            // Preserve RELAY_EARLY flag (required for EXTEND2 forwarding)
                            Cell fwd(circ_id, fixed.command);
                            fwd.payload = dr.decrypted_payload;
                            auto sr = nh_it->second->channel->send(fwd);
                            if (!sr) {
                                LOG_WARN("OR: failed to forward relay cell to next hop on circuit {}",
                                         circ_id);
                            } else {
                                LOG_INFO("OR: forwarded {} cell to next hop on circuit {}",
                                         cell_command_name(fixed.command), circ_id);
                            }
                        } else {
                            LOG_WARN("OR: no next hop for circuit {} to forward relay cell",
                                     circ_id);
                        }
                        continue;
                    }

                    // Cell is for us
                    auto& relay = dr.relay;

                    LOG_DEBUG("OR: relay cmd={} stream={} datalen={}",
                             static_cast<int>(relay->command),
                             relay->stream_id,
                             relay->data.size());

                    // Handle BEGIN_DIR
                    if (relay->command == RelayCommand::BEGIN_DIR) {
                        LOG_INFO("OR: BEGIN_DIR on stream {}",
                                 relay->stream_id);

                        // Send CONNECTED (empty body for directory)
                        auto resp = encrypt_relay_cell(
                            cc, circ_id, RelayCommand::CONNECTED,
                            relay->stream_id, {});
                        auto sr = channel->send(resp);
                        if (!sr) {
                            LOG_WARN("OR: failed to send CONNECTED");
                        }
                        stream_bufs[relay->stream_id] = "";
                        stream_package_windows[relay->stream_id] = 500;
                        continue;
                    }

                    // Handle DATA (directory stream or TCP-forwarded stream)
                    if (relay->command == RelayCommand::DATA) {
                        // Check if this is a TCP-forwarded stream first
                        auto sock_it = stream_sockets.find(relay->stream_id);
                        if (sock_it != stream_sockets.end()) {
                            send(sock_it->second, relay->data.data(),
                                 relay->data.size(), 0);
                            continue;
                        }

                        auto sit = stream_bufs.find(relay->stream_id);
                        if (sit == stream_bufs.end()) {
                            LOG_WARN("OR: DATA for unknown stream {}",
                                     relay->stream_id);
                            continue;
                        }

                        sit->second.append(
                            reinterpret_cast<const char*>(relay->data.data()),
                            relay->data.size());

                        LOG_DEBUG("OR: DATA stream={} total_buf={}",
                                 relay->stream_id, sit->second.size());

                        // Check if we have a complete HTTP request
                        if (sit->second.find("\r\n\r\n") != std::string::npos ||
                            sit->second.find("\n\n") != std::string::npos) {

                            LOG_INFO("OR: HTTP request: {}",
                                     sit->second.substr(0, 80));

                            // Build HTTP response
                            std::string body;
                            if (sit->second.find("/tor/server/authority") !=
                                    std::string::npos) {
                                body = bridge_desc;
                            } else {
                                // Proxy the request to a real dir authority
                                // Extract the path from GET /path HTTP/1.0
                                std::string path;
                                auto get_pos = sit->second.find("GET ");
                                if (get_pos != std::string::npos) {
                                    auto path_start = get_pos + 4;
                                    auto path_end = sit->second.find(' ', path_start);
                                    if (path_end != std::string::npos)
                                        path = sit->second.substr(path_start, path_end - path_start);
                                }

                                LOG_INFO("OR: proxying dir request: {} -> dir authority", path);

                                // Connect to dir authority (gabelmoo)
                                struct addrinfo hints_{}, *res_ = nullptr;
                                hints_.ai_family = AF_INET;
                                hints_.ai_socktype = SOCK_STREAM;
                                int dir_sock = -1;
                                if (getaddrinfo("131.188.40.189", "80", &hints_, &res_) == 0 && res_) {
                                    dir_sock = socket(res_->ai_family, res_->ai_socktype, res_->ai_protocol);
                                    if (dir_sock >= 0) {
                                        // Set timeout
                                        struct timeval tv;
                                        tv.tv_sec = 30;
                                        tv.tv_usec = 0;
                                        setsockopt(dir_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                                        setsockopt(dir_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                                        if (connect(dir_sock, res_->ai_addr, res_->ai_addrlen) < 0) {
                                            close(dir_sock);
                                            dir_sock = -1;
                                        }
                                    }
                                    freeaddrinfo(res_);
                                }

                                if (dir_sock >= 0) {
                                    // Send HTTP request (keep .z suffix for compressed responses)
                                    std::string dir_req = "GET " + path + " HTTP/1.0\r\nHost: 131.188.40.189\r\n\r\n";
                                    send(dir_sock, dir_req.data(), dir_req.size(), 0);

                                    // Read response
                                    std::string dir_resp;
                                    char rbuf[4096];
                                    ssize_t n;
                                    while ((n = recv(dir_sock, rbuf, sizeof(rbuf), 0)) > 0) {
                                        dir_resp.append(rbuf, static_cast<size_t>(n));
                                    }
                                    close(dir_sock);

                                    if (!dir_resp.empty()) {
                                        // Extract body from HTTP response
                                        // Find \r\n\r\n header/body separator
                                        auto hdr_end = dir_resp.find("\r\n\r\n");
                                        std::string proxy_headers = dir_resp.substr(0, hdr_end);
                                        std::string proxy_body;
                                        if (hdr_end != std::string::npos) {
                                            proxy_body = dir_resp.substr(hdr_end + 4);
                                        }
                                        LOG_INFO("OR: proxied dir response: {} bytes body (headers: {})",
                                                 proxy_body.size(), proxy_headers.substr(0, 80));

                                        // Check if authority response had Content-Encoding
                                        bool is_deflated = proxy_headers.find("Content-Encoding: deflate") != std::string::npos;

                                        // Build our own HTTP response wrapping the body
                                        std::string our_http = "HTTP/1.0 200 OK\r\n"
                                            "Content-Type: text/plain\r\n";
                                        if (is_deflated)
                                            our_http += "Content-Encoding: deflate\r\n";
                                        our_http += "Content-Length: " + std::to_string(proxy_body.size()) + "\r\n\r\n";

                                        // Combine our headers + authority body
                                        std::string full_resp = our_http + proxy_body;

                                        // Send response respecting flow control windows.
                                        // Circuit window starts at 1000 (decrement per cell, +100 per circuit SENDME).
                                        // Stream window starts at 500 (decrement per cell, +50 per stream SENDME).
                                        const size_t mx = PAYLOAD_LEN - RELAY_HEADER_LEN;
                                        size_t off = 0;
                                        StreamId sid = relay->stream_id;
                                        auto& stream_pkg = stream_package_windows[sid];

                                        while (off < full_resp.size() && channel->is_open()) {
                                            if (circuit_package_window <= 0 || stream_pkg <= 0) {
                                                // Window exhausted - save for later, SENDMEs will resume
                                                pending_responses.push_back({circ_id, sid, full_resp, off});
                                                LOG_DEBUG("OR: flow control pause at {}/{} bytes (circ_win={}, stream_win={})",
                                                         off, full_resp.size(), circuit_package_window, stream_pkg);
                                                break;
                                            }
                                            size_t chk = std::min(mx, full_resp.size() - off);
                                            std::vector<uint8_t> cd(
                                                full_resp.begin() + static_cast<std::ptrdiff_t>(off),
                                                full_resp.begin() + static_cast<std::ptrdiff_t>(off + chk));
                                            auto dc = encrypt_relay_cell(
                                                cc, circ_id, RelayCommand::DATA, sid, cd);
                                            auto sr = channel->send(dc);
                                            if (!sr) {
                                                LOG_WARN("OR: send failed during proxied response");
                                                break;
                                            }
                                            off += chk;
                                            circuit_package_window--;
                                            stream_pkg--;
                                        }
                                        if (off >= full_resp.size()) {
                                            // Fully sent
                                            auto end_cell = encrypt_relay_cell(
                                                cc, circ_id, RelayCommand::END, sid,
                                                {static_cast<uint8_t>(EndReason::DONE)});
                                            (void)channel->send(end_cell);
                                            stream_bufs.erase(sit);
                                            LOG_INFO("OR: sent proxied response ({} bytes, {} cells) to stream {}",
                                                     full_resp.size(), full_resp.size() / mx + 1, sid);
                                        }
                                        continue;
                                    }
                                }

                                // Fallback: 404
                                LOG_WARN("OR: dir proxy failed, sending 404 for: {}", path);
                                std::string http_resp =
                                    "HTTP/1.0 404 Not Found\r\n"
                                    "Content-Length: 0\r\n\r\n";
                                std::vector<uint8_t> resp_data(
                                    http_resp.begin(), http_resp.end());
                                auto resp = encrypt_relay_cell(
                                    cc, circ_id, RelayCommand::DATA,
                                    relay->stream_id, resp_data);
                                (void)channel->send(resp);

                                auto end_cell = encrypt_relay_cell(
                                    cc, circ_id, RelayCommand::END,
                                    relay->stream_id,
                                    {static_cast<uint8_t>(EndReason::DONE)});
                                (void)channel->send(end_cell);
                                stream_bufs.erase(sit);
                                continue;
                            }

                            std::string http_resp =
                                "HTTP/1.0 200 OK\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: " +
                                std::to_string(body.size()) +
                                "\r\n\r\n" + body;

                            // Send response in chunks (max 498 bytes per
                            // relay DATA cell = PAYLOAD_LEN - RELAY_HEADER_LEN)
                            const size_t max_data = PAYLOAD_LEN - RELAY_HEADER_LEN;
                            size_t offset = 0;
                            while (offset < http_resp.size()) {
                                size_t chunk = std::min(
                                    max_data, http_resp.size() - offset);
                                std::vector<uint8_t> chunk_data(
                                    http_resp.begin() +
                                        static_cast<std::ptrdiff_t>(offset),
                                    http_resp.begin() +
                                        static_cast<std::ptrdiff_t>(
                                            offset + chunk));

                                auto data_cell = encrypt_relay_cell(
                                    cc, circ_id, RelayCommand::DATA,
                                    relay->stream_id, chunk_data);
                                auto sr = channel->send(data_cell);
                                if (!sr) {
                                    LOG_WARN("OR: failed to send DATA chunk");
                                    break;
                                }
                                offset += chunk;
                                circuit_package_window--;
                                stream_package_windows[relay->stream_id]--;
                            }

                            LOG_INFO("OR: sent descriptor ({} bytes) to stream {}",
                                     http_resp.size(), relay->stream_id);

                            // Send END
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::END,
                                relay->stream_id,
                                {static_cast<uint8_t>(EndReason::DONE)});
                            (void)channel->send(end_cell);

                            stream_bufs.erase(sit);
                        }
                        continue;
                    }

                    // Handle BEGIN (TCP connect through bridge)
                    if (relay->command == RelayCommand::BEGIN) {
                        // Parse address:port from data (null-terminated)
                        std::string addr_port(
                            reinterpret_cast<const char*>(relay->data.data()),
                            relay->data.size());
                        // Remove null terminator and flags
                        auto null_pos = addr_port.find('\0');
                        if (null_pos != std::string::npos)
                            addr_port = addr_port.substr(0, null_pos);

                        auto colon_pos = addr_port.rfind(':');
                        if (colon_pos == std::string::npos) {
                            LOG_WARN("OR: BEGIN with invalid address: {}",
                                     addr_port);
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::END,
                                relay->stream_id,
                                {static_cast<uint8_t>(EndReason::RESOLVEFAILED)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        std::string host = addr_port.substr(0, colon_pos);
                        int port = std::stoi(addr_port.substr(colon_pos + 1));
                        LOG_INFO("OR: BEGIN stream {} -> {}:{}",
                                 relay->stream_id, host, port);

                        // DNS resolve + TCP connect
                        StreamId stream_id = relay->stream_id;
                        int sock = -1;
                        struct addrinfo hints{}, *res = nullptr;
                        hints.ai_family = AF_UNSPEC;
                        hints.ai_socktype = SOCK_STREAM;
                        std::string port_str = std::to_string(port);
                        int gai_err = getaddrinfo(host.c_str(), port_str.c_str(),
                                                   &hints, &res);
                        if (gai_err == 0 && res) {
                            sock = socket(res->ai_family, res->ai_socktype,
                                          res->ai_protocol);
                            if (sock >= 0) {
                                if (connect(sock, res->ai_addr,
                                            res->ai_addrlen) < 0) {
                                    close(sock);
                                    sock = -1;
                                }
                            }
                            freeaddrinfo(res);
                        }

                        if (sock < 0) {
                            LOG_WARN("OR: BEGIN connect failed: {}:{}", host, port);
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::END,
                                stream_id,
                                {static_cast<uint8_t>(EndReason::CONNECTREFUSED)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        // Send CONNECTED: 4-byte IP + 4-byte TTL
                        std::vector<uint8_t> connected_body(8, 0);
                        connected_body[0] = 127; connected_body[1] = 0;
                        connected_body[2] = 0; connected_body[3] = 1;
                        connected_body[4] = 0; connected_body[5] = 0;
                        connected_body[6] = 0x0E; connected_body[7] = 0x10; // TTL=3600

                        auto conn_resp = encrypt_relay_cell(
                            cc, circ_id, RelayCommand::CONNECTED,
                            stream_id, connected_body);
                        (void)channel->send(conn_resp);

                        // Store socket for data forwarding
                        stream_sockets[stream_id] = sock;

                        // Start reader thread for this stream
                        auto chan_weak = std::weak_ptr<Channel>(channel);
                        std::thread([chan_weak, &cc, circ_id, stream_id,
                                     sock, &stream_sockets]() {
                            uint8_t buf[498];
                            while (true) {
                                ssize_t n = recv(sock, buf, sizeof(buf), 0);
                                if (n <= 0) break;
                                auto ch = chan_weak.lock();
                                if (!ch || !ch->is_open()) break;
                                std::vector<uint8_t> data(buf, buf + n);
                                auto cell = encrypt_relay_cell(
                                    cc, circ_id, RelayCommand::DATA,
                                    stream_id, data);
                                auto sr = ch->send(cell);
                                if (!sr) break;
                            }
                            close(sock);
                            auto ch = chan_weak.lock();
                            if (ch && ch->is_open()) {
                                auto end = encrypt_relay_cell(
                                    cc, circ_id, RelayCommand::END,
                                    stream_id,
                                    {static_cast<uint8_t>(EndReason::DONE)});
                                (void)ch->send(end);
                            }
                            stream_sockets.erase(stream_id);
                        }).detach();

                        continue;
                    }

                    // Handle END
                    if (relay->command == RelayCommand::END) {
                        LOG_INFO("OR: END on stream {}", relay->stream_id);
                        stream_bufs.erase(relay->stream_id);
                        stream_package_windows.erase(relay->stream_id);
                        // Remove any pending responses for this stream
                        pending_responses.erase(
                            std::remove_if(pending_responses.begin(), pending_responses.end(),
                                [&](const PendingResponse& pr) {
                                    return pr.stream_id == relay->stream_id;
                                }),
                            pending_responses.end());
                        // Close any associated socket
                        auto sock_it = stream_sockets.find(relay->stream_id);
                        if (sock_it != stream_sockets.end()) {
                            close(sock_it->second);
                            stream_sockets.erase(sock_it);
                        }
                        continue;
                    }

                    // Handle SENDME (flow control - acknowledge)
                    if (relay->command == RelayCommand::SENDME) {
                        if (relay->stream_id == 0) {
                            // Circuit-level SENDME
                            circuit_package_window += 100;
                            LOG_DEBUG("OR: circuit SENDME on {}, window now {}",
                                     circ_id, circuit_package_window);
                        } else {
                            // Stream-level SENDME
                            auto sw_it = stream_package_windows.find(relay->stream_id);
                            if (sw_it != stream_package_windows.end()) {
                                sw_it->second += 50;
                            }
                            LOG_DEBUG("OR: stream SENDME on stream {}, window now {}",
                                     relay->stream_id,
                                     sw_it != stream_package_windows.end() ? sw_it->second : -1);
                        }

                        // Resume any pending responses that now have window space
                        for (auto pr_it = pending_responses.begin();
                             pr_it != pending_responses.end(); ) {
                            auto pr_circ_it = circuits.find(pr_it->circ_id);
                            if (pr_circ_it == circuits.end()) {
                                pr_it = pending_responses.erase(pr_it);
                                continue;
                            }
                            auto& pr_cc = pr_circ_it->second;
                            auto pr_sw = stream_package_windows.find(pr_it->stream_id);
                            if (pr_sw == stream_package_windows.end()) {
                                pr_it = pending_responses.erase(pr_it);
                                continue;
                            }

                            if (circuit_package_window <= 0 || pr_sw->second <= 0) {
                                ++pr_it;
                                continue;
                            }

                            // Continue sending this response
                            const size_t mx = PAYLOAD_LEN - RELAY_HEADER_LEN;
                            bool send_ok = true;
                            while (pr_it->offset < pr_it->data.size() &&
                                   channel->is_open() &&
                                   circuit_package_window > 0 &&
                                   pr_sw->second > 0) {
                                size_t chk = std::min(mx,
                                    pr_it->data.size() - pr_it->offset);
                                std::vector<uint8_t> cd(
                                    pr_it->data.begin() + static_cast<std::ptrdiff_t>(pr_it->offset),
                                    pr_it->data.begin() + static_cast<std::ptrdiff_t>(pr_it->offset + chk));
                                auto dc = encrypt_relay_cell(
                                    pr_cc, pr_it->circ_id, RelayCommand::DATA,
                                    pr_it->stream_id, cd);
                                auto sr = channel->send(dc);
                                if (!sr) { send_ok = false; break; }
                                pr_it->offset += chk;
                                circuit_package_window--;
                                pr_sw->second--;
                            }

                            if (!send_ok || pr_it->offset >= pr_it->data.size()) {
                                if (pr_it->offset >= pr_it->data.size()) {
                                    // Fully sent - send END
                                    auto end_cell = encrypt_relay_cell(
                                        pr_cc, pr_it->circ_id, RelayCommand::END,
                                        pr_it->stream_id,
                                        {static_cast<uint8_t>(EndReason::DONE)});
                                    (void)channel->send(end_cell);
                                    stream_bufs.erase(pr_it->stream_id);
                                    LOG_INFO("OR: completed response ({} bytes) to stream {}",
                                             pr_it->data.size(), pr_it->stream_id);
                                }
                                pr_it = pending_responses.erase(pr_it);
                            } else {
                                LOG_DEBUG("OR: response still pending for stream {} ({}/{})",
                                         pr_it->stream_id, pr_it->offset, pr_it->data.size());
                                ++pr_it;
                            }
                        }
                        continue;
                    }

                    // Handle EXTEND2 (circuit extension through this relay)
                    if (relay->command == RelayCommand::EXTEND2) {
                        LOG_INFO("OR: EXTEND2 on circuit {}", circ_id);

                        auto& data = relay->data;
                        size_t pos = 0;

                        // Parse link specifiers
                        if (pos >= data.size()) {
                            LOG_WARN("OR: EXTEND2 too short");
                            continue;
                        }
                        uint8_t nspec = data[pos++];
                        std::string target_ip;
                        uint16_t target_port = 0;

                        for (uint8_t i = 0; i < nspec && pos + 2 <= data.size(); ++i) {
                            uint8_t lstype = data[pos++];
                            uint8_t lslen = data[pos++];
                            if (pos + lslen > data.size()) break;

                            if (lstype == 0 && lslen == 6) {
                                // IPv4: 4 bytes IP + 2 bytes port
                                char ip_buf[INET_ADDRSTRLEN];
                                struct in_addr addr;
                                memcpy(&addr, &data[pos], 4);
                                inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf));
                                target_ip = ip_buf;
                                target_port = (static_cast<uint16_t>(data[pos+4]) << 8) |
                                               static_cast<uint16_t>(data[pos+5]);
                            } else if (lstype == 1 && lslen == 18) {
                                // IPv6: 16 bytes IP + 2 bytes port
                                char ip_buf[INET6_ADDRSTRLEN];
                                struct in6_addr addr;
                                memcpy(&addr, &data[pos], 16);
                                inet_ntop(AF_INET6, &addr, ip_buf, sizeof(ip_buf));
                                target_ip = ip_buf;
                                target_port = (static_cast<uint16_t>(data[pos+16]) << 8) |
                                               static_cast<uint16_t>(data[pos+17]);
                            }
                            pos += lslen;
                        }

                        if (target_ip.empty() || target_port == 0) {
                            LOG_WARN("OR: EXTEND2 no usable address found");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        // Parse CREATE2 handshake data
                        if (pos + 4 > data.size()) {
                            LOG_WARN("OR: EXTEND2 missing handshake data");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                            (void)channel->send(end_cell);
                            continue;
                        }
                        uint16_t htype = (static_cast<uint16_t>(data[pos]) << 8) |
                                          static_cast<uint16_t>(data[pos+1]);
                        uint16_t hlen = (static_cast<uint16_t>(data[pos+2]) << 8) |
                                         static_cast<uint16_t>(data[pos+3]);
                        pos += 4;
                        if (pos + hlen > data.size()) {
                            LOG_WARN("OR: EXTEND2 handshake data truncated");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                            (void)channel->send(end_cell);
                            continue;
                        }
                        std::vector<uint8_t> hdata(data.begin() + pos,
                                                   data.begin() + pos + hlen);

                        LOG_INFO("OR: EXTEND2 target={}:{} htype={} hlen={}",
                                 target_ip, target_port, htype, hlen);

                        // Connect to target relay via TLS
                        boost::asio::io_context ext_io;
                        crypto::TlsContext ext_tls;
                        auto ext_tls_init = ext_tls.init_client();
                        if (!ext_tls_init) {
                            LOG_WARN("OR: EXTEND2 TLS client init failed");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::CONNECTFAILED)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        auto ext_conn = std::make_shared<net::TlsConnection>(ext_io, ext_tls);
                        ext_conn->set_connect_timeout(std::chrono::milliseconds(10000));
                        auto conn_result = ext_conn->connect(target_ip, target_port);
                        if (!conn_result) {
                            LOG_WARN("OR: EXTEND2 TCP connect to {}:{} failed",
                                     target_ip, target_port);
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::CONNECTFAILED)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        auto tls_result = ext_conn->tls_handshake(true);
                        if (!tls_result) {
                            LOG_WARN("OR: EXTEND2 TLS handshake to {}:{} failed",
                                     target_ip, target_port);
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::CONNECTFAILED)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        // Create channel for next hop
                        auto nh_channel = std::make_shared<Channel>();
                        nh_channel->set_connection(ext_conn);

                        // Tor link protocol as initiator:
                        // 1. Send VERSIONS (using 2-byte circuit IDs initially)
                        std::vector<uint8_t> versions_payload = {0, 3, 0, 4, 0, 5};
                        VariableCell versions_cell(0, CellCommand::VERSIONS,
                                                   versions_payload);
                        auto vs_result = nh_channel->send(versions_cell);
                        if (!vs_result) {
                            LOG_WARN("OR: EXTEND2 failed to send VERSIONS");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        // 2. Receive VERSIONS from target
                        auto nh_versions = nh_channel->receive_variable();
                        if (!nh_versions) {
                            LOG_WARN("OR: EXTEND2 failed to receive VERSIONS from target");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        // Negotiate v4+
                        nh_channel->set_link_version(4);

                        // 3. Receive CERTS, AUTH_CHALLENGE, NETINFO (consume them)
                        for (int rx = 0; rx < 3; ++rx) {
                            auto any = nh_channel->receive_any();
                            if (!any) {
                                LOG_WARN("OR: EXTEND2 failed to receive cell {} from target", rx);
                                break;
                            }
                        }

                        // 4. Send NETINFO
                        {
                            Cell netinfo(0, CellCommand::NETINFO);
                            netinfo.payload.fill(0);
                            // TIME (4 bytes) - current time
                            auto now = std::chrono::system_clock::now();
                            auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                now.time_since_epoch()).count();
                            netinfo.payload[0] = static_cast<uint8_t>((epoch >> 24) & 0xFF);
                            netinfo.payload[1] = static_cast<uint8_t>((epoch >> 16) & 0xFF);
                            netinfo.payload[2] = static_cast<uint8_t>((epoch >> 8) & 0xFF);
                            netinfo.payload[3] = static_cast<uint8_t>(epoch & 0xFF);
                            // OTHERADDR: type=4(IPv4), len=4, addr
                            netinfo.payload[4] = 4; // IPv4
                            netinfo.payload[5] = 4; // length
                            struct in_addr target_addr;
                            inet_pton(AF_INET, target_ip.c_str(), &target_addr);
                            memcpy(&netinfo.payload[6], &target_addr, 4);
                            // NUMADDR = 1
                            netinfo.payload[10] = 1;
                            // MYADDR: type=4, len=4, 127.0.0.1
                            netinfo.payload[11] = 4;
                            netinfo.payload[12] = 4;
                            netinfo.payload[13] = 127;
                            netinfo.payload[16] = 1;
                            auto ni_result = nh_channel->send(netinfo);
                            if (!ni_result) {
                                LOG_WARN("OR: EXTEND2 failed to send NETINFO");
                            }
                        }

                        nh_channel->set_state(ChannelState::Open);

                        // 5. Send CREATE2 to target
                        {
                            Cell create2(circ_id, CellCommand::CREATE2);
                            create2.payload.fill(0);
                            create2.payload[0] = static_cast<uint8_t>(htype >> 8);
                            create2.payload[1] = static_cast<uint8_t>(htype & 0xFF);
                            create2.payload[2] = static_cast<uint8_t>(hlen >> 8);
                            create2.payload[3] = static_cast<uint8_t>(hlen & 0xFF);
                            std::memcpy(create2.payload.data() + 4, hdata.data(),
                                        hdata.size());
                            auto c2_result = nh_channel->send(create2);
                            if (!c2_result) {
                                LOG_WARN("OR: EXTEND2 failed to send CREATE2 to target");
                                auto end_cell = encrypt_relay_cell(
                                    cc, circ_id, RelayCommand::TRUNCATED, 0,
                                    {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                                (void)channel->send(end_cell);
                                continue;
                            }
                        }

                        // 6. Receive CREATED2 from target
                        auto created2_cell = nh_channel->receive();
                        if (!created2_cell ||
                            created2_cell->command != CellCommand::CREATED2) {
                            LOG_WARN("OR: EXTEND2 failed to receive CREATED2 from target");
                            auto end_cell = encrypt_relay_cell(
                                cc, circ_id, RelayCommand::TRUNCATED, 0,
                                {static_cast<uint8_t>(DestroyReason::INTERNAL)});
                            (void)channel->send(end_cell);
                            continue;
                        }

                        // 7. Send EXTENDED2 back to client
                        // EXTENDED2 payload: HLEN(2) | HDATA(HLEN)
                        // Extract HLEN from CREATED2
                        uint16_t resp_hlen =
                            (static_cast<uint16_t>(created2_cell->payload[0]) << 8) |
                             static_cast<uint16_t>(created2_cell->payload[1]);
                        std::vector<uint8_t> ext2_data;
                        ext2_data.push_back(created2_cell->payload[0]);
                        ext2_data.push_back(created2_cell->payload[1]);
                        ext2_data.insert(ext2_data.end(),
                                         created2_cell->payload.begin() + 2,
                                         created2_cell->payload.begin() + 2 + resp_hlen);

                        auto ext2_cell = encrypt_relay_cell(
                            cc, circ_id, RelayCommand::EXTENDED2, 0, ext2_data);
                        auto ext2_result = channel->send(ext2_cell);
                        if (!ext2_result) {
                            LOG_WARN("OR: EXTEND2 failed to send EXTENDED2 to client");
                            continue;
                        }

                        LOG_INFO("OR: EXTEND2 success on circuit {} → {}:{}",
                                 circ_id, target_ip, target_port);

                        // 8. Start backward relay cell reader for this next hop
                        auto nh = std::make_unique<NextHopState>();
                        nh->channel = nh_channel;
                        auto nh_running = &nh->running;
                        auto client_channel = channel;
                        auto circ_id_copy = circ_id;

                        // Store circuits ref for backward encryption
                        auto circuits_ptr = &circuits;

                        nh->reader_thread = std::thread(
                            [nh_channel, client_channel, circ_id_copy,
                             nh_running, circuits_ptr]() {
                            while (nh_running->load() &&
                                   nh_channel->is_open() &&
                                   client_channel->is_open()) {
                                auto cell = nh_channel->receive();
                                if (!cell) break;

                                if (cell->command == CellCommand::DESTROY) {
                                    LOG_INFO("OR: next hop destroyed circuit {}",
                                             circ_id_copy);
                                    break;
                                }

                                if (cell->command == CellCommand::RELAY) {
                                    // Backward direction: encrypt with Kb
                                    auto c_it = circuits_ptr->find(circ_id_copy);
                                    if (c_it == circuits_ptr->end()) break;

                                    Cell back_cell(circ_id_copy, CellCommand::RELAY);
                                    back_cell.payload = cell->payload;
                                    // Encrypt payload with backward cipher (Kb)
                                    auto enc = c_it->second.backward_cipher.process(
                                        std::span<uint8_t>(back_cell.payload.data(),
                                                           PAYLOAD_LEN));
                                    if (!enc) break;

                                    auto sr = client_channel->send(back_cell);
                                    if (!sr) break;
                                }
                            }
                        });

                        next_hops.emplace(circ_id, std::move(nh));
                        continue;
                    }

                    LOG_DEBUG("OR: unhandled relay cmd={} stream={}",
                             static_cast<int>(relay->command),
                             relay->stream_id);
                    continue;
                }

                // --- DESTROY ---
                if (fixed.command == CellCommand::DESTROY) {
                    LOG_INFO("OR: DESTROY circuit {}", fixed.circuit_id);
                    next_hops.erase(fixed.circuit_id);  // Clean up next hop
                    circuits.erase(fixed.circuit_id);
                    // Clean up pending responses for this circuit
                    pending_responses.erase(
                        std::remove_if(pending_responses.begin(), pending_responses.end(),
                            [&](const PendingResponse& pr) {
                                return pr.circ_id == fixed.circuit_id;
                            }),
                        pending_responses.end());
                    continue;
                }

                // --- CREATE2 (ntor handshake) ---
                if (fixed.command == CellCommand::CREATE2) {
                    CircuitId circ_id = fixed.circuit_id;

                    // Parse CREATE2: HTYPE(2) | HLEN(2) | HDATA(HLEN)
                    uint16_t htype = (static_cast<uint16_t>(fixed.payload[0]) << 8) |
                                      static_cast<uint16_t>(fixed.payload[1]);
                    uint16_t hlen = (static_cast<uint16_t>(fixed.payload[2]) << 8) |
                                     static_cast<uint16_t>(fixed.payload[3]);

                    if (htype != 0x0002) { // ntor
                        LOG_WARN("OR: CREATE2 unsupported handshake type {}", htype);
                        Cell destroy(circ_id, CellCommand::DESTROY);
                        destroy.payload[0] = static_cast<uint8_t>(DestroyReason::INTERNAL);
                        (void)channel->send(destroy);
                        continue;
                    }

                    if (hlen != crypto::NTOR_CLIENT_HANDSHAKE_LEN) {
                        LOG_WARN("OR: CREATE2 invalid ntor length {}", hlen);
                        Cell destroy(circ_id, CellCommand::DESTROY);
                        destroy.payload[0] = static_cast<uint8_t>(DestroyReason::INTERNAL);
                        (void)channel->send(destroy);
                        continue;
                    }

                    // Run ntor server handshake
                    crypto::NtorServerHandshake ntor_hs;
                    auto ntor_result = ntor_hs.process_request(
                        std::span<const uint8_t>(fixed.payload.data() + 4, hlen),
                        crypto::NodeId(keys_ptr->rsa_identity.rsa_public_key_der()),
                        keys_ptr->onion_key);
                    if (!ntor_result) {
                        LOG_WARN("OR: ntor handshake failed: {}",
                                 crypto::ntor_error_message(ntor_result.error()));
                        Cell destroy(circ_id, CellCommand::DESTROY);
                        destroy.payload[0] = static_cast<uint8_t>(DestroyReason::INTERNAL);
                        (void)channel->send(destroy);
                        continue;
                    }

                    auto& [ntor_response, ntor_keys] = *ntor_result;

                    // Send CREATED2: HLEN(2) | HDATA(64)
                    Cell created(circ_id, CellCommand::CREATED2);
                    created.payload.fill(0);
                    created.payload[0] = static_cast<uint8_t>(ntor_response.size() >> 8);
                    created.payload[1] = static_cast<uint8_t>(ntor_response.size() & 0xFF);
                    std::memcpy(created.payload.data() + 2, ntor_response.data(),
                                ntor_response.size());

                    auto send_res = channel->send(created);
                    if (!send_res) {
                        LOG_WARN("OR: failed to send CREATED2");
                        continue;
                    }

                    // Initialize circuit crypto from ntor key material
                    CircuitCrypto cc;
                    auto kf_init = cc.forward_cipher.init(
                        std::span<const uint8_t>(ntor_keys.forward_key));
                    auto kb_init = cc.backward_cipher.init(
                        std::span<const uint8_t>(ntor_keys.backward_key));
                    auto df_init = cc.forward_digest.init(
                        std::span<const uint8_t>(ntor_keys.forward_digest));
                    auto db_init = cc.backward_digest.init(
                        std::span<const uint8_t>(ntor_keys.backward_digest));

                    if (!kf_init || !kb_init || !df_init || !db_init) {
                        LOG_ERROR("OR: failed to initialize ntor circuit crypto");
                        Cell destroy(circ_id, CellCommand::DESTROY);
                        destroy.payload[0] = static_cast<uint8_t>(DestroyReason::INTERNAL);
                        (void)channel->send(destroy);
                        continue;
                    }

                    circuits.emplace(circ_id, std::move(cc));
                    LOG_INFO("OR: circuit {} created (CREATE2/ntor)", circ_id);
                    continue;
                }

                LOG_DEBUG("OR: unhandled cell cmd={}",
                         cell_command_name(fixed.command));
            }

            channel->close();
            LOG_INFO("OR: connection handler thread exiting");
        }).detach();
    });

    // Start obfs4 listener for bridge mode with transport enabled
    if (config_->relay.mode == modes::RelayMode::Bridge &&
        config_->bridge.transport == "obfs4" && keys_) {

        auto iat = static_cast<transport::IatMode>(config_->bridge.iat_mode);
        impl_->obfs4_listener = std::make_unique<transport::Obfs4Listener>(
            impl_->io_context, fingerprint_, keys_->onion_key, iat);
        impl_->obfs4_listener->set_or_port(config_->relay.or_port);

        auto obfs4_result = impl_->obfs4_listener->start(
            "0.0.0.0", config_->bridge.transport_port);
        if (!obfs4_result) {
            LOG_ERROR("Failed to start obfs4 listener on port {}",
                      config_->bridge.transport_port);
            // Non-fatal: bridge still works on OR port without obfs4
        } else {
            LOG_INFO("obfs4 transport listening on port {}",
                     config_->bridge.transport_port);

            // Set obfs4 cert on bridge behavior
            auto* bridge = dynamic_cast<modes::BridgeRelay*>(behavior_.get());
            if (bridge) {
                bridge->set_obfs4_cert(impl_->obfs4_listener->cert());
            }
        }
    }

    // Log bridge line for bridge mode
    if (config_->relay.mode == modes::RelayMode::Bridge) {
        auto* bridge = dynamic_cast<modes::BridgeRelay*>(behavior_.get());
        if (bridge) {
            LOG_INFO("Bridge line: {}", bridge->bridge_line());
        }
    }

    impl_->io_thread = std::jthread([this](std::stop_token) {
        auto work_guard = boost::asio::make_work_guard(impl_->io_context);
        impl_->io_context.run();
    });

    running_ = true;
    return {};
}

std::expected<void, RelayError> Relay::stop() {
    if (!running_) {
        return std::unexpected(RelayError::NotRunning);
    }

    LOG_INFO("Shutdown requested, stopping relay...");

    // Stop obfs4 listener and acceptor
    if (impl_) {
        if (impl_->obfs4_listener) {
            impl_->obfs4_listener->stop();
        }
        if (impl_->or_acceptor) {
            impl_->or_acceptor->close();
        }
        impl_->io_context.stop();
        if (impl_->io_thread.joinable()) {
            impl_->io_thread.join();
        }
    }

    // Close all channels
    channel_manager_->close_all();

    running_ = false;
    LOG_INFO("Relay stopped");
    return {};
}

std::expected<void, RelayError>
Relay::switch_mode(modes::RelayMode new_mode) {
    if (!running_) {
        return std::unexpected(RelayError::NotRunning);
    }

    auto new_behavior = modes::create_behavior(new_mode, config_);
    if (!new_behavior) {
        return std::unexpected(RelayError::ModeSwitchFailed);
    }

    auto validate_result = new_behavior->validate_config();
    if (!validate_result) {
        return std::unexpected(RelayError::ConfigError);
    }

    behavior_ = std::move(new_behavior);
    return {};
}

modes::RelayMode Relay::mode() const {
    if (behavior_) {
        return behavior_->mode();
    }
    return modes::RelayMode::Middle;
}

// --- RelayBuilder ---

RelayBuilder& RelayBuilder::config(util::Config& cfg) {
    config_ = &cfg;
    return *this;
}

std::expected<std::unique_ptr<Relay>, RelayError> RelayBuilder::build() {
    if (!config_) {
        return std::unexpected(RelayError::ConfigError);
    }

    auto relay = std::make_unique<Relay>();
    relay->config_ = config_;

    return relay;
}

// --- Utility ---

std::string relay_error_message(RelayError err) {
    switch (err) {
        case RelayError::ConfigError:          return "Configuration error";
        case RelayError::KeyGenerationFailed:  return "Key generation failed";
        case RelayError::BindFailed:           return "Failed to bind to port";
        case RelayError::TlsInitFailed:        return "TLS initialization failed";
        case RelayError::StartFailed:          return "Failed to start relay";
        case RelayError::StopFailed:           return "Failed to stop relay";
        case RelayError::AlreadyRunning:       return "Relay is already running";
        case RelayError::NotRunning:           return "Relay is not running";
        case RelayError::ModeSwitchFailed:     return "Failed to switch relay mode";
        case RelayError::DirectoryError:       return "Directory operation failed";
        case RelayError::InternalError:        return "Internal error";
        default:                               return "Unknown relay error";
    }
}

}  // namespace tor::core
