#include <catch2/catch_test_macros.hpp>
#include "tor/transport/obfs4.hpp"
#include "tor/transport/obfs4_listener.hpp"
#include "tor/crypto/keys.hpp"
#include "tor/crypto/hash.hpp"
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/common/ntor.hpp"
#include <cstring>

using namespace tor::transport;
using namespace tor::crypto;

// Simulated client handshake for testing.
// Uses obfs4_cpp's Elligator2 keypair and correct HMAC key order:
//   key = identity_pub[32] || node_id[20]
static std::vector<uint8_t> build_client_handshake(
    const NodeId& node_id,
    const Curve25519PublicKey& server_pubkey,
    const obfs4::crypto::Keypair& client_kp) {

    std::vector<uint8_t> handshake;

    // 1. Client representative (32 bytes)
    if (!client_kp.representative) return {};
    handshake.insert(handshake.end(),
                     client_kp.representative->begin(),
                     client_kp.representative->end());

    // 2. Build HMAC key: identity_pub[32] || node_id[20] (correct order)
    std::vector<uint8_t> hmac_key;
    hmac_key.reserve(32 + 20);
    hmac_key.insert(hmac_key.end(),
                    server_pubkey.data().begin(), server_pubkey.data().end());
    hmac_key.insert(hmac_key.end(),
                    node_id.data().begin(), node_id.data().end());

    // 3. HMAC mark: HMAC-SHA256(key, representative) truncated to 16 bytes
    auto mark_hmac = hmac_sha256(hmac_key, *client_kp.representative);
    if (!mark_hmac) return {};
    handshake.insert(handshake.end(),
                     mark_hmac->begin(),
                     mark_hmac->begin() + OBFS4_MARK_LEN);

    // 4. Epoch-hour MAC: HMAC-SHA256(key, representative || mark || epoch_str)
    auto hour_str = std::to_string(epoch_hour());
    std::vector<uint8_t> mac_input(handshake.begin(), handshake.end());
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(hour_str.data()),
                     reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

    auto epoch_mac = hmac_sha256(hmac_key, mac_input);
    if (!epoch_mac) return {};
    handshake.insert(handshake.end(), epoch_mac->begin(), epoch_mac->end());

    return handshake;
}

TEST_CASE("End-to-end obfs4 handshake", "[integration][transport][obfs4]") {
    // Generate server keys
    auto server_keys = RelayKeyPair::generate();
    REQUIRE(server_keys.has_value());

    NodeId node_id(server_keys->identity_key.public_key());

    // Generate representable client keypair using obfs4_cpp
    auto client_kp = obfs4::crypto::elligator2::generate_representable_keypair();
    REQUIRE(client_kp.representative.has_value());

    // Create server handshake handler
    Obfs4ServerHandshake server_hs(node_id, server_keys->onion_key);

    // Build client handshake message
    auto client_hello = build_client_handshake(
        node_id, server_keys->onion_key.public_key(), client_kp);
    REQUIRE_FALSE(client_hello.empty());

    // Feed client handshake to server
    auto result = server_hs.consume(client_hello);
    REQUIRE(result.has_value());

    // Server should have completed handshake
    REQUIRE(server_hs.state() == Obfs4ServerHandshake::State::Completed);

    // Generate server hello
    auto server_hello = server_hs.generate_server_hello();
    REQUIRE(server_hello.has_value());
    REQUIRE(server_hello->size() >= OBFS4_MIN_SERVER_HANDSHAKE);

    // Session keys should be non-zero
    auto& keys = server_hs.session_keys();
    bool send_key_zero = true;
    for (auto b : keys.send_key) if (b != 0) { send_key_zero = false; break; }
    REQUIRE_FALSE(send_key_zero);
}

TEST_CASE("End-to-end obfs4 framing after handshake", "[integration][transport][obfs4]") {
    // Simulate a completed handshake with known keys
    std::array<uint8_t, 32> send_key{}, recv_key{};
    std::array<uint8_t, 24> send_nonce{}, recv_nonce{};
    std::array<uint8_t, 24> send_drbg{}, recv_drbg{};
    for (int i = 0; i < 32; ++i) {
        send_key[i] = static_cast<uint8_t>(i);
        recv_key[i] = static_cast<uint8_t>(i + 32);
    }
    send_drbg[0] = 0x01;
    recv_drbg[0] = 0x02;

    // Server sends with send_key, client receives with send_key (matching)
    Obfs4Framing server_framing, client_framing;
    server_framing.init_send(send_key, send_nonce, send_drbg);
    client_framing.init_recv(send_key, send_nonce, send_drbg);

    // Client sends with recv_key, server receives with recv_key (matching)
    client_framing.init_send(recv_key, recv_nonce, recv_drbg);
    server_framing.init_recv(recv_key, recv_nonce, recv_drbg);

    // Server -> Client
    std::vector<uint8_t> server_msg = {'S', 'e', 'r', 'v', 'e', 'r'};
    auto encoded = server_framing.encode(server_msg);
    auto decoded = client_framing.decode(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->frames.size() == 1);
    REQUIRE(decoded->frames[0] == server_msg);

    // Client -> Server
    std::vector<uint8_t> client_msg = {'C', 'l', 'i', 'e', 'n', 't'};
    auto encoded2 = client_framing.encode(client_msg);
    auto decoded2 = server_framing.decode(encoded2);
    REQUIRE(decoded2.has_value());
    REQUIRE(decoded2->frames.size() == 1);
    REQUIRE(decoded2->frames[0] == client_msg);
}

TEST_CASE("obfs4 cert generation and bridge line", "[integration][transport][obfs4]") {
    auto keys = RelayKeyPair::generate();
    REQUIRE(keys.has_value());

    NodeId node_id(keys->identity_key.public_key());

    Obfs4Identity identity;
    identity.node_id = node_id;
    identity.ntor_public_key = keys->onion_key.public_key();

    auto cert = identity.to_cert();

    // Verify cert round-trips
    auto parsed = Obfs4Identity::from_cert(cert);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->node_id == node_id);
    REQUIRE(parsed->ntor_public_key == keys->onion_key.public_key());

    // A bridge line would look like:
    // Bridge obfs4 1.2.3.4:443 FINGERPRINT cert=CERT iat-mode=0
    std::string bridge_line = "Bridge obfs4 1.2.3.4:443 " +
                              node_id.to_hex() +
                              " cert=" + cert +
                              " iat-mode=0";

    // Should contain all required components
    REQUIRE(bridge_line.find("obfs4") != std::string::npos);
    REQUIRE(bridge_line.find("cert=") != std::string::npos);
    REQUIRE(bridge_line.find("iat-mode=") != std::string::npos);
}
