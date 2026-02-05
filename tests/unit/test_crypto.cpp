#include <catch2/catch_all.hpp>
#include "tor/crypto/keys.hpp"
#include "tor/crypto/hash.hpp"
#include "tor/crypto/aes_ctr.hpp"
#include "tor/crypto/ntor.hpp"
#include "../fixtures/key_fixtures.hpp"

using namespace tor::crypto;
using namespace tor::test::fixtures;

TEST_CASE("Ed25519 key generation", "[crypto][ed25519][unit]") {
    SECTION("Generate random key pair") {
        auto result = Ed25519SecretKey::generate();
        REQUIRE(result.has_value());

        auto& secret = *result;
        const auto& pubkey = secret.public_key();

        // Public key should not be all zeros
        bool all_zeros = true;
        for (auto byte : pubkey.data()) {
            if (byte != 0) {
                all_zeros = false;
                break;
            }
        }
        CHECK_FALSE(all_zeros);
    }

    SECTION("Key from seed is deterministic") {
        auto seed = ed25519_vectors::secret_key_1();
        auto key1 = Ed25519SecretKey::from_seed(seed);
        auto key2 = Ed25519SecretKey::from_seed(seed);

        REQUIRE(key1.has_value());
        REQUIRE(key2.has_value());

        CHECK(key1->public_key().data() == key2->public_key().data());
    }
}

TEST_CASE("Ed25519 signing and verification", "[crypto][ed25519][unit]") {
    SECTION("Sign and verify message") {
        auto key_result = Ed25519SecretKey::generate();
        REQUIRE(key_result.has_value());
        auto& key = *key_result;

        std::vector<uint8_t> message = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto sig_result = key.sign(message);
        REQUIRE(sig_result.has_value());

        bool valid = key.public_key().verify(message, *sig_result);
        CHECK(valid);
    }

    SECTION("Verification fails for wrong message") {
        auto key_result = Ed25519SecretKey::generate();
        REQUIRE(key_result.has_value());
        auto& key = *key_result;

        std::vector<uint8_t> message = {0x01, 0x02, 0x03};
        std::vector<uint8_t> wrong_message = {0x01, 0x02, 0x04};

        auto sig_result = key.sign(message);
        REQUIRE(sig_result.has_value());

        bool valid = key.public_key().verify(wrong_message, *sig_result);
        CHECK_FALSE(valid);
    }

    SECTION("Verification fails for wrong key") {
        auto key1_result = Ed25519SecretKey::generate();
        auto key2_result = Ed25519SecretKey::generate();
        REQUIRE(key1_result.has_value());
        REQUIRE(key2_result.has_value());

        std::vector<uint8_t> message = {0x01, 0x02, 0x03};
        auto sig_result = key1_result->sign(message);
        REQUIRE(sig_result.has_value());

        bool valid = key2_result->public_key().verify(message, *sig_result);
        CHECK_FALSE(valid);
    }
}

TEST_CASE("Curve25519 key generation", "[crypto][curve25519][unit]") {
    SECTION("Generate random key pair") {
        auto result = Curve25519SecretKey::generate();
        REQUIRE(result.has_value());

        const auto& pubkey = result->public_key();

        // Public key should not be all zeros
        bool all_zeros = true;
        for (auto byte : pubkey.data()) {
            if (byte != 0) {
                all_zeros = false;
                break;
            }
        }
        CHECK_FALSE(all_zeros);
    }
}

TEST_CASE("Curve25519 Diffie-Hellman", "[crypto][curve25519][unit]") {
    SECTION("DH produces same shared secret") {
        auto alice_result = Curve25519SecretKey::generate();
        auto bob_result = Curve25519SecretKey::generate();

        REQUIRE(alice_result.has_value());
        REQUIRE(bob_result.has_value());

        auto shared_ab = alice_result->diffie_hellman(bob_result->public_key());
        auto shared_ba = bob_result->diffie_hellman(alice_result->public_key());

        REQUIRE(shared_ab.has_value());
        REQUIRE(shared_ba.has_value());

        CHECK(*shared_ab == *shared_ba);
    }

    SECTION("Reject low-order points") {
        auto key_result = Curve25519SecretKey::generate();
        REQUIRE(key_result.has_value());

        Curve25519PublicKey low_order(curve25519_vectors::low_order_point());
        CHECK(low_order.is_low_order());

        auto dh_result = key_result->diffie_hellman(low_order);
        CHECK_FALSE(dh_result.has_value());
    }
}

TEST_CASE("SHA-1 hashing", "[crypto][hash][unit]") {
    SECTION("Empty string hash") {
        auto result = sha1(std::span<const uint8_t>{});
        REQUIRE(result.has_value());

        // SHA-1 of empty string
        std::array<uint8_t, 20> expected = {
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
            0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
            0xaf, 0xd8, 0x07, 0x09
        };
        CHECK(*result == expected);
    }

    SECTION("Incremental hashing") {
        Sha1 hasher;

        std::vector<uint8_t> part1 = {'h', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> part2 = {' ', 'w', 'o', 'r', 'l', 'd'};

        auto r1 = hasher.update(part1);
        REQUIRE(r1.has_value());
        auto r2 = hasher.update(part2);
        REQUIRE(r2.has_value());

        auto result = hasher.finalize();
        REQUIRE(result.has_value());

        // Compare with one-shot hash
        std::vector<uint8_t> full = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
        auto full_result = sha1(full);
        REQUIRE(full_result.has_value());

        CHECK(*result == *full_result);
    }
}

TEST_CASE("SHA-256 hashing", "[crypto][hash][unit]") {
    SECTION("Known test vector") {
        std::vector<uint8_t> message = {'a', 'b', 'c'};
        auto result = sha256(message);
        REQUIRE(result.has_value());

        // SHA-256("abc")
        std::array<uint8_t, 32> expected = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
        CHECK(*result == expected);
    }
}

TEST_CASE("HMAC-SHA256", "[crypto][hash][unit]") {
    SECTION("RFC 4231 test vector 1") {
        std::vector<uint8_t> key(20, 0x0b);
        std::vector<uint8_t> data = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};

        auto result = hmac_sha256(key, data);
        REQUIRE(result.has_value());

        std::array<uint8_t, 32> expected = {
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
        };
        CHECK(*result == expected);
    }
}

TEST_CASE("AES-128-CTR encryption", "[crypto][aes][unit]") {
    SECTION("Encrypt and decrypt") {
        auto key = aes_vectors::key_1();
        auto nonce = aes_vectors::nonce_1();

        std::vector<uint8_t> plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

        AesCtr128 cipher;
        auto init_result = cipher.init(key, nonce);
        REQUIRE(init_result.has_value());

        auto encrypt_result = cipher.process(std::span<const uint8_t>(plaintext));
        REQUIRE(encrypt_result.has_value());

        // Decrypt (reset and process ciphertext)
        cipher.reset();
        auto decrypt_result = cipher.process(std::span<const uint8_t>(*encrypt_result));
        REQUIRE(decrypt_result.has_value());

        CHECK(*decrypt_result == plaintext);
    }

    SECTION("CTR mode is symmetric") {
        auto key = aes_vectors::key_1();
        auto nonce = aes_vectors::nonce_1();

        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};

        // Encrypt with one cipher
        auto result1 = aes_ctr_128(key, nonce, data);
        REQUIRE(result1.has_value());

        // "Decrypt" with another cipher (CTR mode is symmetric)
        auto result2 = aes_ctr_128(key, nonce, *result1);
        REQUIRE(result2.has_value());

        CHECK(*result2 == data);
    }
}

TEST_CASE("Hex encoding/decoding", "[crypto][encoding][unit]") {
    SECTION("Roundtrip") {
        std::vector<uint8_t> data = {0x00, 0x11, 0x22, 0x33, 0xFF};
        auto hex = to_hex(data);
        auto decoded = from_hex(hex);

        REQUIRE(decoded.has_value());
        CHECK(*decoded == data);
    }

    SECTION("Known encoding") {
        std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
        CHECK(to_hex(data) == "deadbeef");
    }
}

TEST_CASE("Base64 encoding/decoding", "[crypto][encoding][unit]") {
    SECTION("Roundtrip") {
        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto b64 = to_base64(data);
        auto decoded = from_base64(b64);

        REQUIRE(decoded.has_value());
        CHECK(*decoded == data);
    }
}

TEST_CASE("ntor handshake", "[crypto][ntor][unit]") {
    SECTION("Complete handshake") {
        // Generate server keys
        auto server_identity = Ed25519SecretKey::generate();
        REQUIRE(server_identity.has_value());

        auto server_onion = Curve25519SecretKey::generate();
        REQUIRE(server_onion.has_value());

        NodeId server_node_id(server_identity->public_key());

        // Client creates request
        NtorClientHandshake client;
        auto request = client.create_request(server_node_id, server_onion->public_key());
        REQUIRE(request.has_value());
        CHECK(request->size() == NTOR_CLIENT_HANDSHAKE_LEN);

        // Server processes request
        NtorServerHandshake server;
        auto server_result = server.process_request(
            *request, server_node_id, *server_onion);
        REQUIRE(server_result.has_value());

        auto& [response, server_keys] = *server_result;
        CHECK(response.size() == NTOR_SERVER_HANDSHAKE_LEN);

        // Client completes handshake
        auto client_keys = client.complete_handshake(response);
        REQUIRE(client_keys.has_value());

        // Keys should match (but directions are swapped)
        CHECK(client_keys->forward_key == server_keys.backward_key);
        CHECK(client_keys->backward_key == server_keys.forward_key);
    }

    SECTION("Reject invalid handshake length") {
        NtorClientHandshake client;

        NodeId node_id(std::array<uint8_t, 20>{});
        auto onion_result = Curve25519SecretKey::generate();
        REQUIRE(onion_result.has_value());

        auto request = client.create_request(node_id, onion_result->public_key());
        REQUIRE(request.has_value());

        // Truncated response
        std::vector<uint8_t> truncated_response(32, 0);
        auto result = client.complete_handshake(truncated_response);

        CHECK_FALSE(result.has_value());
        CHECK(result.error() == NtorError::InvalidHandshakeLength);
    }
}

TEST_CASE("NodeId generation", "[crypto][keys][unit]") {
    SECTION("From Ed25519 public key") {
        auto key_result = Ed25519SecretKey::generate();
        REQUIRE(key_result.has_value());

        NodeId node_id(key_result->public_key());

        // Should be SHA-1 hash of public key
        auto expected = sha1(key_result->public_key().as_span());
        REQUIRE(expected.has_value());

        CHECK(node_id.data() == *expected);
    }

    SECTION("Hex roundtrip") {
        auto key_result = Ed25519SecretKey::generate();
        REQUIRE(key_result.has_value());

        NodeId original(key_result->public_key());
        auto hex = original.to_hex();
        auto parsed = NodeId::from_hex(hex);

        REQUIRE(parsed.has_value());
        CHECK(*parsed == original);
    }
}

TEST_CASE("Constant-time comparison", "[crypto][utility][unit]") {
    SECTION("Equal arrays") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5};
        std::vector<uint8_t> b = {1, 2, 3, 4, 5};

        CHECK(constant_time_compare(a, b));
    }

    SECTION("Different arrays") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5};
        std::vector<uint8_t> b = {1, 2, 3, 4, 6};

        CHECK_FALSE(constant_time_compare(a, b));
    }

    SECTION("Different lengths") {
        std::vector<uint8_t> a = {1, 2, 3};
        std::vector<uint8_t> b = {1, 2, 3, 4};

        CHECK_FALSE(constant_time_compare(a, b));
    }
}
