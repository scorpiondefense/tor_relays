#include <catch2/catch_all.hpp>
#include "tor/core/circuit.hpp"
#include "tor/core/channel.hpp"
#include "tor/crypto/ntor.hpp"
#include "../mocks/mock_network.hpp"

using namespace tor::core;
using namespace tor::crypto;

TEST_CASE("Circuit creation flow", "[circuit][integration]") {
    SECTION("Create circuit and initialize crypto") {
        auto channel = std::make_shared<Channel>();
        CircuitTable table;

        // Create circuit
        auto circuit_result = table.create_circuit(channel);
        REQUIRE(circuit_result.has_value());
        auto circuit = *circuit_result;

        CHECK(circuit->state() == CircuitState::Created);

        // Simulate ntor handshake completion
        auto server_identity = Ed25519SecretKey::generate();
        REQUIRE(server_identity.has_value());

        auto server_onion = Curve25519SecretKey::generate();
        REQUIRE(server_onion.has_value());

        NodeId server_node_id(server_identity->public_key());

        // Client initiates handshake
        NtorClientHandshake client;
        auto request = client.create_request(
            server_node_id, server_onion->public_key());
        REQUIRE(request.has_value());

        // Server responds
        NtorServerHandshake server;
        auto server_result = server.process_request(
            *request, server_node_id, *server_onion);
        REQUIRE(server_result.has_value());

        auto& [response, server_keys] = *server_result;

        // Client completes
        auto client_keys = client.complete_handshake(response);
        REQUIRE(client_keys.has_value());

        // Initialize circuit crypto
        auto init_result = circuit->init_crypto(*client_keys);
        REQUIRE(init_result.has_value());

        // Transition to Open
        circuit->set_state(CircuitState::Open);
        CHECK(circuit->state() == CircuitState::Open);
    }

    SECTION("Circuit table manages multiple circuits") {
        auto channel = std::make_shared<Channel>();
        CircuitTable table;

        // Create multiple circuits
        std::vector<std::shared_ptr<Circuit>> circuits;
        for (int i = 0; i < 10; ++i) {
            auto result = table.create_circuit(channel);
            REQUIRE(result.has_value());
            circuits.push_back(*result);
        }

        CHECK(table.count() == 10);

        // Verify all circuits have unique IDs
        std::set<CircuitId> ids;
        for (const auto& c : circuits) {
            ids.insert(c->id());
        }
        CHECK(ids.size() == 10);
    }

    SECTION("Circuit cleanup removes stale circuits") {
        auto channel = std::make_shared<Channel>();
        CircuitTable table;

        // Create circuit
        auto result = table.create_circuit(channel);
        REQUIRE(result.has_value());
        auto circuit = *result;

        // Circuit should not be cleaned up immediately
        auto removed = table.cleanup_stale(std::chrono::seconds(300));
        CHECK(removed == 0);
        CHECK(table.count() == 1);

        // With very short timeout, should be cleaned up
        removed = table.cleanup_stale(std::chrono::seconds(0));
        CHECK(removed == 1);
        CHECK(table.count() == 0);
    }
}

TEST_CASE("Stream lifecycle", "[circuit][streams][integration]") {
    auto channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, channel);

    SECTION("Complete stream lifecycle") {
        // Create stream
        auto create_result = circuit->create_stream(100);
        REQUIRE(create_result.has_value());
        auto stream = *create_result;

        CHECK(stream->state() == Stream::State::Connecting);

        // Set target
        stream->set_target("example.com", 443);
        CHECK(stream->target_address() == "example.com");
        CHECK(stream->target_port() == 443);

        // Transition to Open (simulating CONNECTED received)
        stream->set_state(Stream::State::Open);
        CHECK(stream->state() == Stream::State::Open);

        // Simulate data transfer
        for (int i = 0; i < 10; ++i) {
            stream->decrement_deliver_window();
        }
        CHECK(stream->deliver_window() == 490);

        // Close stream
        stream->set_state(Stream::State::Closed);
        CHECK(stream->state() == Stream::State::Closed);

        // Remove from circuit
        circuit->remove_stream(100);
        CHECK(circuit->stream_count() == 0);
    }

    SECTION("Multiple concurrent streams") {
        for (StreamId id = 1; id <= 5; ++id) {
            auto result = circuit->create_stream(id);
            REQUIRE(result.has_value());
        }

        CHECK(circuit->stream_count() == 5);

        // Remove some streams
        circuit->remove_stream(2);
        circuit->remove_stream(4);

        CHECK(circuit->stream_count() == 3);

        // Remaining streams should be accessible
        CHECK(circuit->get_stream(1) != nullptr);
        CHECK(circuit->get_stream(3) != nullptr);
        CHECK(circuit->get_stream(5) != nullptr);
        CHECK(circuit->get_stream(2) == nullptr);
        CHECK(circuit->get_stream(4) == nullptr);
    }
}

TEST_CASE("Cell encryption roundtrip", "[circuit][crypto][integration]") {
    auto channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, channel);

    // Set up crypto
    auto server_identity = Ed25519SecretKey::generate();
    REQUIRE(server_identity.has_value());

    auto server_onion = Curve25519SecretKey::generate();
    REQUIRE(server_onion.has_value());

    NodeId server_node_id(server_identity->public_key());

    NtorClientHandshake client;
    auto request = client.create_request(
        server_node_id, server_onion->public_key());
    REQUIRE(request.has_value());

    NtorServerHandshake server;
    auto server_result = server.process_request(
        *request, server_node_id, *server_onion);
    REQUIRE(server_result.has_value());

    auto client_keys = client.complete_handshake(server_result->first);
    REQUIRE(client_keys.has_value());

    auto init_result = circuit->init_crypto(*client_keys);
    REQUIRE(init_result.has_value());

    // Note: Full encryption roundtrip would require both sides of the circuit
    // This test verifies the crypto initialization succeeds
}
