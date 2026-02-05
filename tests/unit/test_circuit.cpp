#include <catch2/catch_all.hpp>
#include <thread>
#include "tor/core/circuit.hpp"
#include "tor/core/channel.hpp"
#include "tor/crypto/ntor.hpp"

using namespace tor::core;
using namespace tor::crypto;

TEST_CASE("Circuit state machine", "[circuit][state][unit]") {
    auto channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, channel);

    SECTION("Initial state is Created") {
        CHECK(circuit->state() == CircuitState::Created);
    }

    SECTION("Valid transitions from Created") {
        CHECK(circuit->can_transition_to(CircuitState::Extending));
        CHECK(circuit->can_transition_to(CircuitState::Open));
        CHECK(circuit->can_transition_to(CircuitState::Destroying));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Closed));
    }

    SECTION("Transition to Extending") {
        circuit->set_state(CircuitState::Extending);
        CHECK(circuit->state() == CircuitState::Extending);

        CHECK(circuit->can_transition_to(CircuitState::Open));
        CHECK(circuit->can_transition_to(CircuitState::Destroying));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Created));
    }

    SECTION("Transition to Open") {
        circuit->set_state(CircuitState::Open);
        CHECK(circuit->state() == CircuitState::Open);

        CHECK(circuit->can_transition_to(CircuitState::Destroying));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Created));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Extending));
    }

    SECTION("Transition to Destroying") {
        circuit->set_state(CircuitState::Destroying);
        CHECK(circuit->state() == CircuitState::Destroying);

        CHECK(circuit->can_transition_to(CircuitState::Closed));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Open));
    }

    SECTION("Closed is terminal") {
        circuit->set_state(CircuitState::Destroying);
        circuit->set_state(CircuitState::Closed);
        CHECK(circuit->state() == CircuitState::Closed);

        CHECK_FALSE(circuit->can_transition_to(CircuitState::Created));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Open));
        CHECK_FALSE(circuit->can_transition_to(CircuitState::Destroying));
    }
}

TEST_CASE("Circuit ID and properties", "[circuit][unit]") {
    auto channel = std::make_shared<Channel>();

    SECTION("Circuit has correct ID") {
        auto circuit = std::make_shared<Circuit>(0x12345678, channel);
        CHECK(circuit->id() == 0x12345678);
    }

    SECTION("Circuit tracks creation time") {
        auto before = std::chrono::steady_clock::now();
        auto circuit = std::make_shared<Circuit>(1, channel);
        auto after = std::chrono::steady_clock::now();

        CHECK(circuit->created_at() >= before);
        CHECK(circuit->created_at() <= after);
    }

    SECTION("Circuit touch updates last_activity") {
        auto circuit = std::make_shared<Circuit>(1, channel);
        auto initial = circuit->last_activity();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        circuit->touch();

        CHECK(circuit->last_activity() > initial);
    }
}

TEST_CASE("Circuit stream management", "[circuit][streams][unit]") {
    auto channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, channel);

    SECTION("Create and retrieve stream") {
        auto result = circuit->create_stream(42);
        REQUIRE(result.has_value());

        auto stream = circuit->get_stream(42);
        REQUIRE(stream != nullptr);
        CHECK(stream->id() == 42);
        CHECK(stream->circuit_id() == circuit->id());
    }

    SECTION("Stream count increases") {
        CHECK(circuit->stream_count() == 0);

        (void)circuit->create_stream(1);
        CHECK(circuit->stream_count() == 1);

        (void)circuit->create_stream(2);
        CHECK(circuit->stream_count() == 2);
    }

    SECTION("Remove stream") {
        (void)circuit->create_stream(100);
        CHECK(circuit->stream_count() == 1);

        circuit->remove_stream(100);
        CHECK(circuit->stream_count() == 0);

        auto stream = circuit->get_stream(100);
        CHECK(stream == nullptr);
    }

    SECTION("Non-existent stream returns nullptr") {
        auto stream = circuit->get_stream(999);
        CHECK(stream == nullptr);
    }
}

TEST_CASE("Stream state and properties", "[circuit][streams][unit]") {
    Stream stream(42, 1);

    SECTION("Initial state is Connecting") {
        CHECK(stream.state() == Stream::State::Connecting);
    }

    SECTION("State transitions") {
        stream.set_state(Stream::State::Open);
        CHECK(stream.state() == Stream::State::Open);

        stream.set_state(Stream::State::HalfClosed);
        CHECK(stream.state() == Stream::State::HalfClosed);

        stream.set_state(Stream::State::Closed);
        CHECK(stream.state() == Stream::State::Closed);
    }

    SECTION("Target address and port") {
        stream.set_target("example.com", 443);
        CHECK(stream.target_address() == "example.com");
        CHECK(stream.target_port() == 443);
    }

    SECTION("Deliver window management") {
        CHECK(stream.can_send());

        // Exhaust window
        for (int i = 0; i < 500; ++i) {
            stream.decrement_deliver_window();
        }
        CHECK_FALSE(stream.can_send());

        // Refill
        stream.increment_deliver_window(50);
        CHECK(stream.can_send());
    }
}

TEST_CASE("Circuit table", "[circuit][table][unit]") {
    CircuitTable table;

    SECTION("Create circuit allocates ID") {
        auto channel = std::make_shared<Channel>();
        auto result = table.create_circuit(channel);

        REQUIRE(result.has_value());
        CHECK((*result)->id() != 0);
    }

    SECTION("Create circuit with specific ID") {
        auto channel = std::make_shared<Channel>();
        auto result = table.create_circuit(0xABCD, channel);

        REQUIRE(result.has_value());
        CHECK((*result)->id() == 0xABCD);
    }

    SECTION("Get existing circuit") {
        auto channel = std::make_shared<Channel>();
        auto created = table.create_circuit(100, channel);
        REQUIRE(created.has_value());

        auto retrieved = table.get(100);
        REQUIRE(retrieved != nullptr);
        CHECK(retrieved->id() == 100);
    }

    SECTION("Get non-existent circuit returns nullptr") {
        auto result = table.get(999);
        CHECK(result == nullptr);
    }

    SECTION("Remove circuit") {
        auto channel = std::make_shared<Channel>();
        (void)table.create_circuit(200, channel);
        CHECK(table.exists(200));

        table.remove(200);
        CHECK_FALSE(table.exists(200));
    }

    SECTION("Circuit count") {
        auto channel = std::make_shared<Channel>();

        CHECK(table.count() == 0);

        (void)table.create_circuit(1, channel);
        CHECK(table.count() == 1);

        (void)table.create_circuit(2, channel);
        CHECK(table.count() == 2);

        table.remove(1);
        CHECK(table.count() == 1);
    }

    SECTION("All circuits") {
        auto channel = std::make_shared<Channel>();
        (void)table.create_circuit(10, channel);
        (void)table.create_circuit(20, channel);
        (void)table.create_circuit(30, channel);

        auto all = table.all_circuits();
        CHECK(all.size() == 3);
    }
}

TEST_CASE("Circuit SENDME window", "[circuit][sendme][unit]") {
    auto channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, channel);

    SECTION("Initial package window") {
        CHECK(circuit->can_send());
        CHECK(circuit->package_window() == 1000);
    }

    SECTION("Decrement package window") {
        for (int i = 0; i < 100; ++i) {
            circuit->decrement_package_window();
        }
        CHECK(circuit->package_window() == 900);
    }

    SECTION("Package window blocking") {
        for (int i = 0; i < 1000; ++i) {
            circuit->decrement_package_window();
        }
        CHECK_FALSE(circuit->can_send());
    }

    SECTION("Increment package window") {
        for (int i = 0; i < 1000; ++i) {
            circuit->decrement_package_window();
        }
        CHECK_FALSE(circuit->can_send());

        circuit->increment_package_window(100);
        CHECK(circuit->can_send());
    }

    SECTION("Deliver window") {
        CHECK(circuit->deliver_window() == 1000);

        circuit->decrement_deliver_window();
        CHECK(circuit->deliver_window() == 999);

        circuit->increment_deliver_window(100);
        CHECK(circuit->deliver_window() == 1099);
    }
}

TEST_CASE("Circuit RELAY_EARLY tracking", "[circuit][relay-early][unit]") {
    auto channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, channel);

    SECTION("Initial count is zero") {
        CHECK(circuit->relay_early_count() == 0);
    }

    SECTION("Increment count") {
        circuit->increment_relay_early_count();
        CHECK(circuit->relay_early_count() == 1);

        circuit->increment_relay_early_count();
        CHECK(circuit->relay_early_count() == 2);
    }

    SECTION("Max RELAY_EARLY constant") {
        CHECK(Circuit::MAX_RELAY_EARLY == 8);
    }
}

TEST_CASE("Circuit next/prev hop", "[circuit][hops][unit]") {
    auto prev_channel = std::make_shared<Channel>();
    auto next_channel = std::make_shared<Channel>();
    auto circuit = std::make_shared<Circuit>(1, prev_channel);

    SECTION("Prev hop channel is set at construction") {
        CHECK(circuit->prev_hop_channel() == prev_channel);
    }

    SECTION("Next hop initially null") {
        CHECK(circuit->next_hop_channel() == nullptr);
        CHECK(circuit->next_hop_circuit_id() == 0);
    }

    SECTION("Set next hop") {
        circuit->set_next_hop(next_channel, 0x1234);

        CHECK(circuit->next_hop_channel() == next_channel);
        CHECK(circuit->next_hop_circuit_id() == 0x1234);
    }
}

TEST_CASE("Circuit state names", "[circuit][utility][unit]") {
    CHECK(std::string(circuit_state_name(CircuitState::Created)) == "Created");
    CHECK(std::string(circuit_state_name(CircuitState::Extending)) == "Extending");
    CHECK(std::string(circuit_state_name(CircuitState::Open)) == "Open");
    CHECK(std::string(circuit_state_name(CircuitState::Destroying)) == "Destroying");
    CHECK(std::string(circuit_state_name(CircuitState::Closed)) == "Closed");
}
