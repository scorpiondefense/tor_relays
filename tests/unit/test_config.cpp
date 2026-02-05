#include <catch2/catch_all.hpp>
#include "tor/util/config.hpp"
#include "tor/modes/relay_behavior.hpp"

using namespace tor::util;
using namespace tor::modes;

TEST_CASE("Relay mode parsing", "[config][modes][unit]") {
    SECTION("Parse middle mode") {
        auto result = parse_relay_mode("middle");
        REQUIRE(result.has_value());
        CHECK(*result == RelayMode::Middle);
    }

    SECTION("Parse exit mode") {
        auto result = parse_relay_mode("exit");
        REQUIRE(result.has_value());
        CHECK(*result == RelayMode::Exit);
    }

    SECTION("Parse bridge mode") {
        auto result = parse_relay_mode("bridge");
        REQUIRE(result.has_value());
        CHECK(*result == RelayMode::Bridge);
    }

    SECTION("Case insensitive") {
        CHECK(parse_relay_mode("MIDDLE").has_value());
        CHECK(parse_relay_mode("Exit").has_value());
        CHECK(parse_relay_mode("BRIDGE").has_value());
    }

    SECTION("Invalid mode") {
        auto result = parse_relay_mode("invalid");
        CHECK_FALSE(result.has_value());
    }
}

TEST_CASE("Default config", "[config][unit]") {
    auto config = default_config();

    SECTION("Has sensible defaults") {
        CHECK(config.relay.mode == RelayMode::Middle);
        CHECK(config.relay.or_port == 9001);
        CHECK(config.relay.dir_port == 0);  // Disabled by default
    }

    SECTION("Directory published for middle relay") {
        CHECK(config.directory.publish_server_descriptor == true);
    }
}

TEST_CASE("Config effective exit policy", "[config][policy][unit]") {
    Config config;

    SECTION("Middle relay rejects all") {
        config.relay.mode = RelayMode::Middle;
        auto policy = config.effective_exit_policy();

        // Middle relay should reject all
        CHECK_FALSE(policy.allows(0x08080808, 80));
    }

    SECTION("Bridge relay rejects all") {
        config.relay.mode = RelayMode::Bridge;
        auto policy = config.effective_exit_policy();

        CHECK_FALSE(policy.allows(0x08080808, 80));
    }
}

TEST_CASE("Config mode helpers", "[config][unit]") {
    Config config;

    SECTION("is_exit") {
        config.relay.mode = RelayMode::Exit;
        CHECK(config.is_exit());
        CHECK_FALSE(config.is_bridge());
    }

    SECTION("is_bridge") {
        config.relay.mode = RelayMode::Bridge;
        CHECK(config.is_bridge());
        CHECK_FALSE(config.is_exit());
    }

    SECTION("Neither for middle") {
        config.relay.mode = RelayMode::Middle;
        CHECK_FALSE(config.is_exit());
        CHECK_FALSE(config.is_bridge());
    }
}

TEST_CASE("Relay mode names", "[config][unit]") {
    CHECK(std::string(relay_mode_name(RelayMode::Middle)) == "Middle");
    CHECK(std::string(relay_mode_name(RelayMode::Exit)) == "Exit");
    CHECK(std::string(relay_mode_name(RelayMode::Bridge)) == "Bridge");
}

TEST_CASE("Relay operation names", "[config][unit]") {
    CHECK(std::string(relay_operation_name(RelayOperation::ForwardRelay)) == "ForwardRelay");
    CHECK(std::string(relay_operation_name(RelayOperation::ExitToInternet)) == "ExitToInternet");
    CHECK(std::string(relay_operation_name(RelayOperation::PublishDescriptor)) == "PublishDescriptor");
}

TEST_CASE("Bandwidth config", "[config][bandwidth][unit]") {
    SECTION("Unlimited config") {
        auto config = policy::BandwidthManager::Config::unlimited();
        CHECK(config.rate == 0);
        CHECK(config.burst == 0);
    }

    SECTION("Limited config") {
        auto config = policy::BandwidthManager::Config::limited(10);  // 10 Mbps
        CHECK(config.rate == 10 * 1024 * 1024);  // 10 MB/s
    }
}
