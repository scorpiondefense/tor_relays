#include <catch2/catch_all.hpp>
#include "tor/modes/guard_relay.hpp"
#include "tor/modes/relay_behavior.hpp"
#include "tor/util/config.hpp"

using namespace tor::modes;
using namespace tor::util;

TEST_CASE("Guard mode parsing", "[guard][modes][unit]") {
    SECTION("Parse guard mode lowercase") {
        auto result = parse_relay_mode("guard");
        REQUIRE(result.has_value());
        CHECK(*result == RelayMode::Guard);
    }

    SECTION("Parse guard mode capitalized") {
        auto result = parse_relay_mode("Guard");
        REQUIRE(result.has_value());
        CHECK(*result == RelayMode::Guard);
    }

    SECTION("Parse guard mode uppercase") {
        auto result = parse_relay_mode("GUARD");
        REQUIRE(result.has_value());
        CHECK(*result == RelayMode::Guard);
    }
}

TEST_CASE("Guard relay mode name", "[guard][modes][unit]") {
    CHECK(std::string(relay_mode_name(RelayMode::Guard)) == "Guard");
}

TEST_CASE("Guard relay creation", "[guard][modes][unit]") {
    SECTION("Default construction") {
        GuardRelay guard;
        CHECK(guard.mode() == RelayMode::Guard);
        CHECK(guard.mode_name() == "Guard");
    }

    SECTION("Factory function") {
        auto behavior = create_behavior(RelayMode::Guard, nullptr);
        REQUIRE(behavior != nullptr);
        CHECK(behavior->mode() == RelayMode::Guard);
        CHECK(behavior->mode_name() == "Guard");
    }

    SECTION("With config") {
        Config config;
        config.guard.min_uptime = std::chrono::seconds{10 * 24 * 3600};  // 10 days
        config.guard.min_bandwidth = 5 * 1024 * 1024;  // 5 MB/s

        GuardRelay guard(&config);
        CHECK(guard.requirements().min_uptime == std::chrono::seconds{10 * 24 * 3600});
        CHECK(guard.requirements().min_bandwidth == 5 * 1024 * 1024);
    }
}

TEST_CASE("Guard relay operation permissions", "[guard][modes][unit]") {
    GuardRelay guard;

    SECTION("Allowed operations") {
        CHECK(guard.allows_operation(RelayOperation::ForwardRelay));
        CHECK(guard.allows_operation(RelayOperation::BeginDir));
        CHECK(guard.allows_operation(RelayOperation::PublishDescriptor));
        CHECK(guard.allows_operation(RelayOperation::AcceptRendezvous));
    }

    SECTION("Denied operations") {
        CHECK_FALSE(guard.allows_operation(RelayOperation::CreateStreams));
        CHECK_FALSE(guard.allows_operation(RelayOperation::ExitToInternet));
        CHECK_FALSE(guard.allows_operation(RelayOperation::ResolveDns));
    }
}

TEST_CASE("Guard relay statistics", "[guard][modes][unit]") {
    GuardRelay guard;

    SECTION("Initial stats are zero") {
        const auto& stats = guard.stats();
        CHECK(stats.unique_clients.load() == 0);
        CHECK(stats.circuits_as_guard.load() == 0);
        CHECK(stats.cells_forwarded.load() == 0);
        CHECK_FALSE(stats.guard_duty_active.load());
    }

    SECTION("Guard duty tracking") {
        guard.start_guard_duty();
        CHECK(guard.stats().guard_duty_active.load());

        // Duty time should be >= 0
        auto duty_time = guard.stats().guard_duty_time();
        CHECK(duty_time.count() >= 0);
    }

    SECTION("Client tracking") {
        guard.record_client("client_1");
        CHECK(guard.stats().unique_clients.load() == 1);

        // Same client again shouldn't increase count
        guard.record_client("client_1");
        CHECK(guard.stats().unique_clients.load() == 1);

        // Different client should increase count
        guard.record_client("client_2");
        CHECK(guard.stats().unique_clients.load() == 2);
    }
}

TEST_CASE("Guard eligibility requirements", "[guard][modes][unit]") {
    SECTION("Default requirements") {
        auto reqs = GuardRelay::EligibilityRequirements::default_requirements();
        CHECK(reqs.min_uptime == std::chrono::seconds{8 * 24 * 3600});  // 8 days
        CHECK(reqs.min_bandwidth == 2 * 1024 * 1024);  // 2 MB/s
    }

    SECTION("Guard does not meet requirements initially") {
        GuardRelay guard;
        guard.start_guard_duty();

        // Just started, shouldn't meet 8 day uptime requirement
        CHECK_FALSE(guard.meets_guard_requirements());
    }
}

TEST_CASE("Guard relay descriptor additions", "[guard][modes][unit]") {
    GuardRelay guard;
    guard.start_guard_duty();

    auto additions = guard.descriptor_additions();

    // Should contain guard-specific fields
    CHECK(additions.find("guard-circuits") != std::string::npos);
    CHECK(additions.find("guard-clients") != std::string::npos);
}

TEST_CASE("Guard relay config validation", "[guard][modes][unit]") {
    SECTION("Default config is valid") {
        GuardRelay guard;
        auto result = guard.validate_config();
        CHECK(result.has_value());
    }

    SECTION("Invalid config with zero bandwidth") {
        Config config;
        config.guard.min_bandwidth = 0;

        GuardRelay guard(&config);
        auto result = guard.validate_config();
        CHECK_FALSE(result.has_value());
    }

    SECTION("Invalid config with zero uptime") {
        Config config;
        config.guard.min_uptime = std::chrono::seconds{0};

        GuardRelay guard(&config);
        auto result = guard.validate_config();
        CHECK_FALSE(result.has_value());
    }
}

TEST_CASE("Config is_guard helper", "[guard][config][unit]") {
    Config config;

    SECTION("is_guard returns true for guard mode") {
        config.relay.mode = RelayMode::Guard;
        CHECK(config.is_guard());
        CHECK_FALSE(config.is_exit());
        CHECK_FALSE(config.is_bridge());
    }

    SECTION("is_guard returns false for other modes") {
        config.relay.mode = RelayMode::Middle;
        CHECK_FALSE(config.is_guard());

        config.relay.mode = RelayMode::Exit;
        CHECK_FALSE(config.is_guard());

        config.relay.mode = RelayMode::Bridge;
        CHECK_FALSE(config.is_guard());
    }
}
