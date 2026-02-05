#include <catch2/catch_all.hpp>
#include "tor/directory/descriptor.hpp"
#include "tor/crypto/keys.hpp"
#include "tor/policy/exit_policy.hpp"

using namespace tor::directory;
using namespace tor::crypto;
using namespace tor::policy;

TEST_CASE("Server descriptor building", "[directory][integration]") {
    SECTION("Build complete descriptor") {
        // Generate keys
        auto identity_result = Ed25519SecretKey::generate();
        REQUIRE(identity_result.has_value());

        auto onion_result = Curve25519SecretKey::generate();
        REQUIRE(onion_result.has_value());

        // Build descriptor
        DescriptorBuilder builder;
        auto desc = builder
            .nickname("TestRelay")
            .identity_key(identity_result->public_key())
            .onion_key(onion_result->public_key())
            .address("1.2.3.4", 9001)
            .dir_port(9030)
            .bandwidth(10000000, 20000000, 8000000)
            .exit_policy(ExitPolicy::reduced())
            .contact("test@example.com")
            .platform("Tor 1.0.0 (test)")
            .hidden_service_dir(true)
            .build();

        CHECK(desc.nickname == "TestRelay");
        CHECK(desc.or_port == 9001);
        CHECK(desc.dir_port == 9030);
        CHECK(desc.bandwidth_avg == 10000000);
        CHECK(desc.bandwidth_burst == 20000000);
        CHECK(desc.bandwidth_observed == 8000000);
        CHECK(desc.contact == "test@example.com");
        CHECK(desc.hidden_service_dir == true);
    }

    SECTION("Descriptor has correct identity") {
        auto identity_result = Ed25519SecretKey::generate();
        REQUIRE(identity_result.has_value());

        auto onion_result = Curve25519SecretKey::generate();
        REQUIRE(onion_result.has_value());

        DescriptorBuilder builder;
        auto desc = builder
            .nickname("TestRelay")
            .identity_key(identity_result->public_key())
            .onion_key(onion_result->public_key())
            .address("1.2.3.4", 9001)
            .build();

        CHECK(desc.identity_key == identity_result->public_key());
        CHECK(desc.onion_key == onion_result->public_key());

        // Fingerprint should be SHA-1 of identity key
        NodeId expected_fp(identity_result->public_key());
        CHECK(desc.fingerprint == expected_fp);
    }
}

TEST_CASE("Router flags", "[directory][flags][integration]") {
    SECTION("Flag to string") {
        RouterFlags flags;
        flags.exit = true;
        flags.guard = true;
        flags.stable = true;
        flags.valid = true;
        flags.running = true;

        auto str = flags.to_string();
        CHECK(str.find("Exit") != std::string::npos);
        CHECK(str.find("Guard") != std::string::npos);
        CHECK(str.find("Stable") != std::string::npos);
    }

    SECTION("Default flags") {
        RouterFlags flags;
        CHECK(flags.running == true);
        CHECK(flags.valid == true);
        CHECK(flags.exit == false);
        CHECK(flags.guard == false);
    }
}

TEST_CASE("Descriptor validity", "[directory][validity][integration]") {
    SECTION("Recently published descriptor is valid") {
        auto identity_result = Ed25519SecretKey::generate();
        REQUIRE(identity_result.has_value());

        auto onion_result = Curve25519SecretKey::generate();
        REQUIRE(onion_result.has_value());

        DescriptorBuilder builder;
        auto desc = builder
            .nickname("TestRelay")
            .identity_key(identity_result->public_key())
            .onion_key(onion_result->public_key())
            .address("1.2.3.4", 9001)
            .build();

        // Set published time to now
        desc.published = std::chrono::system_clock::now();

        CHECK(desc.is_valid());
    }
}

TEST_CASE("Directory authority defaults", "[directory][authority][integration]") {
    SECTION("Get default authorities") {
        auto authorities = get_default_authorities();
        CHECK(!authorities.empty());
    }

    SECTION("Get bridge authorities") {
        auto authorities = get_bridge_authorities();
        // May be empty in test environment, but shouldn't crash
    }

    SECTION("Authority has required fields") {
        auto authorities = get_default_authorities();

        for (const auto& auth : authorities) {
            CHECK(!auth.nickname.empty());
            CHECK(!auth.address.empty());
            CHECK(auth.dir_port > 0);
        }
    }
}

TEST_CASE("Exit policy in descriptor", "[directory][policy][integration]") {
    SECTION("Descriptor contains exit policy") {
        auto identity_result = Ed25519SecretKey::generate();
        REQUIRE(identity_result.has_value());

        auto onion_result = Curve25519SecretKey::generate();
        REQUIRE(onion_result.has_value());

        auto policy = ExitPolicy::reduced();

        DescriptorBuilder builder;
        auto desc = builder
            .nickname("ExitRelay")
            .identity_key(identity_result->public_key())
            .onion_key(onion_result->public_key())
            .address("1.2.3.4", 9001)
            .exit_policy(policy)
            .build();

        CHECK(!desc.exit_policy.is_empty());
    }
}

TEST_CASE("Descriptor timestamp formatting", "[directory][format][integration]") {
    SECTION("Format current time") {
        auto now = std::chrono::system_clock::now();
        auto str = format_descriptor_time(now);

        // Should be in format "YYYY-MM-DD HH:MM:SS"
        CHECK(str.length() == 19);
        CHECK(str[4] == '-');
        CHECK(str[7] == '-');
        CHECK(str[10] == ' ');
        CHECK(str[13] == ':');
        CHECK(str[16] == ':');
    }

    SECTION("Parse formatted time") {
        auto now = std::chrono::system_clock::now();
        auto str = format_descriptor_time(now);

        auto parsed = parse_descriptor_time(str);
        REQUIRE(parsed.has_value());

        // Should be within 1 second of original
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - *parsed);
        CHECK(std::abs(diff.count()) <= 1);
    }
}
