#include <catch2/catch_all.hpp>
#include "tor/policy/exit_policy.hpp"

using namespace tor::policy;

TEST_CASE("Port range parsing", "[exit-policy][parsing][unit]") {
    SECTION("Single port") {
        auto result = PortRange::parse("80");
        REQUIRE(result.has_value());
        CHECK(result->low == 80);
        CHECK(result->high == 80);
        CHECK(result->is_single());
    }

    SECTION("Port range") {
        auto result = PortRange::parse("80-443");
        REQUIRE(result.has_value());
        CHECK(result->low == 80);
        CHECK(result->high == 443);
        CHECK_FALSE(result->is_single());
    }

    SECTION("All ports") {
        auto result = PortRange::parse("*");
        REQUIRE(result.has_value());
        CHECK(result->is_all());
    }

    SECTION("Invalid port") {
        auto result = PortRange::parse("abc");
        CHECK_FALSE(result.has_value());
    }

    SECTION("Reversed range") {
        auto result = PortRange::parse("443-80");
        CHECK_FALSE(result.has_value());
    }
}

TEST_CASE("Port range matching", "[exit-policy][matching][unit]") {
    SECTION("Single port match") {
        auto range = PortRange::single(80);
        CHECK(range.contains(80));
        CHECK_FALSE(range.contains(81));
        CHECK_FALSE(range.contains(79));
    }

    SECTION("Range match") {
        auto range = PortRange::range(80, 443);
        CHECK(range.contains(80));
        CHECK(range.contains(443));
        CHECK(range.contains(100));
        CHECK_FALSE(range.contains(79));
        CHECK_FALSE(range.contains(444));
    }

    SECTION("All ports match") {
        auto range = PortRange::all();
        CHECK(range.contains(0));
        CHECK(range.contains(80));
        CHECK(range.contains(65535));
    }
}

TEST_CASE("IPv4 address parsing", "[exit-policy][parsing][unit]") {
    SECTION("Simple address") {
        auto result = IPv4Address::parse("192.168.1.1");
        REQUIRE(result.has_value());
        CHECK(result->prefix_len == 32);
    }

    SECTION("Address with CIDR") {
        auto result = IPv4Address::parse("10.0.0.0/8");
        REQUIRE(result.has_value());
        CHECK(result->prefix_len == 8);
    }

    SECTION("Any address") {
        auto result = IPv4Address::parse("*");
        REQUIRE(result.has_value());
        CHECK(result->is_any());
    }

    SECTION("Invalid address") {
        auto result = IPv4Address::parse("256.1.1.1");
        CHECK_FALSE(result.has_value());
    }

    SECTION("Invalid CIDR") {
        auto result = IPv4Address::parse("10.0.0.0/33");
        CHECK_FALSE(result.has_value());
    }
}

TEST_CASE("IPv4 address matching", "[exit-policy][matching][unit]") {
    SECTION("Exact match") {
        auto addr = IPv4Address::from_octets(192, 168, 1, 1);
        CHECK(addr.matches(0xC0A80101));  // 192.168.1.1
        CHECK_FALSE(addr.matches(0xC0A80102));  // 192.168.1.2
    }

    SECTION("CIDR /8 match") {
        auto result = IPv4Address::parse("10.0.0.0/8");
        REQUIRE(result.has_value());

        CHECK(result->matches(0x0A000001));  // 10.0.0.1
        CHECK(result->matches(0x0AFFFFFF));  // 10.255.255.255
        CHECK_FALSE(result->matches(0x0B000001));  // 11.0.0.1
    }

    SECTION("CIDR /24 match") {
        auto result = IPv4Address::parse("192.168.1.0/24");
        REQUIRE(result.has_value());

        CHECK(result->matches(0xC0A80100));  // 192.168.1.0
        CHECK(result->matches(0xC0A801FF));  // 192.168.1.255
        CHECK_FALSE(result->matches(0xC0A80201));  // 192.168.2.1
    }

    SECTION("Any matches everything") {
        auto addr = IPv4Address::any();
        CHECK(addr.matches(0x00000000));
        CHECK(addr.matches(0xFFFFFFFF));
        CHECK(addr.matches(0x7F000001));  // 127.0.0.1
    }
}

TEST_CASE("Exit policy rule parsing", "[exit-policy][parsing][unit]") {
    SECTION("Accept rule") {
        auto result = ExitPolicyRule::parse("accept *:80");
        REQUIRE(result.has_value());
        CHECK(result->action == ExitPolicyRule::Action::Accept);
        CHECK(result->address.is_any());
        CHECK(result->ports.is_single());
    }

    SECTION("Reject rule") {
        auto result = ExitPolicyRule::parse("reject *:*");
        REQUIRE(result.has_value());
        CHECK(result->action == ExitPolicyRule::Action::Reject);
        CHECK(result->address.is_any());
        CHECK(result->ports.is_all());
    }

    SECTION("Rule with IP") {
        auto result = ExitPolicyRule::parse("accept 192.168.1.0/24:443");
        REQUIRE(result.has_value());
        CHECK(result->action == ExitPolicyRule::Action::Accept);
        CHECK_FALSE(result->address.is_any());
    }

    SECTION("Rule with port range") {
        auto result = ExitPolicyRule::parse("accept *:80-443");
        REQUIRE(result.has_value());
        CHECK(result->ports.low == 80);
        CHECK(result->ports.high == 443);
    }

    SECTION("Invalid rule - no action") {
        auto result = ExitPolicyRule::parse("allow *:80");
        CHECK_FALSE(result.has_value());
    }

    SECTION("Invalid rule - no colon") {
        auto result = ExitPolicyRule::parse("accept 80");
        CHECK_FALSE(result.has_value());
    }
}

TEST_CASE("Exit policy evaluation", "[exit-policy][matching][unit]") {
    SECTION("Reject all policy") {
        auto policy = ExitPolicy::reject_all();
        CHECK_FALSE(policy.allows(0xC0A80101, 80));  // 192.168.1.1:80
        CHECK_FALSE(policy.allows(0x08080808, 443)); // 8.8.8.8:443
    }

    SECTION("Accept all policy") {
        auto policy = ExitPolicy::accept_all();
        // Note: accept_all still rejects private addresses
        CHECK(policy.allows(0x08080808, 80));  // 8.8.8.8:80
        CHECK_FALSE(policy.allows(0xC0A80101, 80));  // 192.168.1.1 (private)
    }

    SECTION("Rules evaluated in order") {
        auto result = ExitPolicy::parse(R"(
            accept *:80
            accept *:443
            reject *:*
        )");
        REQUIRE(result.has_value());
        auto& policy = *result;

        CHECK(policy.allows(0x08080808, 80));   // 8.8.8.8:80
        CHECK(policy.allows(0x08080808, 443));  // 8.8.8.8:443
        CHECK_FALSE(policy.allows(0x08080808, 22));  // 8.8.8.8:22
    }

    SECTION("First matching rule wins") {
        auto result = ExitPolicy::parse(R"(
            reject *:80
            accept *:*
        )");
        REQUIRE(result.has_value());
        auto& policy = *result;

        CHECK_FALSE(policy.allows(0x08080808, 80));  // Rejected by first rule
        CHECK(policy.allows(0x08080808, 443));       // Accepted by second rule
    }
}

TEST_CASE("Private address rejection", "[exit-policy][private][unit]") {
    auto policy = ExitPolicy::accept_all();

    SECTION("RFC1918 10.0.0.0/8") {
        CHECK_FALSE(policy.allows(0x0A000001, 80));  // 10.0.0.1
        CHECK_FALSE(policy.allows(0x0AFFFFFF, 80));  // 10.255.255.255
    }

    SECTION("RFC1918 172.16.0.0/12") {
        CHECK_FALSE(policy.allows(0xAC100001, 80));  // 172.16.0.1
        CHECK_FALSE(policy.allows(0xAC1FFFFF, 80));  // 172.31.255.255
        CHECK(policy.allows(0xAC200001, 80));        // 172.32.0.1 (not private)
    }

    SECTION("RFC1918 192.168.0.0/16") {
        CHECK_FALSE(policy.allows(0xC0A80001, 80));  // 192.168.0.1
        CHECK_FALSE(policy.allows(0xC0A8FFFF, 80));  // 192.168.255.255
    }

    SECTION("Loopback 127.0.0.0/8") {
        CHECK_FALSE(policy.allows(0x7F000001, 80));  // 127.0.0.1
        CHECK_FALSE(policy.allows(0x7FFFFFFF, 80));  // 127.255.255.255
    }
}

TEST_CASE("Reduced exit policy", "[exit-policy][reduced][unit]") {
    auto policy = ExitPolicy::reduced();

    SECTION("Allows common web ports") {
        CHECK(policy.allows(0x08080808, 80));   // HTTP
        CHECK(policy.allows(0x08080808, 443));  // HTTPS
    }

    SECTION("Allows common ports") {
        CHECK(policy.allows(0x08080808, 22));   // SSH
        CHECK(policy.allows(0x08080808, 53));   // DNS
        CHECK(policy.allows(0x08080808, 587));  // SMTP submission
    }

    SECTION("Rejects uncommon ports") {
        CHECK_FALSE(policy.allows(0x08080808, 25));   // SMTP (often blocked)
        CHECK_FALSE(policy.allows(0x08080808, 1234)); // Random port
    }
}

TEST_CASE("Exit policy serialization", "[exit-policy][serialization][unit]") {
    SECTION("Roundtrip") {
        auto original = ExitPolicy::parse(R"(
            accept *:80
            accept *:443
            reject *:*
        )");
        REQUIRE(original.has_value());

        auto str = original->to_string();
        auto reparsed = ExitPolicy::parse(str);

        REQUIRE(reparsed.has_value());
        CHECK(reparsed->rule_count() == original->rule_count());
    }

    SECTION("Rule to_string") {
        auto rule_result = ExitPolicyRule::parse("accept 192.168.1.0/24:80-443");
        REQUIRE(rule_result.has_value());

        auto str = rule_result->to_string();
        CHECK(str.find("accept") != std::string::npos);
        CHECK(str.find("192.168.1.0/24") != std::string::npos);
        CHECK(str.find("80-443") != std::string::npos);
    }
}

TEST_CASE("Exit policy with hostname", "[exit-policy][hostname][unit]") {
    SECTION("Match hostname exactly") {
        ExitPolicy policy;
        policy.add_rule(ExitPolicyRule{
            ExitPolicyRule::Action::Accept,
            AddressPattern{AddressPattern::Type::Hostname, std::string("example.com")},
            PortRange::all()
        });
        policy.add_rule(ExitPolicyRule{
            ExitPolicyRule::Action::Reject,
            AddressPattern::any(),
            PortRange::all()
        });

        CHECK(policy.allows("example.com", 80));
        CHECK_FALSE(policy.allows("other.com", 80));
    }
}
