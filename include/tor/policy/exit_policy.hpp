#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace tor::policy {

// Policy error types
enum class PolicyError {
    ParseError,
    InvalidAddress,
    InvalidPort,
    InvalidCidr,
    InvalidRule,
};

// Port range (inclusive)
struct PortRange {
    uint16_t low{0};
    uint16_t high{65535};

    [[nodiscard]] bool contains(uint16_t port) const {
        return port >= low && port <= high;
    }

    [[nodiscard]] bool is_single() const { return low == high; }
    [[nodiscard]] bool is_all() const { return low == 0 && high == 65535; }

    [[nodiscard]] static PortRange single(uint16_t port) { return {port, port}; }
    [[nodiscard]] static PortRange all() { return {0, 65535}; }
    [[nodiscard]] static PortRange range(uint16_t low, uint16_t high) { return {low, high}; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static std::expected<PortRange, PolicyError> parse(const std::string& str);

    bool operator==(const PortRange&) const = default;
};

// IPv4 address with optional CIDR mask
struct IPv4Address {
    uint32_t address{0};
    uint8_t prefix_len{32};  // CIDR prefix length (0-32)

    [[nodiscard]] bool matches(uint32_t ip) const;
    [[nodiscard]] bool is_any() const { return prefix_len == 0; }
    [[nodiscard]] bool is_exact() const { return prefix_len == 32; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static std::expected<IPv4Address, PolicyError> parse(const std::string& str);
    [[nodiscard]] static IPv4Address any() { return {0, 0}; }
    [[nodiscard]] static IPv4Address from_octets(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        return {(static_cast<uint32_t>(a) << 24) |
                (static_cast<uint32_t>(b) << 16) |
                (static_cast<uint32_t>(c) << 8) |
                static_cast<uint32_t>(d), 32};
    }

    bool operator==(const IPv4Address&) const = default;
};

// IPv6 address with optional prefix
struct IPv6Address {
    std::array<uint8_t, 16> address{};
    uint8_t prefix_len{128};

    [[nodiscard]] bool matches(std::span<const uint8_t, 16> ip) const;
    [[nodiscard]] bool is_any() const { return prefix_len == 0; }
    [[nodiscard]] bool is_exact() const { return prefix_len == 128; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static std::expected<IPv6Address, PolicyError> parse(const std::string& str);
    [[nodiscard]] static IPv6Address any() { return {{}, 0}; }

    bool operator==(const IPv6Address&) const = default;
};

// Address pattern (can be *, hostname, IPv4, or IPv6)
struct AddressPattern {
    enum class Type { Any, IPv4, IPv6, Hostname };

    Type type{Type::Any};
    std::variant<std::monostate, IPv4Address, IPv6Address, std::string> value;

    [[nodiscard]] bool matches(uint32_t ipv4) const;
    [[nodiscard]] bool matches(std::span<const uint8_t, 16> ipv6) const;
    [[nodiscard]] bool matches(const std::string& hostname) const;

    [[nodiscard]] bool is_any() const { return type == Type::Any; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static std::expected<AddressPattern, PolicyError> parse(const std::string& str);
    [[nodiscard]] static AddressPattern any() { return {Type::Any, std::monostate{}}; }

    bool operator==(const AddressPattern&) const = default;
};

// Single exit policy rule
struct ExitPolicyRule {
    enum class Action { Accept, Reject };

    Action action{Action::Reject};
    AddressPattern address;
    PortRange ports;

    [[nodiscard]] bool matches(uint32_t ipv4, uint16_t port) const;
    [[nodiscard]] bool matches(std::span<const uint8_t, 16> ipv6, uint16_t port) const;
    [[nodiscard]] bool matches(const std::string& hostname, uint16_t port) const;

    [[nodiscard]] bool is_accept() const { return action == Action::Accept; }
    [[nodiscard]] bool is_reject() const { return action == Action::Reject; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static std::expected<ExitPolicyRule, PolicyError> parse(const std::string& str);

    bool operator==(const ExitPolicyRule&) const = default;
};

// Complete exit policy (list of rules evaluated in order)
class ExitPolicy {
public:
    ExitPolicy() = default;
    explicit ExitPolicy(std::vector<ExitPolicyRule> rules);

    // Check if destination is allowed (evaluates rules in order)
    [[nodiscard]] bool allows(uint32_t ipv4, uint16_t port) const;
    [[nodiscard]] bool allows(std::span<const uint8_t, 16> ipv6, uint16_t port) const;
    [[nodiscard]] bool allows(const std::string& hostname, uint16_t port) const;

    // Add rule
    void add_rule(ExitPolicyRule rule);
    void add_rule_front(ExitPolicyRule rule);

    // Get rules
    [[nodiscard]] const std::vector<ExitPolicyRule>& rules() const { return rules_; }
    [[nodiscard]] size_t rule_count() const { return rules_.size(); }
    [[nodiscard]] bool is_empty() const { return rules_.empty(); }

    // Clear all rules
    void clear() { rules_.clear(); }

    // Serialize for descriptor
    [[nodiscard]] std::string to_string() const;

    // Parse policy from string (one rule per line)
    [[nodiscard]] static std::expected<ExitPolicy, PolicyError>
    parse(const std::string& policy_str);

    // Standard policies
    [[nodiscard]] static ExitPolicy reject_all();   // "reject *:*"
    [[nodiscard]] static ExitPolicy accept_all();   // "accept *:*"
    [[nodiscard]] static ExitPolicy reduced();      // Common web ports only

    // Helper to check for private addresses
    [[nodiscard]] static bool is_private_ipv4(uint32_t ip);
    [[nodiscard]] static bool is_private_ipv6(std::span<const uint8_t, 16> ip);

    bool operator==(const ExitPolicy&) const = default;

private:
    std::vector<ExitPolicyRule> rules_;

    // Default action when no rule matches
    static constexpr ExitPolicyRule::Action DEFAULT_ACTION = ExitPolicyRule::Action::Reject;
};

// Summary of exit policy for directory
struct ExitPolicySummary {
    bool accepts_most_ports{false};
    std::vector<PortRange> accepted_ports;
    std::vector<PortRange> rejected_ports;

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static ExitPolicySummary from_policy(const ExitPolicy& policy);
};

// Utility
[[nodiscard]] std::string policy_error_message(PolicyError err);

// Parse IPv4 address from dotted-decimal string
[[nodiscard]] std::expected<uint32_t, PolicyError> parse_ipv4(const std::string& str);

// Parse port from string
[[nodiscard]] std::expected<uint16_t, PolicyError> parse_port(const std::string& str);

// Common port numbers
namespace ports {
    constexpr uint16_t HTTP = 80;
    constexpr uint16_t HTTPS = 443;
    constexpr uint16_t FTP = 21;
    constexpr uint16_t SSH = 22;
    constexpr uint16_t SMTP = 25;
    constexpr uint16_t DNS = 53;
    constexpr uint16_t POP3 = 110;
    constexpr uint16_t IMAP = 143;
    constexpr uint16_t IRC = 6667;
}

// Private network ranges
namespace private_ranges {
    // 10.0.0.0/8
    constexpr uint32_t RFC1918_10_BASE = 0x0A000000;
    constexpr uint32_t RFC1918_10_MASK = 0xFF000000;

    // 172.16.0.0/12
    constexpr uint32_t RFC1918_172_BASE = 0xAC100000;
    constexpr uint32_t RFC1918_172_MASK = 0xFFF00000;

    // 192.168.0.0/16
    constexpr uint32_t RFC1918_192_BASE = 0xC0A80000;
    constexpr uint32_t RFC1918_192_MASK = 0xFFFF0000;

    // 127.0.0.0/8
    constexpr uint32_t LOOPBACK_BASE = 0x7F000000;
    constexpr uint32_t LOOPBACK_MASK = 0xFF000000;
}

}  // namespace tor::policy
