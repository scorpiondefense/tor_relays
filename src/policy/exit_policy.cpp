#include "tor/policy/exit_policy.hpp"
#include <algorithm>
#include <charconv>
#include <sstream>

namespace tor::policy {

// PortRange implementation
std::string PortRange::to_string() const {
    if (is_single()) {
        return std::to_string(low);
    }
    if (is_all()) {
        return "*";
    }
    return std::to_string(low) + "-" + std::to_string(high);
}

std::expected<PortRange, PolicyError> PortRange::parse(const std::string& str) {
    if (str == "*") {
        return PortRange::all();
    }

    auto dash_pos = str.find('-');
    if (dash_pos == std::string::npos) {
        // Single port
        auto port = parse_port(str);
        if (!port) {
            return std::unexpected(port.error());
        }
        return PortRange::single(*port);
    }

    // Port range
    auto low_str = str.substr(0, dash_pos);
    auto high_str = str.substr(dash_pos + 1);

    auto low = parse_port(low_str);
    auto high = parse_port(high_str);

    if (!low || !high) {
        return std::unexpected(PolicyError::InvalidPort);
    }

    if (*low > *high) {
        return std::unexpected(PolicyError::InvalidPort);
    }

    return PortRange::range(*low, *high);
}

// IPv4Address implementation
bool IPv4Address::matches(uint32_t ip) const {
    if (prefix_len == 0) {
        return true;  // Match any
    }

    uint32_t mask = (prefix_len == 32) ? 0xFFFFFFFF : ~((1u << (32 - prefix_len)) - 1);
    return (ip & mask) == (address & mask);
}

std::string IPv4Address::to_string() const {
    if (prefix_len == 0) {
        return "*";
    }

    std::ostringstream oss;
    oss << ((address >> 24) & 0xFF) << "."
        << ((address >> 16) & 0xFF) << "."
        << ((address >> 8) & 0xFF) << "."
        << (address & 0xFF);

    if (prefix_len < 32) {
        oss << "/" << static_cast<int>(prefix_len);
    }

    return oss.str();
}

std::expected<IPv4Address, PolicyError> IPv4Address::parse(const std::string& str) {
    if (str == "*") {
        return IPv4Address::any();
    }

    std::string addr_str = str;
    uint8_t prefix = 32;

    auto slash_pos = str.find('/');
    if (slash_pos != std::string::npos) {
        addr_str = str.substr(0, slash_pos);
        auto prefix_str = str.substr(slash_pos + 1);
        int prefix_val;
        auto result = std::from_chars(prefix_str.data(),
                                       prefix_str.data() + prefix_str.size(),
                                       prefix_val);
        if (result.ec != std::errc() || prefix_val < 0 || prefix_val > 32) {
            return std::unexpected(PolicyError::InvalidCidr);
        }
        prefix = static_cast<uint8_t>(prefix_val);
    }

    auto ip_result = parse_ipv4(addr_str);
    if (!ip_result) {
        return std::unexpected(ip_result.error());
    }

    return IPv4Address{*ip_result, prefix};
}

// IPv6Address implementation
bool IPv6Address::matches(std::span<const uint8_t, 16> ip) const {
    if (prefix_len == 0) {
        return true;
    }

    size_t full_bytes = prefix_len / 8;
    size_t remaining_bits = prefix_len % 8;

    // Compare full bytes
    for (size_t i = 0; i < full_bytes; ++i) {
        if (address[i] != ip[i]) {
            return false;
        }
    }

    // Compare remaining bits
    if (remaining_bits > 0 && full_bytes < 16) {
        uint8_t mask = ~((1u << (8 - remaining_bits)) - 1);
        if ((address[full_bytes] & mask) != (ip[full_bytes] & mask)) {
            return false;
        }
    }

    return true;
}

std::string IPv6Address::to_string() const {
    if (prefix_len == 0) {
        return "*";
    }

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        oss << std::hex << ((static_cast<int>(address[i]) << 8) | address[i + 1]);
    }
    oss << "]";

    if (prefix_len < 128) {
        oss << "/" << static_cast<int>(prefix_len);
    }

    return oss.str();
}

// AddressPattern implementation
bool AddressPattern::matches(uint32_t ipv4) const {
    if (type == Type::Any) return true;
    if (type != Type::IPv4) return false;
    return std::get<IPv4Address>(value).matches(ipv4);
}

bool AddressPattern::matches(std::span<const uint8_t, 16> ipv6) const {
    if (type == Type::Any) return true;
    if (type != Type::IPv6) return false;
    return std::get<IPv6Address>(value).matches(ipv6);
}

bool AddressPattern::matches(const std::string& hostname) const {
    if (type == Type::Any) return true;
    if (type != Type::Hostname) return false;
    return std::get<std::string>(value) == hostname;
}

std::string AddressPattern::to_string() const {
    switch (type) {
        case Type::Any:
            return "*";
        case Type::IPv4:
            return std::get<IPv4Address>(value).to_string();
        case Type::IPv6:
            return std::get<IPv6Address>(value).to_string();
        case Type::Hostname:
            return std::get<std::string>(value);
        default:
            return "*";
    }
}

std::expected<AddressPattern, PolicyError> AddressPattern::parse(const std::string& str) {
    if (str == "*") {
        return AddressPattern::any();
    }

    // Try IPv4
    auto ipv4 = IPv4Address::parse(str);
    if (ipv4) {
        return AddressPattern{Type::IPv4, *ipv4};
    }

    // Try IPv6 (enclosed in brackets)
    if (str.front() == '[') {
        auto ipv6 = IPv6Address::parse(str);
        if (ipv6) {
            return AddressPattern{Type::IPv6, *ipv6};
        }
    }

    // Treat as hostname
    return AddressPattern{Type::Hostname, str};
}

// ExitPolicyRule implementation
bool ExitPolicyRule::matches(uint32_t ipv4, uint16_t port) const {
    return address.matches(ipv4) && ports.contains(port);
}

bool ExitPolicyRule::matches(std::span<const uint8_t, 16> ipv6, uint16_t port) const {
    return address.matches(ipv6) && ports.contains(port);
}

bool ExitPolicyRule::matches(const std::string& hostname, uint16_t port) const {
    return address.matches(hostname) && ports.contains(port);
}

std::string ExitPolicyRule::to_string() const {
    std::string result = (action == Action::Accept) ? "accept " : "reject ";
    result += address.to_string() + ":" + ports.to_string();
    return result;
}

std::expected<ExitPolicyRule, PolicyError> ExitPolicyRule::parse(const std::string& str) {
    std::string s = str;

    // Trim whitespace
    auto start = s.find_first_not_of(" \t");
    auto end = s.find_last_not_of(" \t");
    if (start == std::string::npos) {
        return std::unexpected(PolicyError::ParseError);
    }
    s = s.substr(start, end - start + 1);

    ExitPolicyRule rule;

    // Parse action
    if (s.substr(0, 6) == "accept") {
        rule.action = Action::Accept;
        s = s.substr(6);
    } else if (s.substr(0, 6) == "reject") {
        rule.action = Action::Reject;
        s = s.substr(6);
    } else {
        return std::unexpected(PolicyError::ParseError);
    }

    // Skip whitespace
    start = s.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return std::unexpected(PolicyError::ParseError);
    }
    s = s.substr(start);

    // Find colon separating address and port
    auto colon_pos = s.rfind(':');
    if (colon_pos == std::string::npos) {
        return std::unexpected(PolicyError::ParseError);
    }

    // Parse address
    auto addr_str = s.substr(0, colon_pos);
    auto addr_result = AddressPattern::parse(addr_str);
    if (!addr_result) {
        return std::unexpected(addr_result.error());
    }
    rule.address = *addr_result;

    // Parse port
    auto port_str = s.substr(colon_pos + 1);
    auto port_result = PortRange::parse(port_str);
    if (!port_result) {
        return std::unexpected(port_result.error());
    }
    rule.ports = *port_result;

    return rule;
}

// ExitPolicy implementation
ExitPolicy::ExitPolicy(std::vector<ExitPolicyRule> rules)
    : rules_(std::move(rules)) {}

bool ExitPolicy::allows(uint32_t ipv4, uint16_t port) const {
    // Check private addresses
    if (is_private_ipv4(ipv4)) {
        return false;
    }

    for (const auto& rule : rules_) {
        if (rule.matches(ipv4, port)) {
            return rule.is_accept();
        }
    }
    return false;  // Default reject
}

bool ExitPolicy::allows(std::span<const uint8_t, 16> ipv6, uint16_t port) const {
    if (is_private_ipv6(ipv6)) {
        return false;
    }

    for (const auto& rule : rules_) {
        if (rule.matches(ipv6, port)) {
            return rule.is_accept();
        }
    }
    return false;
}

bool ExitPolicy::allows(const std::string& hostname, uint16_t port) const {
    for (const auto& rule : rules_) {
        if (rule.matches(hostname, port)) {
            return rule.is_accept();
        }
    }
    return false;
}

void ExitPolicy::add_rule(ExitPolicyRule rule) {
    rules_.push_back(std::move(rule));
}

void ExitPolicy::add_rule_front(ExitPolicyRule rule) {
    rules_.insert(rules_.begin(), std::move(rule));
}

std::string ExitPolicy::to_string() const {
    std::ostringstream oss;
    for (const auto& rule : rules_) {
        oss << rule.to_string() << "\n";
    }
    return oss.str();
}

std::expected<ExitPolicy, PolicyError> ExitPolicy::parse(const std::string& policy_str) {
    std::vector<ExitPolicyRule> rules;
    std::istringstream iss(policy_str);
    std::string line;

    while (std::getline(iss, line)) {
        // Skip empty lines and comments
        auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') {
            continue;
        }

        auto rule_result = ExitPolicyRule::parse(line);
        if (!rule_result) {
            return std::unexpected(rule_result.error());
        }
        rules.push_back(*rule_result);
    }

    return ExitPolicy(std::move(rules));
}

ExitPolicy ExitPolicy::reject_all() {
    ExitPolicy policy;
    policy.add_rule(ExitPolicyRule{
        ExitPolicyRule::Action::Reject,
        AddressPattern::any(),
        PortRange::all()
    });
    return policy;
}

ExitPolicy ExitPolicy::accept_all() {
    ExitPolicy policy;
    policy.add_rule(ExitPolicyRule{
        ExitPolicyRule::Action::Accept,
        AddressPattern::any(),
        PortRange::all()
    });
    return policy;
}

ExitPolicy ExitPolicy::reduced() {
    // Reduced exit policy - common web ports only
    ExitPolicy policy;

    // Accept common ports
    std::vector<uint16_t> allowed_ports = {
        80, 443,  // HTTP/HTTPS
        21, 22,   // FTP/SSH
        23,       // Telnet
        43,       // WHOIS
        53,       // DNS
        79,       // Finger
        110, 143, // POP3/IMAP
        194,      // IRC
        220,      // IMAP3
        389,      // LDAP
        443,      // HTTPS
        465, 587, // SMTP
        706,      // SILC
        873,      // rsync
        993, 995, // IMAPS/POP3S
        1194,     // OpenVPN
        1723,     // PPTP
        5222, 5223, // XMPP
        6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, // IRC
        6697,     // IRC over TLS
        8080,     // HTTP alt
        8443,     // HTTPS alt
    };

    for (uint16_t port : allowed_ports) {
        policy.add_rule(ExitPolicyRule{
            ExitPolicyRule::Action::Accept,
            AddressPattern::any(),
            PortRange::single(port)
        });
    }

    // Reject everything else
    policy.add_rule(ExitPolicyRule{
        ExitPolicyRule::Action::Reject,
        AddressPattern::any(),
        PortRange::all()
    });

    return policy;
}

bool ExitPolicy::is_private_ipv4(uint32_t ip) {
    using namespace private_ranges;

    // 10.0.0.0/8
    if ((ip & RFC1918_10_MASK) == RFC1918_10_BASE) return true;

    // 172.16.0.0/12
    if ((ip & RFC1918_172_MASK) == RFC1918_172_BASE) return true;

    // 192.168.0.0/16
    if ((ip & RFC1918_192_MASK) == RFC1918_192_BASE) return true;

    // 127.0.0.0/8
    if ((ip & LOOPBACK_MASK) == LOOPBACK_BASE) return true;

    return false;
}

bool ExitPolicy::is_private_ipv6(std::span<const uint8_t, 16> ip) {
    // ::1 (loopback)
    bool is_loopback = true;
    for (size_t i = 0; i < 15; ++i) {
        if (ip[i] != 0) {
            is_loopback = false;
            break;
        }
    }
    if (is_loopback && ip[15] == 1) return true;

    // fc00::/7 (unique local)
    if ((ip[0] & 0xFE) == 0xFC) return true;

    // fe80::/10 (link local)
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return true;

    return false;
}

// Utility functions
std::string policy_error_message(PolicyError err) {
    switch (err) {
        case PolicyError::ParseError: return "Parse error";
        case PolicyError::InvalidAddress: return "Invalid address";
        case PolicyError::InvalidPort: return "Invalid port";
        case PolicyError::InvalidCidr: return "Invalid CIDR notation";
        case PolicyError::InvalidRule: return "Invalid rule";
        default: return "Unknown policy error";
    }
}

std::expected<uint32_t, PolicyError> parse_ipv4(const std::string& str) {
    uint32_t result = 0;
    int octets[4];
    int count = 0;

    std::istringstream iss(str);
    std::string token;

    while (std::getline(iss, token, '.') && count < 4) {
        int val;
        auto r = std::from_chars(token.data(), token.data() + token.size(), val);
        if (r.ec != std::errc() || val < 0 || val > 255) {
            return std::unexpected(PolicyError::InvalidAddress);
        }
        octets[count++] = val;
    }

    if (count != 4) {
        return std::unexpected(PolicyError::InvalidAddress);
    }

    result = (static_cast<uint32_t>(octets[0]) << 24) |
             (static_cast<uint32_t>(octets[1]) << 16) |
             (static_cast<uint32_t>(octets[2]) << 8) |
             static_cast<uint32_t>(octets[3]);

    return result;
}

std::expected<uint16_t, PolicyError> parse_port(const std::string& str) {
    int val;
    auto result = std::from_chars(str.data(), str.data() + str.size(), val);
    if (result.ec != std::errc() || val < 0 || val > 65535) {
        return std::unexpected(PolicyError::InvalidPort);
    }
    return static_cast<uint16_t>(val);
}

}  // namespace tor::policy
