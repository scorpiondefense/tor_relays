#pragma once

#include "tor/crypto/keys.hpp"
#include "tor/policy/exit_policy.hpp"
#include "tor/policy/bandwidth.hpp"
#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace tor::directory {

// Descriptor error types
enum class DescriptorError {
    ParseError,
    InvalidSignature,
    MissingField,
    InvalidField,
    ExpiredDescriptor,
    FutureDescriptor,
};

// Router flags (from consensus)
struct RouterFlags {
    bool authority{false};
    bool bad_exit{false};
    bool exit{false};
    bool fast{false};
    bool guard{false};
    bool hsdir{false};
    bool no_ed_consensus{false};
    bool stable{false};
    bool stale_desc{false};
    bool running{true};
    bool valid{true};
    bool v2dir{false};

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static std::expected<RouterFlags, DescriptorError>
    parse(const std::string& flags_str);
};

// Server descriptor (published by relays)
class ServerDescriptor {
public:
    ServerDescriptor() = default;

    // Identity
    std::string nickname;
    crypto::Ed25519PublicKey identity_key;
    crypto::Curve25519PublicKey onion_key;
    crypto::NodeId fingerprint;

    // Network addresses
    std::string address;  // IPv4 address
    uint16_t or_port{0};
    uint16_t dir_port{0};
    std::optional<std::string> ipv6_address;
    std::optional<uint16_t> ipv6_or_port;

    // Platform info
    std::string platform;  // e.g., "Tor 0.4.7.13 on Linux"
    std::vector<std::string> protocols;  // Supported sub-protocols

    // Timing
    std::chrono::system_clock::time_point published;
    std::optional<std::chrono::seconds> uptime;

    // Bandwidth
    uint64_t bandwidth_avg{0};    // Average bandwidth (bytes/s)
    uint64_t bandwidth_burst{0};  // Burst bandwidth (bytes/s)
    uint64_t bandwidth_observed{0};  // Observed bandwidth

    // Exit policy
    policy::ExitPolicy exit_policy;
    std::optional<policy::ExitPolicySummary> exit_policy_summary;

    // Family
    std::vector<crypto::NodeId> family;

    // Contact info
    std::string contact;

    // Hidden service directory
    bool hidden_service_dir{false};

    // Extra info digest (if published)
    std::optional<std::string> extra_info_digest;

    // Generate descriptor document
    [[nodiscard]] std::expected<std::string, DescriptorError>
    generate(const crypto::Ed25519SecretKey& signing_key) const;

    // Parse descriptor document
    [[nodiscard]] static std::expected<ServerDescriptor, DescriptorError>
    parse(const std::string& document);

    // Verify descriptor signature
    [[nodiscard]] std::expected<void, DescriptorError>
    verify_signature(const std::string& document) const;

    // Check if descriptor is valid (not expired, not in future)
    [[nodiscard]] bool is_valid() const;

    // Get digest of descriptor (for consensus)
    [[nodiscard]] std::string digest() const;

private:
    std::string cached_document_;
    mutable std::optional<std::string> cached_digest_;

    // Sign descriptor with identity key
    [[nodiscard]] std::expected<std::string, DescriptorError>
    sign(const std::string& document, const crypto::Ed25519SecretKey& key) const;
};

// Extra info descriptor (optional additional data)
class ExtraInfoDescriptor {
public:
    ExtraInfoDescriptor() = default;

    std::string nickname;
    crypto::NodeId fingerprint;
    std::chrono::system_clock::time_point published;

    // Statistics
    std::optional<policy::BandwidthHistory> write_history;
    std::optional<policy::BandwidthHistory> read_history;

    // Geoip stats
    std::optional<std::string> geoip_db_digest;
    std::optional<std::string> geoip6_db_digest;

    // Cell statistics
    std::optional<uint64_t> cell_stats_end;
    std::optional<uint64_t> cell_processed_cells;
    std::optional<uint64_t> cell_queued_cells;

    // Generate extra info document
    [[nodiscard]] std::expected<std::string, DescriptorError>
    generate(const crypto::Ed25519SecretKey& signing_key) const;

    // Parse extra info document
    [[nodiscard]] static std::expected<ExtraInfoDescriptor, DescriptorError>
    parse(const std::string& document);
};

// Micro descriptor (compact descriptor for clients)
class MicroDescriptor {
public:
    MicroDescriptor() = default;

    crypto::Curve25519PublicKey onion_key;
    std::optional<crypto::Ed25519PublicKey> ed25519_id;
    std::vector<crypto::NodeId> family;
    std::optional<policy::ExitPolicySummary> exit_policy;

    [[nodiscard]] std::string generate() const;
    [[nodiscard]] static std::expected<MicroDescriptor, DescriptorError>
    parse(const std::string& document);

    // Micro descriptor digest
    [[nodiscard]] std::string digest() const;
};

// Descriptor builder for constructing descriptors
class DescriptorBuilder {
public:
    DescriptorBuilder() = default;

    DescriptorBuilder& nickname(const std::string& name);
    DescriptorBuilder& identity_key(const crypto::Ed25519PublicKey& key);
    DescriptorBuilder& onion_key(const crypto::Curve25519PublicKey& key);
    DescriptorBuilder& address(const std::string& addr, uint16_t port);
    DescriptorBuilder& dir_port(uint16_t port);
    DescriptorBuilder& ipv6_address(const std::string& addr, uint16_t port);
    DescriptorBuilder& bandwidth(uint64_t avg, uint64_t burst, uint64_t observed);
    DescriptorBuilder& exit_policy(const policy::ExitPolicy& policy);
    DescriptorBuilder& contact(const std::string& info);
    DescriptorBuilder& family(const std::vector<crypto::NodeId>& nodes);
    DescriptorBuilder& platform(const std::string& plat);
    DescriptorBuilder& hidden_service_dir(bool enabled);

    [[nodiscard]] ServerDescriptor build() const;

private:
    ServerDescriptor desc_;
};

// Utility
[[nodiscard]] std::string descriptor_error_message(DescriptorError err);

// Format timestamp for descriptor
[[nodiscard]] std::string format_descriptor_time(
    std::chrono::system_clock::time_point tp
);

// Parse timestamp from descriptor
[[nodiscard]] std::expected<std::chrono::system_clock::time_point, DescriptorError>
parse_descriptor_time(const std::string& str);

}  // namespace tor::directory
