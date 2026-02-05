#pragma once

#include "tor/crypto/keys.hpp"
#include "tor/directory/descriptor.hpp"
#include <chrono>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tor::directory {

// Consensus error types
enum class ConsensusError {
    ParseError,
    InvalidSignature,
    MissingField,
    ExpiredConsensus,
    NotEnoughSignatures,
    InvalidFormat,
};

// Network status document type
enum class ConsensusType {
    NetworkStatus,    // Full network status (ns flavor)
    MicroDescriptor,  // Micro descriptor consensus (microdesc flavor)
};

// Router status entry in consensus
struct RouterStatus {
    std::string nickname;
    crypto::NodeId identity;
    std::optional<crypto::Ed25519PublicKey> ed25519_id;
    std::string descriptor_digest;  // Or micro descriptor digest

    // Address info
    std::string address;
    uint16_t or_port{0};
    uint16_t dir_port{0};

    // Flags
    RouterFlags flags;

    // Version
    std::optional<std::string> version;

    // Bandwidth weight
    uint64_t bandwidth{0};

    // Protocols
    std::map<std::string, std::vector<uint32_t>> protocols;

    // For micro descriptor consensus
    std::optional<std::string> micro_digest;

    [[nodiscard]] bool is_exit() const { return flags.exit; }
    [[nodiscard]] bool is_guard() const { return flags.guard; }
    [[nodiscard]] bool is_stable() const { return flags.stable; }
    [[nodiscard]] bool is_fast() const { return flags.fast; }
    [[nodiscard]] bool is_running() const { return flags.running; }
    [[nodiscard]] bool is_valid() const { return flags.valid; }
};

// Directory authority signature
struct AuthoritySignature {
    std::string identity;  // Authority identity fingerprint
    std::string signing_key_digest;
    std::string signature;
    std::string algorithm;  // "sha256" or "sha1"
};

// Bandwidth weights for path selection
struct BandwidthWeights {
    int64_t wgg{0};  // Guard for guard position
    int64_t wgm{0};  // Guard for middle position
    int64_t wgd{0};  // Guard for exit position (directory)
    int64_t wmg{0};  // Middle for guard position
    int64_t wmm{0};  // Middle for middle position
    int64_t wme{0};  // Middle for exit position
    int64_t wmd{0};  // Middle for directory
    int64_t weg{0};  // Exit for guard position
    int64_t wem{0};  // Exit for middle position
    int64_t wed{0};  // Exit for directory
    int64_t wee{0};  // Exit for exit position
    int64_t wbd{0};  // Bandwidth for directory
    int64_t wbg{0};  // Bandwidth for guard
    int64_t wbe{0};  // Bandwidth for exit
    int64_t wbm{0};  // Bandwidth for middle

    static constexpr int64_t SCALE = 10000;
};

// Network consensus document
class Consensus {
public:
    Consensus() = default;

    // Consensus metadata
    ConsensusType type{ConsensusType::NetworkStatus};
    uint32_t consensus_method{0};

    // Timing
    std::chrono::system_clock::time_point valid_after;
    std::chrono::system_clock::time_point fresh_until;
    std::chrono::system_clock::time_point valid_until;

    // Voting info
    uint32_t vote_delay_seconds{0};
    uint32_t dist_delay_seconds{0};

    // Client versions
    std::vector<std::string> client_versions;
    std::vector<std::string> server_versions;

    // Known flags
    std::vector<std::string> known_flags;

    // Recommended client/server protocols
    std::map<std::string, std::string> recommended_client_protocols;
    std::map<std::string, std::string> recommended_relay_protocols;
    std::map<std::string, std::string> required_client_protocols;
    std::map<std::string, std::string> required_relay_protocols;

    // Parameters
    std::map<std::string, int64_t> params;

    // Shared random values
    std::optional<std::string> shared_rand_previous;
    std::optional<std::string> shared_rand_current;

    // Router statuses
    std::vector<RouterStatus> routers;

    // Authority signatures
    std::vector<AuthoritySignature> signatures;

    // Bandwidth weights
    BandwidthWeights bandwidth_weights;

    // Parse consensus document
    [[nodiscard]] static std::expected<Consensus, ConsensusError>
    parse(const std::string& document);

    // Verify consensus signatures
    [[nodiscard]] std::expected<void, ConsensusError>
    verify_signatures(
        const std::vector<crypto::Ed25519PublicKey>& authority_keys
    ) const;

    // Check if consensus is valid (timing)
    [[nodiscard]] bool is_fresh() const;
    [[nodiscard]] bool is_valid() const;
    [[nodiscard]] bool is_expired() const;

    // Find router by identity
    [[nodiscard]] std::optional<RouterStatus>
    find_router(const crypto::NodeId& identity) const;

    // Find router by nickname
    [[nodiscard]] std::optional<RouterStatus>
    find_router_by_nickname(const std::string& nickname) const;

    // Get all exit routers
    [[nodiscard]] std::vector<RouterStatus> get_exits() const;

    // Get all guard routers
    [[nodiscard]] std::vector<RouterStatus> get_guards() const;

    // Get total bandwidth
    [[nodiscard]] uint64_t total_bandwidth() const;

    // Get parameter with default
    [[nodiscard]] int64_t get_param(
        const std::string& name,
        int64_t default_value
    ) const;

private:
    mutable std::map<crypto::NodeId, size_t> identity_index_;

    void build_index() const;
};

// Consensus diff (for incremental updates)
class ConsensusDiff {
public:
    ConsensusDiff() = default;

    std::string from_digest;  // Digest of base consensus
    std::string to_digest;    // Digest of resulting consensus
    std::vector<std::string> diff_lines;

    // Apply diff to base consensus
    [[nodiscard]] std::expected<std::string, ConsensusError>
    apply(const std::string& base_consensus) const;

    // Parse diff document
    [[nodiscard]] static std::expected<ConsensusDiff, ConsensusError>
    parse(const std::string& document);
};

// Consensus cache for storing and retrieving consensus documents
class ConsensusCache {
public:
    explicit ConsensusCache(const std::filesystem::path& cache_dir);
    ~ConsensusCache() = default;

    // Get cached consensus
    [[nodiscard]] std::expected<Consensus, ConsensusError>
    get_consensus(ConsensusType type) const;

    // Store consensus
    [[nodiscard]] std::expected<void, ConsensusError>
    store_consensus(const Consensus& consensus, const std::string& document);

    // Get cached consensus diff
    [[nodiscard]] std::expected<ConsensusDiff, ConsensusError>
    get_diff(const std::string& from_digest) const;

    // Check if we have a valid cached consensus
    [[nodiscard]] bool has_valid_consensus(ConsensusType type) const;

private:
    std::filesystem::path cache_dir_;
    mutable std::shared_ptr<Consensus> cached_consensus_;
};

// Utility
[[nodiscard]] std::string consensus_error_message(ConsensusError err);

}  // namespace tor::directory
