#pragma once

#include "tor/crypto/keys.hpp"
#include "tor/directory/descriptor.hpp"
#include "tor/directory/consensus.hpp"
#include "tor/net/connection.hpp"
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace tor::directory {

// Directory authority error types
enum class AuthorityError {
    ConnectionFailed,
    RequestFailed,
    ResponseParseError,
    NotFound,
    Timeout,
    RateLimited,
    ServerError,
};

// Directory authority info
struct DirectoryAuthority {
    std::string nickname;
    std::string address;
    uint16_t dir_port{80};
    uint16_t or_port{443};
    crypto::NodeId identity;
    crypto::Ed25519PublicKey ed25519_id;

    // Optional v3 identity key
    std::optional<crypto::Ed25519PublicKey> v3_identity;

    // Flags
    bool is_v3_authority{true};
    bool is_bridge_authority{false};

    [[nodiscard]] std::string dir_url() const;
};

// Built-in directory authorities (hardcoded like in C Tor)
[[nodiscard]] std::vector<DirectoryAuthority> get_default_authorities();
[[nodiscard]] std::vector<DirectoryAuthority> get_bridge_authorities();

// Directory request type
enum class DirRequestType {
    Consensus,
    ConsensusDiff,
    Descriptor,
    ExtraInfo,
    MicroDescriptor,
    AuthorityCerts,
    StatusVote,
};

// Directory response
struct DirResponse {
    int status_code{0};
    std::string status_message;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;

    [[nodiscard]] bool is_success() const { return status_code >= 200 && status_code < 300; }
    [[nodiscard]] bool is_not_found() const { return status_code == 404; }
    [[nodiscard]] bool is_not_modified() const { return status_code == 304; }
    [[nodiscard]] std::string body_string() const;
};

// Directory client for fetching from authorities
class DirectoryClient {
public:
    explicit DirectoryClient(boost::asio::io_context& io_context);
    ~DirectoryClient() = default;

    // Fetch consensus
    [[nodiscard]] std::expected<Consensus, AuthorityError>
    fetch_consensus(
        const DirectoryAuthority& authority,
        ConsensusType type = ConsensusType::MicroDescriptor
    );

    // Fetch consensus diff
    [[nodiscard]] std::expected<ConsensusDiff, AuthorityError>
    fetch_consensus_diff(
        const DirectoryAuthority& authority,
        const std::string& from_digest
    );

    // Fetch server descriptor
    [[nodiscard]] std::expected<ServerDescriptor, AuthorityError>
    fetch_descriptor(
        const DirectoryAuthority& authority,
        const crypto::NodeId& identity
    );

    // Fetch multiple descriptors
    [[nodiscard]] std::expected<std::vector<ServerDescriptor>, AuthorityError>
    fetch_descriptors(
        const DirectoryAuthority& authority,
        const std::vector<crypto::NodeId>& identities
    );

    // Fetch micro descriptors
    [[nodiscard]] std::expected<std::vector<MicroDescriptor>, AuthorityError>
    fetch_micro_descriptors(
        const DirectoryAuthority& authority,
        const std::vector<std::string>& digests
    );

    // Async versions
    using ConsensusHandler = std::function<void(std::expected<Consensus, AuthorityError>)>;
    using DescriptorHandler = std::function<void(std::expected<ServerDescriptor, AuthorityError>)>;

    void async_fetch_consensus(
        const DirectoryAuthority& authority,
        ConsensusHandler handler,
        ConsensusType type = ConsensusType::MicroDescriptor
    );

    void async_fetch_descriptor(
        const DirectoryAuthority& authority,
        const crypto::NodeId& identity,
        DescriptorHandler handler
    );

    // Set timeout
    void set_timeout(std::chrono::milliseconds timeout) { timeout_ = timeout; }

private:
    boost::asio::io_context& io_context_;
    std::chrono::milliseconds timeout_{30000};

    [[nodiscard]] std::expected<DirResponse, AuthorityError>
    make_request(
        const DirectoryAuthority& authority,
        const std::string& path
    );

    [[nodiscard]] std::string build_url(
        const DirectoryAuthority& authority,
        const std::string& path
    );
};

// Directory publisher for uploading descriptors
class DirectoryPublisher {
public:
    explicit DirectoryPublisher(boost::asio::io_context& io_context);
    ~DirectoryPublisher() = default;

    // Publish server descriptor
    [[nodiscard]] std::expected<void, AuthorityError>
    publish_descriptor(
        const DirectoryAuthority& authority,
        const ServerDescriptor& descriptor,
        const crypto::Ed25519SecretKey& signing_key
    );

    // Publish extra info
    [[nodiscard]] std::expected<void, AuthorityError>
    publish_extra_info(
        const DirectoryAuthority& authority,
        const ExtraInfoDescriptor& extra_info,
        const crypto::Ed25519SecretKey& signing_key
    );

    // Publish to all authorities
    [[nodiscard]] std::expected<void, AuthorityError>
    publish_to_all(
        const ServerDescriptor& descriptor,
        const crypto::Ed25519SecretKey& signing_key
    );

    // Async publish
    using PublishHandler = std::function<void(std::expected<void, AuthorityError>)>;

    void async_publish_descriptor(
        const DirectoryAuthority& authority,
        const ServerDescriptor& descriptor,
        const crypto::Ed25519SecretKey& signing_key,
        PublishHandler handler
    );

    // Set publish interval
    void set_publish_interval(std::chrono::seconds interval) {
        publish_interval_ = interval;
    }

    // Check if republish is needed
    [[nodiscard]] bool needs_republish() const;

private:
    boost::asio::io_context& io_context_;
    std::chrono::seconds publish_interval_{3600};  // 1 hour
    std::chrono::steady_clock::time_point last_publish_;
};

// Bridge authority client (for bridge relays)
class BridgeAuthorityClient {
public:
    explicit BridgeAuthorityClient(boost::asio::io_context& io_context);
    ~BridgeAuthorityClient() = default;

    // Publish bridge descriptor
    [[nodiscard]] std::expected<void, AuthorityError>
    publish_bridge_descriptor(
        const ServerDescriptor& descriptor,
        const crypto::Ed25519SecretKey& signing_key
    );

    // Set bridge authority
    void set_authority(const DirectoryAuthority& authority) {
        bridge_authority_ = authority;
    }

private:
    boost::asio::io_context& io_context_;
    std::optional<DirectoryAuthority> bridge_authority_;
};

// Utility
[[nodiscard]] std::string authority_error_message(AuthorityError err);

// HTTP helper functions
[[nodiscard]] std::expected<DirResponse, AuthorityError>
parse_http_response(const std::vector<uint8_t>& data);

[[nodiscard]] std::vector<uint8_t>
build_http_request(
    const std::string& method,
    const std::string& path,
    const std::string& host,
    const std::map<std::string, std::string>& headers = {},
    const std::vector<uint8_t>& body = {}
);

}  // namespace tor::directory
