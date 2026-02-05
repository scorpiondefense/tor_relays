#pragma once

#include <boost/asio.hpp>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace tor::net {

namespace asio = boost::asio;

// Resolver error types
enum class ResolverError {
    NotFound,
    Timeout,
    TemporaryFailure,
    PermanentFailure,
    InvalidHostname,
    NetworkError,
    Cancelled,
};

// Resolved address (IPv4 or IPv6)
struct ResolvedAddress {
    enum class Type { IPv4, IPv6 };

    Type type;
    std::variant<uint32_t, std::array<uint8_t, 16>> address;
    std::optional<uint32_t> ttl;  // Time-to-live in seconds

    [[nodiscard]] bool is_ipv4() const { return type == Type::IPv4; }
    [[nodiscard]] bool is_ipv6() const { return type == Type::IPv6; }

    [[nodiscard]] uint32_t ipv4() const {
        return std::get<uint32_t>(address);
    }

    [[nodiscard]] const std::array<uint8_t, 16>& ipv6() const {
        return std::get<std::array<uint8_t, 16>>(address);
    }

    [[nodiscard]] std::string to_string() const;
};

// Resolution result
struct ResolveResult {
    std::string hostname;
    std::vector<ResolvedAddress> addresses;
    std::chrono::system_clock::time_point resolved_at;

    [[nodiscard]] bool has_ipv4() const;
    [[nodiscard]] bool has_ipv6() const;
    [[nodiscard]] std::optional<ResolvedAddress> first_ipv4() const;
    [[nodiscard]] std::optional<ResolvedAddress> first_ipv6() const;
};

// Resolution handler
using ResolveHandler = std::function<void(
    std::expected<ResolveResult, ResolverError>
)>;

// Async DNS resolver
class Resolver {
public:
    explicit Resolver(asio::io_context& io_context);
    ~Resolver();

    // Disable copying
    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;

    // Synchronous resolution
    [[nodiscard]] std::expected<ResolveResult, ResolverError>
    resolve(const std::string& hostname);

    // Synchronous resolution (IPv4 only)
    [[nodiscard]] std::expected<ResolveResult, ResolverError>
    resolve_ipv4(const std::string& hostname);

    // Synchronous resolution (IPv6 only)
    [[nodiscard]] std::expected<ResolveResult, ResolverError>
    resolve_ipv6(const std::string& hostname);

    // Asynchronous resolution
    void async_resolve(const std::string& hostname, ResolveHandler handler);

    // Asynchronous resolution (IPv4 only)
    void async_resolve_ipv4(const std::string& hostname, ResolveHandler handler);

    // Asynchronous resolution (IPv6 only)
    void async_resolve_ipv6(const std::string& hostname, ResolveHandler handler);

    // Reverse lookup
    [[nodiscard]] std::expected<std::string, ResolverError>
    reverse_lookup(const ResolvedAddress& address);

    void async_reverse_lookup(
        const ResolvedAddress& address,
        std::function<void(std::expected<std::string, ResolverError>)> handler
    );

    // Cancel pending operations
    void cancel();

    // Set timeout for resolutions
    void set_timeout(std::chrono::milliseconds timeout) { timeout_ = timeout; }

    // Set custom DNS server (empty = system default)
    void set_dns_server(const std::string& server) { dns_server_ = server; }

private:
    asio::io_context& io_context_;
    asio::ip::tcp::resolver resolver_;
    std::chrono::milliseconds timeout_{5000};
    std::string dns_server_;
};

// DNS cache for reducing lookups
class DnsCache {
public:
    struct Entry {
        ResolveResult result;
        std::chrono::steady_clock::time_point expires_at;
    };

    DnsCache();
    explicit DnsCache(std::chrono::seconds default_ttl);
    ~DnsCache() = default;

    // Look up cached result
    [[nodiscard]] std::optional<ResolveResult> get(const std::string& hostname);

    // Store result
    void put(const std::string& hostname, const ResolveResult& result);

    // Remove entry
    void remove(const std::string& hostname);

    // Clear all entries
    void clear();

    // Remove expired entries
    size_t cleanup_expired();

    // Get cache size
    [[nodiscard]] size_t size() const { return cache_.size(); }

    // Set default TTL
    void set_default_ttl(std::chrono::seconds ttl) { default_ttl_ = ttl; }

private:
    std::unordered_map<std::string, Entry> cache_;
    std::chrono::seconds default_ttl_{300};  // 5 minutes
    mutable std::mutex mutex_;
};

// Caching resolver wrapper
class CachingResolver {
public:
    CachingResolver(asio::io_context& io_context, std::shared_ptr<DnsCache> cache = nullptr);
    ~CachingResolver() = default;

    // Resolve with caching
    [[nodiscard]] std::expected<ResolveResult, ResolverError>
    resolve(const std::string& hostname);

    void async_resolve(const std::string& hostname, ResolveHandler handler);

    // Access underlying resolver
    [[nodiscard]] Resolver& resolver() { return resolver_; }

    // Access cache
    [[nodiscard]] std::shared_ptr<DnsCache> cache() { return cache_; }

private:
    Resolver resolver_;
    std::shared_ptr<DnsCache> cache_;
};

// Utility
[[nodiscard]] std::string resolver_error_message(ResolverError err);

// Parse address from string (no DNS lookup)
[[nodiscard]] std::expected<ResolvedAddress, ResolverError>
parse_address(const std::string& addr_str);

// Check if string is a valid hostname
[[nodiscard]] bool is_valid_hostname(const std::string& hostname);

// Check if string is an IP address (not hostname)
[[nodiscard]] bool is_ip_address(const std::string& str);

}  // namespace tor::net
