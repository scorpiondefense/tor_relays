#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace tor::policy {

// Bandwidth error types
enum class BandwidthError {
    InvalidRate,
    InvalidBurst,
    RateLimitExceeded,
};

// Token bucket rate limiter
class TokenBucket {
public:
    // Create with rate (bytes/sec) and burst size (bytes)
    TokenBucket(uint64_t rate_bytes_per_sec, uint64_t burst_bytes);
    ~TokenBucket() = default;

    // Try to consume tokens, returns true if allowed
    [[nodiscard]] bool try_consume(uint64_t bytes);

    // Get current available tokens
    [[nodiscard]] uint64_t available() const;

    // Get rate limit
    [[nodiscard]] uint64_t rate() const { return rate_; }
    [[nodiscard]] uint64_t burst() const { return burst_; }

    // Update rate/burst (thread-safe)
    void set_rate(uint64_t rate_bytes_per_sec);
    void set_burst(uint64_t burst_bytes);

    // Reset bucket to full
    void reset();

private:
    void refill();

    std::atomic<uint64_t> tokens_;
    uint64_t rate_;       // bytes per second
    uint64_t burst_;      // max tokens (burst size)
    std::chrono::steady_clock::time_point last_refill_;
    mutable std::mutex mutex_;
};

// Bandwidth statistics
struct BandwidthStats {
    std::atomic<uint64_t> bytes_read{0};
    std::atomic<uint64_t> bytes_written{0};
    std::atomic<uint64_t> bytes_relayed{0};

    // Per-second averages (computed periodically)
    std::atomic<uint64_t> read_rate{0};
    std::atomic<uint64_t> write_rate{0};
    std::atomic<uint64_t> relay_rate{0};

    // Peak rates
    std::atomic<uint64_t> peak_read_rate{0};
    std::atomic<uint64_t> peak_write_rate{0};

    void reset();
};

// Bandwidth manager for a relay
class BandwidthManager {
public:
    // Configuration
    struct Config {
        uint64_t rate{0};           // Average rate (bytes/sec), 0 = unlimited
        uint64_t burst{0};          // Burst allowance (bytes)
        uint64_t relay_rate{0};     // Relayed traffic rate, 0 = same as rate
        uint64_t relay_burst{0};    // Relayed traffic burst

        // Per-connection limits
        uint64_t per_conn_rate{0};  // Per-connection rate, 0 = no limit
        uint64_t per_conn_burst{0};

        // Common configurations
        static Config unlimited();
        static Config limited(uint64_t rate_mbps);
    };

    BandwidthManager();
    explicit BandwidthManager(const Config& config);
    ~BandwidthManager() = default;

    // Apply configuration
    void configure(const Config& config);
    [[nodiscard]] const Config& config() const { return config_; }

    // Check if read is allowed (and consume tokens)
    [[nodiscard]] bool allow_read(uint64_t bytes);

    // Check if write is allowed (and consume tokens)
    [[nodiscard]] bool allow_write(uint64_t bytes);

    // Check if relay is allowed (and consume tokens)
    [[nodiscard]] bool allow_relay(uint64_t bytes);

    // Record bytes (for stats, doesn't affect rate limiting)
    void record_read(uint64_t bytes);
    void record_write(uint64_t bytes);
    void record_relay(uint64_t bytes);

    // Get statistics
    [[nodiscard]] const BandwidthStats& stats() const { return stats_; }

    // Update rate calculations (call periodically)
    void update_rates();

    // Check if rate limiting is enabled
    [[nodiscard]] bool is_limited() const { return config_.rate > 0; }

    // Get current rates
    [[nodiscard]] uint64_t current_read_rate() const { return stats_.read_rate.load(); }
    [[nodiscard]] uint64_t current_write_rate() const { return stats_.write_rate.load(); }
    [[nodiscard]] uint64_t current_relay_rate() const { return stats_.relay_rate.load(); }

private:
    Config config_;
    std::unique_ptr<TokenBucket> read_bucket_;
    std::unique_ptr<TokenBucket> write_bucket_;
    std::unique_ptr<TokenBucket> relay_bucket_;
    BandwidthStats stats_;

    // For rate calculation
    uint64_t last_bytes_read_{0};
    uint64_t last_bytes_written_{0};
    uint64_t last_bytes_relayed_{0};
    std::chrono::steady_clock::time_point last_rate_update_;
};

// Bandwidth history for directory descriptor
class BandwidthHistory {
public:
    // Interval for history buckets (typically 15 minutes)
    static constexpr auto BUCKET_INTERVAL = std::chrono::minutes(15);
    static constexpr size_t MAX_BUCKETS = 96;  // 24 hours of 15-min buckets

    BandwidthHistory();

    // Record bandwidth usage
    void record(uint64_t read_bytes, uint64_t write_bytes);

    // Get observed bandwidth (for descriptor)
    [[nodiscard]] uint64_t observed_bandwidth() const;

    // Get bandwidth history line for descriptor
    [[nodiscard]] std::string write_history() const;
    [[nodiscard]] std::string read_history() const;

private:
    struct Bucket {
        uint64_t read_bytes{0};
        uint64_t write_bytes{0};
        std::chrono::system_clock::time_point start_time;
    };

    std::vector<Bucket> buckets_;
    size_t current_bucket_{0};
    mutable std::mutex mutex_;

    void rotate_if_needed();
};

// Utility
[[nodiscard]] std::string bandwidth_error_message(BandwidthError err);

// Format bytes as human-readable string
[[nodiscard]] std::string format_bytes(uint64_t bytes);
[[nodiscard]] std::string format_rate(uint64_t bytes_per_sec);

// Parse bandwidth string (e.g., "10 MB", "1 GBps")
[[nodiscard]] std::expected<uint64_t, BandwidthError>
parse_bandwidth(const std::string& str);

}  // namespace tor::policy
