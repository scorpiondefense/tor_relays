// Implementation - policy/bandwidth.cpp
#include "tor/policy/bandwidth.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace tor::policy {

// TokenBucket implementation
TokenBucket::TokenBucket(uint64_t rate_bytes_per_sec, uint64_t burst_bytes)
    : tokens_(burst_bytes)
    , rate_(rate_bytes_per_sec)
    , burst_(burst_bytes)
    , last_refill_(std::chrono::steady_clock::now()) {}

bool TokenBucket::try_consume(uint64_t bytes) {
    std::lock_guard lock(mutex_);
    refill();
    
    if (tokens_ >= bytes) {
        tokens_ -= bytes;
        return true;
    }
    return false;
}

uint64_t TokenBucket::available() const {
    std::lock_guard lock(mutex_);
    return tokens_;
}

void TokenBucket::set_rate(uint64_t rate_bytes_per_sec) {
    std::lock_guard lock(mutex_);
    rate_ = rate_bytes_per_sec;
}

void TokenBucket::set_burst(uint64_t burst_bytes) {
    std::lock_guard lock(mutex_);
    burst_ = burst_bytes;
}

void TokenBucket::reset() {
    std::lock_guard lock(mutex_);
    tokens_ = burst_;
    last_refill_ = std::chrono::steady_clock::now();
}

void TokenBucket::refill() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refill_);
    
    if (elapsed.count() > 0) {
        uint64_t new_tokens = (rate_ * elapsed.count()) / 1000;
        tokens_ = std::min(tokens_ + new_tokens, burst_);
        last_refill_ = now;
    }
}

// BandwidthStats implementation
void BandwidthStats::reset() {
    bytes_read = 0;
    bytes_written = 0;
    bytes_relayed = 0;
    read_rate = 0;
    write_rate = 0;
    relay_rate = 0;
    peak_read_rate = 0;
    peak_write_rate = 0;
}

// BandwidthManager::Config implementation
BandwidthManager::Config BandwidthManager::Config::unlimited() {
    return Config{0, 0, 0, 0, 0, 0};
}

BandwidthManager::Config BandwidthManager::Config::limited(uint64_t rate_mbps) {
    uint64_t rate = rate_mbps * 1024 * 1024;  // Convert to bytes per second
    uint64_t burst = rate * 2;  // Allow 2 seconds of burst
    return Config{rate, burst, rate, burst, 0, 0};
}

// BandwidthManager implementation
BandwidthManager::BandwidthManager() 
    : last_rate_update_(std::chrono::steady_clock::now()) {}

BandwidthManager::BandwidthManager(const Config& config)
    : config_(config)
    , last_rate_update_(std::chrono::steady_clock::now()) {
    if (config.rate > 0) {
        read_bucket_ = std::make_unique<TokenBucket>(config.rate, config.burst);
        write_bucket_ = std::make_unique<TokenBucket>(config.rate, config.burst);
    }
    if (config.relay_rate > 0) {
        relay_bucket_ = std::make_unique<TokenBucket>(config.relay_rate, config.relay_burst);
    }
}

void BandwidthManager::configure(const Config& config) {
    config_ = config;
    if (config.rate > 0) {
        read_bucket_ = std::make_unique<TokenBucket>(config.rate, config.burst);
        write_bucket_ = std::make_unique<TokenBucket>(config.rate, config.burst);
    } else {
        read_bucket_.reset();
        write_bucket_.reset();
    }
    if (config.relay_rate > 0) {
        relay_bucket_ = std::make_unique<TokenBucket>(config.relay_rate, config.relay_burst);
    } else {
        relay_bucket_.reset();
    }
}

bool BandwidthManager::allow_read(uint64_t bytes) {
    if (!read_bucket_) return true;
    return read_bucket_->try_consume(bytes);
}

bool BandwidthManager::allow_write(uint64_t bytes) {
    if (!write_bucket_) return true;
    return write_bucket_->try_consume(bytes);
}

bool BandwidthManager::allow_relay(uint64_t bytes) {
    if (!relay_bucket_) {
        // Use write bucket if no separate relay bucket
        return allow_write(bytes);
    }
    return relay_bucket_->try_consume(bytes);
}

void BandwidthManager::record_read(uint64_t bytes) {
    stats_.bytes_read += bytes;
}

void BandwidthManager::record_write(uint64_t bytes) {
    stats_.bytes_written += bytes;
}

void BandwidthManager::record_relay(uint64_t bytes) {
    stats_.bytes_relayed += bytes;
}

void BandwidthManager::update_rates() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_rate_update_);
    
    if (elapsed.count() > 0) {
        uint64_t read_diff = stats_.bytes_read - last_bytes_read_;
        uint64_t write_diff = stats_.bytes_written - last_bytes_written_;
        uint64_t relay_diff = stats_.bytes_relayed - last_bytes_relayed_;
        
        stats_.read_rate = read_diff / elapsed.count();
        stats_.write_rate = write_diff / elapsed.count();
        stats_.relay_rate = relay_diff / elapsed.count();
        
        // Update peak rates
        if (stats_.read_rate > stats_.peak_read_rate) {
            stats_.peak_read_rate = stats_.read_rate.load();
        }
        if (stats_.write_rate > stats_.peak_write_rate) {
            stats_.peak_write_rate = stats_.write_rate.load();
        }
        
        last_bytes_read_ = stats_.bytes_read;
        last_bytes_written_ = stats_.bytes_written;
        last_bytes_relayed_ = stats_.bytes_relayed;
        last_rate_update_ = now;
    }
}

// BandwidthHistory implementation
BandwidthHistory::BandwidthHistory() {
    buckets_.resize(MAX_BUCKETS);
    buckets_[0].start_time = std::chrono::system_clock::now();
}

void BandwidthHistory::record(uint64_t read_bytes, uint64_t write_bytes) {
    std::lock_guard lock(mutex_);
    rotate_if_needed();
    buckets_[current_bucket_].read_bytes += read_bytes;
    buckets_[current_bucket_].write_bytes += write_bytes;
}

uint64_t BandwidthHistory::observed_bandwidth() const {
    std::lock_guard lock(mutex_);
    
    uint64_t total = 0;
    size_t count = 0;
    
    for (const auto& bucket : buckets_) {
        if (bucket.read_bytes > 0 || bucket.write_bytes > 0) {
            total += std::min(bucket.read_bytes, bucket.write_bytes);
            ++count;
        }
    }
    
    if (count == 0) return 0;
    
    // Average bytes per 15-min bucket, converted to bytes/sec
    return (total / count) / (15 * 60);
}

std::string BandwidthHistory::write_history() const {
    return "";
}

std::string BandwidthHistory::read_history() const {
    return "";
}

void BandwidthHistory::rotate_if_needed() {
    auto now = std::chrono::system_clock::now();
    auto elapsed = now - buckets_[current_bucket_].start_time;
    
    if (elapsed >= BUCKET_INTERVAL) {
        current_bucket_ = (current_bucket_ + 1) % MAX_BUCKETS;
        buckets_[current_bucket_].read_bytes = 0;
        buckets_[current_bucket_].write_bytes = 0;
        buckets_[current_bucket_].start_time = now;
    }
}

// Utility functions
std::string bandwidth_error_message(BandwidthError err) {
    switch (err) {
        case BandwidthError::InvalidRate: return "Invalid bandwidth rate";
        case BandwidthError::InvalidBurst: return "Invalid burst size";
        case BandwidthError::RateLimitExceeded: return "Rate limit exceeded";
        default: return "Unknown bandwidth error";
    }
}

std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double value = bytes;
    
    while (value >= 1024 && unit < 4) {
        value /= 1024;
        ++unit;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value << " " << units[unit];
    return oss.str();
}

std::string format_rate(uint64_t bytes_per_sec) {
    return format_bytes(bytes_per_sec) + "/s";
}

std::expected<uint64_t, BandwidthError> parse_bandwidth(const std::string& str) {
    // Simple parsing
    uint64_t value = 0;
    try {
        value = std::stoull(str);
    } catch (...) {
        return std::unexpected(BandwidthError::InvalidRate);
    }
    return value;
}

}  // namespace tor::policy
