#include "tor/directory/descriptor.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace tor::directory {

// RouterFlags implementation
std::string RouterFlags::to_string() const {
    std::ostringstream oss;
    if (authority) oss << "Authority ";
    if (bad_exit) oss << "BadExit ";
    if (exit) oss << "Exit ";
    if (fast) oss << "Fast ";
    if (guard) oss << "Guard ";
    if (hsdir) oss << "HSDir ";
    if (no_ed_consensus) oss << "NoEdConsensus ";
    if (stable) oss << "Stable ";
    if (stale_desc) oss << "StaleDesc ";
    if (running) oss << "Running ";
    if (valid) oss << "Valid ";
    if (v2dir) oss << "V2Dir ";

    std::string result = oss.str();
    // Remove trailing space
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result;
}

std::expected<RouterFlags, DescriptorError>
RouterFlags::parse(const std::string& flags_str) {
    RouterFlags flags;
    flags.running = false;
    flags.valid = false;

    std::istringstream iss(flags_str);
    std::string flag;
    while (iss >> flag) {
        if (flag == "Authority") flags.authority = true;
        else if (flag == "BadExit") flags.bad_exit = true;
        else if (flag == "Exit") flags.exit = true;
        else if (flag == "Fast") flags.fast = true;
        else if (flag == "Guard") flags.guard = true;
        else if (flag == "HSDir") flags.hsdir = true;
        else if (flag == "NoEdConsensus") flags.no_ed_consensus = true;
        else if (flag == "Stable") flags.stable = true;
        else if (flag == "StaleDesc") flags.stale_desc = true;
        else if (flag == "Running") flags.running = true;
        else if (flag == "Valid") flags.valid = true;
        else if (flag == "V2Dir") flags.v2dir = true;
    }
    return flags;
}

// ServerDescriptor implementation
bool ServerDescriptor::is_valid() const {
    auto now = std::chrono::system_clock::now();

    // Check if published is in the future (with some tolerance)
    auto future_tolerance = std::chrono::hours(1);
    if (published > now + future_tolerance) {
        return false;
    }

    // Check if descriptor is expired (18 hours is standard)
    auto max_age = std::chrono::hours(18);
    if (now - published > max_age) {
        return false;
    }

    // Check required fields
    if (nickname.empty()) return false;
    if (address.empty()) return false;
    if (or_port == 0) return false;

    return true;
}

// DescriptorBuilder implementation
DescriptorBuilder& DescriptorBuilder::nickname(const std::string& name) {
    desc_.nickname = name;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::identity_key(const crypto::Ed25519PublicKey& key) {
    desc_.identity_key = key;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::onion_key(const crypto::Curve25519PublicKey& key) {
    desc_.onion_key = key;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::address(const std::string& addr, uint16_t port) {
    desc_.address = addr;
    desc_.or_port = port;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::dir_port(uint16_t port) {
    desc_.dir_port = port;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::ipv6_address(const std::string& addr, uint16_t port) {
    desc_.ipv6_address = addr;
    desc_.ipv6_or_port = port;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::bandwidth(uint64_t avg, uint64_t burst, uint64_t observed) {
    desc_.bandwidth_avg = avg;
    desc_.bandwidth_burst = burst;
    desc_.bandwidth_observed = observed;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::exit_policy(const policy::ExitPolicy& policy) {
    desc_.exit_policy = policy;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::contact(const std::string& info) {
    desc_.contact = info;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::family(const std::vector<crypto::NodeId>& nodes) {
    desc_.family = nodes;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::platform(const std::string& plat) {
    desc_.platform = plat;
    return *this;
}

DescriptorBuilder& DescriptorBuilder::hidden_service_dir(bool enabled) {
    desc_.hidden_service_dir = enabled;
    return *this;
}

ServerDescriptor DescriptorBuilder::build() const {
    ServerDescriptor result = desc_;
    result.published = std::chrono::system_clock::now();
    // Compute fingerprint as SHA-1 of the identity key
    result.fingerprint = crypto::NodeId(result.identity_key);
    return result;
}

// Utility functions
std::string descriptor_error_message(DescriptorError err) {
    switch (err) {
        case DescriptorError::ParseError: return "Parse error";
        case DescriptorError::InvalidSignature: return "Invalid signature";
        case DescriptorError::MissingField: return "Missing required field";
        case DescriptorError::InvalidField: return "Invalid field value";
        case DescriptorError::ExpiredDescriptor: return "Descriptor has expired";
        case DescriptorError::FutureDescriptor: return "Descriptor is from the future";
        default: return "Unknown descriptor error";
    }
}

std::string format_descriptor_time(std::chrono::system_clock::time_point tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_val;
#ifdef _WIN32
    gmtime_s(&tm_val, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_val);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_val, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::expected<std::chrono::system_clock::time_point, DescriptorError>
parse_descriptor_time(const std::string& str) {
    std::tm tm_val = {};
    std::istringstream iss(str);
    iss >> std::get_time(&tm_val, "%Y-%m-%d %H:%M:%S");

    if (iss.fail()) {
        return std::unexpected(DescriptorError::ParseError);
    }

#ifdef _WIN32
    auto time_t_val = _mkgmtime(&tm_val);
#else
    auto time_t_val = timegm(&tm_val);
#endif

    if (time_t_val == -1) {
        return std::unexpected(DescriptorError::ParseError);
    }

    return std::chrono::system_clock::from_time_t(time_t_val);
}

}  // namespace tor::directory
