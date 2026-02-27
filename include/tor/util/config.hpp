#pragma once

#include "tor/modes/relay_behavior.hpp"
#include "tor/modes/bridge_relay.hpp"
#include "tor/policy/exit_policy.hpp"
#include "tor/policy/bandwidth.hpp"
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tor::util {

// Configuration error types
enum class ConfigError {
    FileNotFound,
    ParseError,
    InvalidValue,
    MissingRequired,
    ValidationFailed,
};

// Relay configuration
struct RelayConfig {
    // Identity
    std::string nickname;
    std::string contact_info;

    // Network
    std::string address;        // External IP address (or auto-detect)
    uint16_t or_port{9001};     // Onion router port
    uint16_t dir_port{0};       // Directory port (0 = disabled)
    bool ipv6_enabled{false};
    std::string ipv6_address;
    uint16_t ipv6_or_port{0};

    // Mode
    modes::RelayMode mode{modes::RelayMode::Middle};

    // Bandwidth
    policy::BandwidthManager::Config bandwidth;

    // Data directory
    std::filesystem::path data_dir;
};

// Exit-specific configuration
struct ExitConfig {
    policy::ExitPolicy exit_policy;
    bool reduced_exit_policy{false};
    bool reject_private_networks{true};
    bool dns_enabled{true};
    std::string dns_server;  // Custom DNS server (empty = system default)
};

// Bridge-specific configuration
struct BridgeConfig {
    modes::BridgeRelay::Distribution distribution{modes::BridgeRelay::Distribution::None};
    std::string transport;           // Pluggable transport (e.g., "obfs4")
    std::string bridge_authority;    // Bridge authority address
    std::string server_transport_plugin;  // Path to transport plugin
    uint16_t transport_port{443};    // Port for pluggable transport (e.g., obfs4)
    uint8_t iat_mode{0};            // IAT obfuscation mode (0=off, 1=enabled, 2=paranoid)
};

// Guard-specific configuration
struct GuardConfig {
    // Eligibility requirements for Guard flag
    std::chrono::seconds min_uptime{8 * 24 * 3600};  // 8 days
    size_t min_bandwidth{2 * 1024 * 1024};           // 2 MB/s

    // Client tracking (privacy-preserving)
    bool track_clients{true};
    size_t max_tracked_clients{10000};
};

// Directory configuration
struct DirectoryConfig {
    bool publish_server_descriptor{true};
    bool publish_extra_info{false};
    std::vector<std::string> directory_authorities;
    std::chrono::seconds publish_interval{3600};  // 1 hour
};

// Security configuration
struct SecurityConfig {
    bool sandbox_enabled{true};
    bool hardware_acceleration{true};  // Use CPU crypto extensions
    size_t max_memory_mb{0};           // 0 = unlimited
    size_t max_circuits{0};            // 0 = unlimited
    size_t max_streams_per_circuit{500};
};

// Logging configuration
struct LoggingConfig {
    std::string level{"info"};
    std::string log_file;
    bool log_timestamps{true};
    bool log_to_console{true};
    size_t max_log_size_mb{10};
    size_t max_log_files{5};
};

// Complete configuration
class Config {
public:
    Config() = default;

    // Load from TOML file
    [[nodiscard]] static std::expected<Config, ConfigError>
    load_from_file(const std::filesystem::path& path);

    // Load from TOML string
    [[nodiscard]] static std::expected<Config, ConfigError>
    load_from_string(const std::string& toml_content);

    // Save to TOML file
    [[nodiscard]] std::expected<void, ConfigError>
    save_to_file(const std::filesystem::path& path) const;

    // Serialize to TOML string
    [[nodiscard]] std::string to_toml() const;

    // Validate configuration
    [[nodiscard]] std::expected<void, ConfigError> validate() const;

    // Apply command-line overrides
    void apply_cli_args(int argc, char* argv[]);

    // Configuration sections
    RelayConfig relay;
    ExitConfig exit;
    BridgeConfig bridge;
    GuardConfig guard;
    DirectoryConfig directory;
    SecurityConfig security;
    LoggingConfig logging;

    // Get effective exit policy based on mode
    [[nodiscard]] policy::ExitPolicy effective_exit_policy() const;

    // Check if running as exit relay
    [[nodiscard]] bool is_exit() const {
        return relay.mode == modes::RelayMode::Exit;
    }

    // Check if running as bridge
    [[nodiscard]] bool is_bridge() const {
        return relay.mode == modes::RelayMode::Bridge;
    }

    // Check if running as guard
    [[nodiscard]] bool is_guard() const {
        return relay.mode == modes::RelayMode::Guard;
    }

private:
    [[nodiscard]] std::expected<void, ConfigError> parse_toml(const std::string& content);
};

// Generate default configuration
[[nodiscard]] Config default_config();

// Generate example configuration file content
[[nodiscard]] std::string example_config_toml();

// Utility
[[nodiscard]] std::string config_error_message(ConfigError err);

// CLI argument parsing
struct CliArgs {
    std::optional<std::filesystem::path> config_file;
    std::optional<modes::RelayMode> mode;
    std::optional<uint16_t> port;
    std::optional<std::string> nickname;
    std::optional<std::string> data_dir;
    std::optional<std::string> log_level;
    bool help{false};
    bool version{false};
    bool verify_config{false};
};

[[nodiscard]] std::expected<CliArgs, std::string>
parse_cli_args(int argc, char* argv[]);

void print_usage(const char* program_name);
void print_version();

}  // namespace tor::util
