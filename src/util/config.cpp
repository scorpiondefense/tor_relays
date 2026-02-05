// Implementation - util/config.cpp
#include "tor/util/config.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

namespace tor::util {

std::expected<Config, ConfigError> Config::load_from_file(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return std::unexpected(ConfigError::FileNotFound);
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        return std::unexpected(ConfigError::FileNotFound);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    
    return load_from_string(buffer.str());
}

std::expected<Config, ConfigError> Config::load_from_string(const std::string& toml_content) {
    Config config;
    // Basic TOML parsing - in a real implementation, use a TOML library
    // For now, return default config
    return config;
}

std::expected<void, ConfigError> Config::save_to_file(const std::filesystem::path& path) const {
    std::ofstream file(path);
    if (!file.is_open()) {
        return std::unexpected(ConfigError::FileNotFound);
    }
    file << to_toml();
    return {};
}

std::string Config::to_toml() const {
    std::ostringstream oss;
    oss << "[relay]\n";
    oss << "nickname = \"" << relay.nickname << "\"\n";
    oss << "or_port = " << relay.or_port << "\n";
    oss << "dir_port = " << relay.dir_port << "\n";
    return oss.str();
}

std::expected<void, ConfigError> Config::validate() const {
    if (relay.or_port == 0) {
        return std::unexpected(ConfigError::InvalidValue);
    }
    return {};
}

void Config::apply_cli_args(int argc, char* argv[]) {
    // CLI arg parsing would go here
}

policy::ExitPolicy Config::effective_exit_policy() const {
    if (relay.mode == modes::RelayMode::Exit) {
        return exit.exit_policy;
    }
    // Non-exit relays reject all
    return policy::ExitPolicy::reject_all();
}

Config default_config() {
    Config config;
    config.relay.mode = modes::RelayMode::Middle;
    config.relay.or_port = 9001;
    config.relay.dir_port = 0;
    config.directory.publish_server_descriptor = true;
    return config;
}

std::string example_config_toml() {
    return R"(
# Tor Relay Configuration

[relay]
nickname = "MyRelay"
or_port = 9001
dir_port = 0
mode = "middle"

[bandwidth]
rate = 0  # unlimited
burst = 0

[logging]
level = "info"
)";
}

std::string config_error_message(ConfigError err) {
    switch (err) {
        case ConfigError::FileNotFound: return "Configuration file not found";
        case ConfigError::ParseError: return "Failed to parse configuration";
        case ConfigError::InvalidValue: return "Invalid configuration value";
        case ConfigError::MissingRequired: return "Missing required configuration";
        case ConfigError::ValidationFailed: return "Configuration validation failed";
        default: return "Unknown configuration error";
    }
}

std::expected<CliArgs, std::string> parse_cli_args(int argc, char* argv[]) {
    CliArgs args;
    // Basic CLI parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else if (arg == "--version" || arg == "-v") {
            args.version = true;
        }
    }
    return args;
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n";
}

void print_version() {
    std::cout << "Tor Relay v1.0.0\n";
}

}  // namespace tor::util
