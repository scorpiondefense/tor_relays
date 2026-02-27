#include "tor/util/config.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>

namespace tor::util {

// --- Minimal TOML parser (standard-library only) ---

namespace {

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

// Flat key-value store: "section.subsection.key" -> "value"
using TomlMap = std::unordered_map<std::string, std::string>;

TomlMap parse_toml_simple(const std::string& content) {
    TomlMap result;
    std::string current_section;
    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line)) {
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        // Section header: [section] or [section.subsection]
        if (line.front() == '[' && line.back() == ']') {
            current_section = line.substr(1, line.size() - 2);
            current_section = trim(current_section);
            continue;
        }

        // Key = value
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        auto key = trim(line.substr(0, eq));
        auto value = trim(line.substr(eq + 1));
        value = unquote(value);

        // Build fully qualified key
        std::string fqkey = current_section.empty() ? key : current_section + "." + key;
        result[fqkey] = value;
    }

    return result;
}

std::string get(const TomlMap& m, const std::string& key, const std::string& def = "") {
    auto it = m.find(key);
    return it != m.end() ? it->second : def;
}

int get_int(const TomlMap& m, const std::string& key, int def = 0) {
    auto it = m.find(key);
    if (it == m.end()) return def;
    try { return std::stoi(it->second); } catch (...) { return def; }
}

bool get_bool(const TomlMap& m, const std::string& key, bool def = false) {
    auto it = m.find(key);
    if (it == m.end()) return def;
    return it->second == "true" || it->second == "1";
}

modes::BridgeRelay::Distribution parse_distribution(const std::string& s) {
    if (s == "https") return modes::BridgeRelay::Distribution::Https;
    if (s == "email") return modes::BridgeRelay::Distribution::Email;
    if (s == "moat") return modes::BridgeRelay::Distribution::Moat;
    if (s == "any") return modes::BridgeRelay::Distribution::Any;
    return modes::BridgeRelay::Distribution::None;
}

}  // namespace

// --- Config implementation ---

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

    auto m = parse_toml_simple(toml_content);

    // [relay]
    auto nickname = get(m, "relay.nickname");
    if (!nickname.empty()) config.relay.nickname = nickname;

    auto mode_str = get(m, "relay.mode");
    if (!mode_str.empty()) {
        auto mode_result = modes::parse_relay_mode(mode_str);
        if (mode_result) {
            config.relay.mode = *mode_result;
        }
    }

    auto or_port = get_int(m, "relay.or_port", 0);
    if (or_port > 0) config.relay.or_port = static_cast<uint16_t>(or_port);

    auto dir_port = get_int(m, "relay.dir_port", -1);
    if (dir_port >= 0) config.relay.dir_port = static_cast<uint16_t>(dir_port);

    auto contact = get(m, "relay.contact");
    if (!contact.empty()) config.relay.contact_info = contact;

    auto address = get(m, "relay.address");
    if (!address.empty()) config.relay.address = address;

    // bind_address is handled at runtime (listener always binds to 0.0.0.0);
    // it should NOT overwrite the public-facing address used in bridge lines
    (void)get(m, "relay.bind_address");

    // [relay.bandwidth]
    auto bw_rate = get_int(m, "relay.bandwidth.rate", 0);
    auto bw_burst = get_int(m, "relay.bandwidth.burst", 0);
    if (bw_rate > 0) {
        config.relay.bandwidth.rate = static_cast<uint64_t>(bw_rate);
    }
    if (bw_burst > 0) {
        config.relay.bandwidth.burst = static_cast<uint64_t>(bw_burst);
    }

    // [bridge]
    auto distribution = get(m, "bridge.distribution");
    if (!distribution.empty()) {
        config.bridge.distribution = parse_distribution(distribution);
    }

    // [bridge.transport]
    auto transport_type = get(m, "bridge.transport.type");
    if (!transport_type.empty()) {
        config.bridge.transport = transport_type;
    }

    auto transport_port = get_int(m, "bridge.transport.port", 0);
    if (transport_port > 0) {
        config.bridge.transport_port = static_cast<uint16_t>(transport_port);
    }

    auto iat_mode = get_int(m, "bridge.transport.iat_mode", 0);
    config.bridge.iat_mode = static_cast<uint8_t>(iat_mode);

    // [directory]
    auto publish = get(m, "directory.publish_server_descriptor");
    if (!publish.empty()) {
        config.directory.publish_server_descriptor = (publish == "true" || publish == "1");
    }

    auto fetch_interval = get_int(m, "directory.fetch_interval", 0);
    if (fetch_interval > 0) {
        config.directory.publish_interval = std::chrono::seconds(fetch_interval);
    }

    // [logging]
    auto log_level = get(m, "logging.level");
    if (!log_level.empty()) config.logging.level = log_level;

    auto log_file = get(m, "logging.file");
    if (!log_file.empty()) config.logging.log_file = log_file;

    // [data]
    auto data_dir = get(m, "data.directory");
    if (!data_dir.empty()) config.relay.data_dir = data_dir;

    // [network]
    auto connect_timeout = get_int(m, "network.connect_timeout", 0);
    (void)connect_timeout;  // Stored in relay runtime, not config

    // [security]
    auto sandbox = get_bool(m, "security.sandbox", false);
    config.security.sandbox_enabled = sandbox;

    auto secure_memory = get_bool(m, "security.secure_memory", true);
    (void)secure_memory;  // Applied at runtime

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
    // CLI arg parsing is handled in main.cpp
    (void)argc;
    (void)argv;
}

policy::ExitPolicy Config::effective_exit_policy() const {
    if (relay.mode == modes::RelayMode::Exit) {
        return exit.exit_policy;
    }
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
