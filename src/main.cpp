#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>
#include <filesystem>

#include "tor/core/relay.hpp"
#include "tor/util/config.hpp"
#include "tor/util/logging.hpp"
#include "tor/modes/relay_behavior.hpp"

namespace {

std::atomic<bool> g_shutdown_requested{false};
std::atomic<bool> g_reload_requested{false};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested = true;
    } else if (signal == SIGHUP) {
        g_reload_requested = true;
    }
}

void setup_signal_handlers() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGHUP, signal_handler);
    std::signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe
}

struct CommandLineArgs {
    std::string config_file;
    std::optional<tor::modes::RelayMode> mode;
    std::optional<uint16_t> or_port;
    std::optional<uint16_t> dir_port;
    std::string nickname;
    std::string data_dir;
    bool foreground{false};
    bool help{false};
    bool version{false};
    tor::util::LogLevel log_level{tor::util::LogLevel::Info};
};

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Tor Relay Implementation - C++20\n\n"
              << "Options:\n"
              << "  -c, --config FILE     Configuration file path\n"
              << "  -m, --mode MODE       Relay mode: middle, exit, bridge, guard (default: middle)\n"
              << "  -p, --port PORT       OR port to listen on (default: 9001)\n"
              << "  -d, --dir-port PORT   Directory port (default: 0 = disabled)\n"
              << "  -n, --nickname NAME   Relay nickname\n"
              << "  --data-dir DIR        Data directory for keys and state\n"
              << "  -f, --foreground      Run in foreground (don't daemonize)\n"
              << "  -l, --log-level LEVEL Log level: trace, debug, info, warn, error (default: info)\n"
              << "  -h, --help            Show this help message\n"
              << "  -v, --version         Show version information\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --mode middle --port 9001\n"
              << "  " << program_name << " --mode exit --port 9001 --config /etc/tor/relay.toml\n"
              << "  " << program_name << " --mode bridge --port 443\n"
              << "  " << program_name << " --mode guard --port 9001\n"
              << "\n"
              << "Modes:\n"
              << "  middle   Forward relay cells only (default, safest)\n"
              << "  exit     Connect to external hosts (requires exit policy)\n"
              << "  bridge   Unpublished entry point for censored users\n"
              << "  guard    Entry guard - first hop for client circuits\n";
}

void print_version() {
    std::cout << "Tor Relay Implementation v" << static_cast<int>(tor::core::VersionInfo::MAJOR) << "."
              << static_cast<int>(tor::core::VersionInfo::MINOR) << "." << static_cast<int>(tor::core::VersionInfo::PATCH) << "\n"
              << "Built with C++20, OpenSSL 3.x, Boost.Asio\n"
              << "Protocol versions: 4, 5\n";
}

std::optional<CommandLineArgs> parse_args(int argc, char* argv[]) {
    CommandLineArgs args;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            args.help = true;
            return args;
        }

        if (arg == "-v" || arg == "--version") {
            args.version = true;
            return args;
        }

        if (arg == "-f" || arg == "--foreground") {
            args.foreground = true;
            continue;
        }

        // Options that require a value
        if (i + 1 >= argc) {
            std::cerr << "Error: Option " << arg << " requires a value\n";
            return std::nullopt;
        }

        std::string value = argv[++i];

        if (arg == "-c" || arg == "--config") {
            args.config_file = value;
        } else if (arg == "-m" || arg == "--mode") {
            auto mode_result = tor::modes::parse_relay_mode(value);
            if (!mode_result) {
                std::cerr << "Error: Invalid mode '" << value << "'. Use: middle, exit, bridge, or guard\n";
                return std::nullopt;
            }
            args.mode = mode_result.value();
        } else if (arg == "-p" || arg == "--port") {
            try {
                int port = std::stoi(value);
                if (port <= 0 || port > 65535) {
                    throw std::out_of_range("port");
                }
                args.or_port = static_cast<uint16_t>(port);
            } catch (...) {
                std::cerr << "Error: Invalid port number '" << value << "'\n";
                return std::nullopt;
            }
        } else if (arg == "-d" || arg == "--dir-port") {
            try {
                int port = std::stoi(value);
                if (port < 0 || port > 65535) {
                    throw std::out_of_range("port");
                }
                args.dir_port = static_cast<uint16_t>(port);
            } catch (...) {
                std::cerr << "Error: Invalid directory port number '" << value << "'\n";
                return std::nullopt;
            }
        } else if (arg == "-n" || arg == "--nickname") {
            args.nickname = value;
        } else if (arg == "--data-dir") {
            args.data_dir = value;
        } else if (arg == "-l" || arg == "--log-level") {
            if (value == "trace") {
                args.log_level = tor::util::LogLevel::Trace;
            } else if (value == "debug") {
                args.log_level = tor::util::LogLevel::Debug;
            } else if (value == "info") {
                args.log_level = tor::util::LogLevel::Info;
            } else if (value == "warn" || value == "warning") {
                args.log_level = tor::util::LogLevel::Warn;
            } else if (value == "error") {
                args.log_level = tor::util::LogLevel::Error;
            } else {
                std::cerr << "Error: Invalid log level '" << value << "'\n";
                return std::nullopt;
            }
        } else {
            std::cerr << "Error: Unknown option '" << arg << "'\n";
            return std::nullopt;
        }
    }

    return args;
}

tor::util::Config create_config(const CommandLineArgs& args) {
    tor::util::Config config;

    // If config file specified, load it first
    if (!args.config_file.empty()) {
        auto result = tor::util::Config::load_from_file(args.config_file);
        if (result) {
            config = std::move(*result);
        } else {
            std::cerr << "Warning: Failed to load config file, using defaults\n";
        }
    }

    // Override with command-line arguments (only if explicitly provided)
    if (args.mode) config.relay.mode = *args.mode;
    if (args.or_port) config.relay.or_port = *args.or_port;
    if (args.dir_port) config.relay.dir_port = *args.dir_port;

    if (!args.nickname.empty()) {
        config.relay.nickname = args.nickname;
    }

    if (!args.data_dir.empty()) {
        config.relay.data_dir = args.data_dir;
    }

    return config;
}

void ensure_data_directory(const std::string& path) {
    std::filesystem::path dir(path);
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    auto args_result = parse_args(argc, argv);
    if (!args_result) {
        print_usage(argv[0]);
        return 1;
    }

    const auto& args = *args_result;

    if (args.help) {
        print_usage(argv[0]);
        return 0;
    }

    if (args.version) {
        print_version();
        return 0;
    }

    // Setup logging
    auto& logger = tor::util::global_logger();
    logger.set_level(args.log_level);
    logger.add_sink(std::make_shared<tor::util::ConsoleSink>());

    // Create configuration
    auto config = create_config(args);

    LOG_INFO("Starting Tor Relay...");
    LOG_INFO("Mode: {}", tor::modes::relay_mode_name(config.relay.mode));
    LOG_INFO("OR Port: {}", config.relay.or_port);
    if (!config.bridge.transport.empty()) {
        LOG_INFO("Transport: {} on port {}", config.bridge.transport, config.bridge.transport_port);
    }

    // Ensure data directory exists
    try {
        ensure_data_directory(config.relay.data_dir.string());
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create data directory: {}", e.what());
        return 1;
    }

    // Setup signal handlers
    setup_signal_handlers();

    // Build and start the relay
    try {
        auto relay_result = tor::core::RelayBuilder()
            .config(config)
            .build();

        if (!relay_result) {
            LOG_ERROR("Failed to build relay: {}", tor::core::relay_error_message(relay_result.error()));
            return 1;
        }

        auto relay = std::move(*relay_result);

        // Start the relay
        auto start_result = relay->start();
        if (!start_result) {
            LOG_ERROR("Failed to start relay: {}", tor::core::relay_error_message(start_result.error()));
            return 1;
        }

        LOG_INFO("Relay started successfully");
        LOG_INFO("Listening on port {}", config.relay.or_port);

        if (config.relay.dir_port > 0) {
            LOG_INFO("Directory port: {}", config.relay.dir_port);
        }

        // Main loop
        while (!g_shutdown_requested) {
            // Check for reload signal
            if (g_reload_requested.exchange(false)) {
                LOG_INFO("Reloading configuration...");
                if (!args.config_file.empty()) {
                    auto new_config_result = tor::util::Config::load_from_file(args.config_file);
                    if (new_config_result) {
                        auto switch_result = relay->switch_mode(new_config_result->relay.mode);
                        if (switch_result) {
                            LOG_INFO("Configuration reloaded successfully");
                        } else {
                            LOG_ERROR("Failed to reload config: {}", tor::core::relay_error_message(switch_result.error()));
                        }
                    } else {
                        LOG_ERROR("Failed to load config file");
                    }
                }
            }

            // Sleep briefly to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        LOG_INFO("Shutdown requested, stopping relay...");

        // Graceful shutdown
        auto stop_result = relay->stop();
        if (!stop_result) {
            LOG_ERROR("Error during shutdown: {}", tor::core::relay_error_message(stop_result.error()));
        }

        LOG_INFO("Relay stopped");

    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
