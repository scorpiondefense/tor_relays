#pragma once

#include "tor/core/cell.hpp"
#include "tor/core/channel.hpp"
#include "tor/core/circuit.hpp"
#include "tor/modes/relay_behavior.hpp"
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

// Forward declarations
namespace tor::util {
class Config;
}

namespace tor::core {

// Version information
struct VersionInfo {
    static constexpr uint8_t MAJOR = 1;
    static constexpr uint8_t MINOR = 0;
    static constexpr uint8_t PATCH = 0;

    [[nodiscard]] static std::string to_string() {
        return std::to_string(MAJOR) + "." +
               std::to_string(MINOR) + "." +
               std::to_string(PATCH);
    }
};

// Relay error types
enum class RelayError {
    ConfigError,
    KeyGenerationFailed,
    BindFailed,
    TlsInitFailed,
    StartFailed,
    StopFailed,
    AlreadyRunning,
    NotRunning,
    ModeSwitchFailed,
    DirectoryError,
    InternalError,
};

// Main relay class
class Relay {
public:
    Relay();
    ~Relay();

    // Non-copyable, movable
    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;
    Relay(Relay&&) noexcept;
    Relay& operator=(Relay&&) noexcept;

    // Start the relay (begin accepting connections)
    [[nodiscard]] std::expected<void, RelayError> start();

    // Stop the relay (graceful shutdown)
    [[nodiscard]] std::expected<void, RelayError> stop();

    // Check if the relay is running
    [[nodiscard]] bool is_running() const { return running_; }

    // Switch relay mode at runtime
    [[nodiscard]] std::expected<void, RelayError>
    switch_mode(modes::RelayMode new_mode);

    // Get current mode
    [[nodiscard]] modes::RelayMode mode() const;

    // Get channel manager
    [[nodiscard]] std::shared_ptr<ChannelManager> channel_manager() const {
        return channel_manager_;
    }

    // Get relay behavior
    [[nodiscard]] modes::RelayBehavior* behavior() const {
        return behavior_.get();
    }

private:
    friend class RelayBuilder;

    bool running_{false};
    util::Config* config_{nullptr};
    std::unique_ptr<util::Config> owned_config_;

    std::shared_ptr<ChannelManager> channel_manager_;
    std::unique_ptr<modes::RelayBehavior> behavior_;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Builder for creating a Relay
class RelayBuilder {
public:
    RelayBuilder() = default;
    ~RelayBuilder() = default;

    // Set configuration
    RelayBuilder& config(util::Config& cfg);

    // Build the relay
    [[nodiscard]] std::expected<std::unique_ptr<Relay>, RelayError> build();

private:
    util::Config* config_{nullptr};
};

// Utility
[[nodiscard]] std::string relay_error_message(RelayError err);

}  // namespace tor::core
