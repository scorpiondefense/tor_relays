#include "tor/core/relay.hpp"
#include "tor/net/acceptor.hpp"
#include "tor/util/config.hpp"
#include "tor/util/logging.hpp"
#include <thread>

namespace tor::core {

// --- Relay implementation details ---

struct Relay::Impl {
    boost::asio::io_context io_context;
    std::unique_ptr<net::TcpAcceptor> acceptor;
    std::jthread io_thread;
};

// --- Relay ---

Relay::Relay()
    : channel_manager_(std::make_shared<ChannelManager>()) {}

Relay::~Relay() {
    if (running_) {
        auto result = stop();
        (void)result;  // Best-effort shutdown
    }
}

Relay::Relay(Relay&&) noexcept = default;
Relay& Relay::operator=(Relay&&) noexcept = default;

std::expected<void, RelayError> Relay::start() {
    if (running_) {
        return std::unexpected(RelayError::AlreadyRunning);
    }

    if (!config_) {
        return std::unexpected(RelayError::ConfigError);
    }

    // Create behavior based on mode
    behavior_ = modes::create_behavior(config_->relay.mode, config_);
    if (!behavior_) {
        return std::unexpected(RelayError::InternalError);
    }

    // Initialize networking
    impl_ = std::make_unique<Impl>();
    impl_->acceptor = std::make_unique<net::TcpAcceptor>(impl_->io_context);

    auto listen_result = impl_->acceptor->listen("0.0.0.0", config_->relay.or_port);
    if (!listen_result) {
        return std::unexpected(RelayError::BindFailed);
    }

    // Start accept loop in background thread
    impl_->acceptor->start_accept_loop([](auto /*result*/) {
        // Connection handling will be implemented as protocol layers mature
    });

    impl_->io_thread = std::jthread([this](std::stop_token) {
        auto work_guard = boost::asio::make_work_guard(impl_->io_context);
        impl_->io_context.run();
    });

    running_ = true;
    return {};
}

std::expected<void, RelayError> Relay::stop() {
    if (!running_) {
        return std::unexpected(RelayError::NotRunning);
    }

    // Stop acceptor and io_context
    if (impl_) {
        if (impl_->acceptor) {
            impl_->acceptor->close();
        }
        impl_->io_context.stop();
        if (impl_->io_thread.joinable()) {
            impl_->io_thread.join();
        }
    }

    // Close all channels
    channel_manager_->close_all();

    running_ = false;
    return {};
}

std::expected<void, RelayError>
Relay::switch_mode(modes::RelayMode new_mode) {
    if (!running_) {
        return std::unexpected(RelayError::NotRunning);
    }

    auto new_behavior = modes::create_behavior(new_mode, config_);
    if (!new_behavior) {
        return std::unexpected(RelayError::ModeSwitchFailed);
    }

    auto validate_result = new_behavior->validate_config();
    if (!validate_result) {
        return std::unexpected(RelayError::ConfigError);
    }

    behavior_ = std::move(new_behavior);
    return {};
}

modes::RelayMode Relay::mode() const {
    if (behavior_) {
        return behavior_->mode();
    }
    return modes::RelayMode::Middle;
}

// --- RelayBuilder ---

RelayBuilder& RelayBuilder::config(util::Config& cfg) {
    config_ = &cfg;
    return *this;
}

std::expected<std::unique_ptr<Relay>, RelayError> RelayBuilder::build() {
    if (!config_) {
        return std::unexpected(RelayError::ConfigError);
    }

    auto relay = std::make_unique<Relay>();
    relay->config_ = config_;

    return relay;
}

// --- Utility ---

std::string relay_error_message(RelayError err) {
    switch (err) {
        case RelayError::ConfigError:          return "Configuration error";
        case RelayError::KeyGenerationFailed:  return "Key generation failed";
        case RelayError::BindFailed:           return "Failed to bind to port";
        case RelayError::TlsInitFailed:        return "TLS initialization failed";
        case RelayError::StartFailed:          return "Failed to start relay";
        case RelayError::StopFailed:           return "Failed to stop relay";
        case RelayError::AlreadyRunning:       return "Relay is already running";
        case RelayError::NotRunning:           return "Relay is not running";
        case RelayError::ModeSwitchFailed:     return "Failed to switch relay mode";
        case RelayError::DirectoryError:       return "Directory operation failed";
        case RelayError::InternalError:        return "Internal error";
        default:                               return "Unknown relay error";
    }
}

}  // namespace tor::core
