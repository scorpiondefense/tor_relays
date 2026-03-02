#include "tor/core/relay.hpp"
#include "tor/crypto/key_store.hpp"
#include "tor/crypto/tls.hpp"
#include "tor/modes/bridge_relay.hpp"
#include "tor/net/acceptor.hpp"
#include "tor/protocol/link_protocol.hpp"
#include "tor/transport/obfs4_listener.hpp"
#include "tor/util/config.hpp"
#include "tor/util/logging.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <thread>

namespace tor::core {

// --- Relay implementation details ---

struct Relay::Impl {
    boost::asio::io_context io_context;
    crypto::TlsContext tls_ctx;
    std::vector<uint8_t> tls_cert_der;
    std::unique_ptr<net::TlsAcceptor> or_acceptor;
    std::unique_ptr<transport::Obfs4Listener> obfs4_listener;
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

    // Load or generate identity keys
    if (!config_->relay.data_dir.empty()) {
        crypto::KeyStore key_store(config_->relay.data_dir);

        auto keys_result = key_store.load_or_generate();
        if (!keys_result) {
            LOG_ERROR("Failed to load/generate keys: {}",
                      crypto::key_store_error_message(keys_result.error()));
            return std::unexpected(RelayError::KeyGenerationFailed);
        }

        fingerprint_ = crypto::NodeId(keys_result->identity_key.public_key());

        auto fp_result = key_store.write_fingerprint(
            config_->relay.nickname, fingerprint_);
        if (!fp_result) {
            LOG_WARN("Failed to write fingerprint file: {}",
                     crypto::key_store_error_message(fp_result.error()));
        }

        LOG_INFO("Relay fingerprint: {}", fingerprint_.to_hex());

        keys_ = std::make_unique<crypto::RelayKeyPair>(std::move(*keys_result));
    }

    // Initialize networking
    impl_ = std::make_unique<Impl>();

    // Generate self-signed TLS certificate
    if (!keys_) {
        LOG_ERROR("No identity keys available for TLS certificate generation");
        return std::unexpected(RelayError::KeyGenerationFailed);
    }

    auto cert_result = crypto::TlsContext::generate_self_signed_cert(keys_->identity_key);
    if (!cert_result) {
        LOG_ERROR("Failed to generate self-signed TLS certificate");
        return std::unexpected(RelayError::TlsInitFailed);
    }

    auto& [cert_pem, key_pem] = *cert_result;

    // Convert PEM certificate to DER for CERTS cell
    {
        BIO* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
        X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (x509) {
            int der_len = i2d_X509(x509, nullptr);
            if (der_len > 0) {
                impl_->tls_cert_der.resize(static_cast<size_t>(der_len));
                unsigned char* p = impl_->tls_cert_der.data();
                i2d_X509(x509, &p);
            }
            X509_free(x509);
        }

        if (impl_->tls_cert_der.empty()) {
            LOG_ERROR("Failed to convert TLS certificate to DER format");
            return std::unexpected(RelayError::TlsInitFailed);
        }
    }

    // Initialize TLS context with the generated certificate
    auto tls_init = impl_->tls_ctx.init_server(cert_pem, key_pem);
    if (!tls_init) {
        LOG_ERROR("Failed to initialize TLS context");
        return std::unexpected(RelayError::TlsInitFailed);
    }

    LOG_INFO("TLS context initialized with self-signed certificate");

    // Create TLS acceptor for OR port
    impl_->or_acceptor = std::make_unique<net::TlsAcceptor>(
        impl_->io_context, impl_->tls_ctx);

    auto listen_result = impl_->or_acceptor->listen("0.0.0.0", config_->relay.or_port);
    if (!listen_result) {
        return std::unexpected(RelayError::BindFailed);
    }

    LOG_INFO("OR port listening on 0.0.0.0:{} with TLS", config_->relay.or_port);

    // Start TLS accept loop with real connection handler
    auto keys_ptr = keys_.get();
    auto tls_cert_der_ref = &impl_->tls_cert_der;
    auto channel_mgr = channel_manager_;

    impl_->or_acceptor->start_accept_loop(
        [keys_ptr, tls_cert_der_ref, channel_mgr](auto result) {
        if (!result) {
            LOG_WARN("OR: TLS accept/handshake failed");
            return;
        }

        auto tls_conn = *result;
        LOG_INFO("OR: accepted TLS connection from {}:{}",
                 tls_conn->remote_address(), tls_conn->remote_port());

        // Create channel with TLS connection
        auto channel = std::make_shared<Channel>();
        channel->set_connection(tls_conn);
        channel->set_tls_cert_der(*tls_cert_der_ref);

        // Run link handshake + cell loop in a dedicated thread
        std::thread([channel, keys_ptr, channel_mgr]() {
            LOG_INFO("OR: starting link protocol handshake");

            protocol::LinkProtocolHandler handler;
            auto hs_result = handler.handshake_as_responder(
                *channel,
                keys_ptr->identity_key,
                keys_ptr->identity_key.public_key());

            if (!hs_result) {
                LOG_WARN("OR: link handshake failed: {}",
                         protocol::link_protocol_error_message(hs_result.error()));
                channel->close();
                return;
            }

            LOG_INFO("OR: link protocol handshake completed (v{})",
                     channel->link_version());
            channel->set_state(ChannelState::Open);

            // Cell processing loop
            while (channel->is_open()) {
                auto cell = channel->receive_any();
                if (!cell) {
                    LOG_INFO("OR: connection closed");
                    break;
                }

                auto& [is_var, fixed, var] = *cell;
                if (is_var) {
                    if (var.command != CellCommand::VPADDING) {
                        LOG_INFO("OR: variable cell cmd={}",
                                 cell_command_name(var.command));
                    }
                } else {
                    if (fixed.command == CellCommand::PADDING) {
                        continue;
                    }

                    LOG_INFO("OR: cell cmd={} circ={}",
                             cell_command_name(fixed.command),
                             fixed.circuit_id);

                    if (fixed.command == CellCommand::CREATE2) {
                        // Circuit creation not yet implemented -
                        // respond with DESTROY so client moves on
                        Cell destroy(fixed.circuit_id, CellCommand::DESTROY);
                        destroy.payload[0] = static_cast<uint8_t>(
                            DestroyReason::INTERNAL);
                        auto send_res = channel->send(destroy);
                        if (!send_res) {
                            LOG_WARN("OR: failed to send DESTROY");
                        }
                        LOG_WARN("OR: CREATE2 not yet implemented, sent DESTROY");
                    }
                }
            }

            channel->close();
            LOG_INFO("OR: connection handler thread exiting");
        }).detach();
    });

    // Start obfs4 listener for bridge mode with transport enabled
    if (config_->relay.mode == modes::RelayMode::Bridge &&
        config_->bridge.transport == "obfs4" && keys_) {

        auto iat = static_cast<transport::IatMode>(config_->bridge.iat_mode);
        impl_->obfs4_listener = std::make_unique<transport::Obfs4Listener>(
            impl_->io_context, fingerprint_, keys_->onion_key, iat);
        impl_->obfs4_listener->set_or_port(config_->relay.or_port);

        auto obfs4_result = impl_->obfs4_listener->start(
            "0.0.0.0", config_->bridge.transport_port);
        if (!obfs4_result) {
            LOG_ERROR("Failed to start obfs4 listener on port {}",
                      config_->bridge.transport_port);
            // Non-fatal: bridge still works on OR port without obfs4
        } else {
            LOG_INFO("obfs4 transport listening on port {}",
                     config_->bridge.transport_port);

            // Set obfs4 cert on bridge behavior
            auto* bridge = dynamic_cast<modes::BridgeRelay*>(behavior_.get());
            if (bridge) {
                bridge->set_obfs4_cert(impl_->obfs4_listener->cert());
            }
        }
    }

    // Log bridge line for bridge mode
    if (config_->relay.mode == modes::RelayMode::Bridge) {
        auto* bridge = dynamic_cast<modes::BridgeRelay*>(behavior_.get());
        if (bridge) {
            LOG_INFO("Bridge line: {}", bridge->bridge_line());
        }
    }

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

    LOG_INFO("Shutdown requested, stopping relay...");

    // Stop obfs4 listener and acceptor
    if (impl_) {
        if (impl_->obfs4_listener) {
            impl_->obfs4_listener->stop();
        }
        if (impl_->or_acceptor) {
            impl_->or_acceptor->close();
        }
        impl_->io_context.stop();
        if (impl_->io_thread.joinable()) {
            impl_->io_thread.join();
        }
    }

    // Close all channels
    channel_manager_->close_all();

    running_ = false;
    LOG_INFO("Relay stopped");
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
