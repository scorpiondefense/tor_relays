#pragma once

#include "tor/modes/relay_behavior.hpp"
#include "tor/policy/exit_policy.hpp"
#include "tor/net/connection.hpp"
#include <memory>
#include <unordered_map>
#include <mutex>

namespace tor::modes {

// Exit relay mode - terminates circuits to the internet
// This mode allows:
// - Exit traffic based on configured exit policy
// - DNS resolution
// - Stream creation to allowed destinations
// - Published in directory with exit policy
class ExitRelay : public RelayBehavior {
public:
    ExitRelay();
    explicit ExitRelay(const Config* config);
    ~ExitRelay() override = default;

    // RelayBehavior interface
    [[nodiscard]] RelayMode mode() const override { return RelayMode::Exit; }
    [[nodiscard]] std::string mode_name() const override { return "Exit"; }

    [[nodiscard]] bool allows_operation(RelayOperation op) const override;

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_relay_cell(
        std::shared_ptr<core::Circuit> circuit,
        core::RelayCell& cell
    ) override;

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_begin(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& begin_cell
    ) override;

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_extend(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& extend_cell
    ) override;

    [[nodiscard]] std::string descriptor_additions() const override;

    [[nodiscard]] std::expected<void, std::string> validate_config() const override;

    // Exit policy management
    void set_exit_policy(policy::ExitPolicy policy) { exit_policy_ = std::move(policy); }
    [[nodiscard]] const policy::ExitPolicy& exit_policy() const { return exit_policy_; }

    // Use reduced exit policy (common web ports only)
    void use_reduced_policy();

    // Check if destination is allowed
    [[nodiscard]] bool allows_exit(const std::string& address, uint16_t port) const;

    // Set channel manager for circuit extension
    void set_channel_manager(std::shared_ptr<core::ChannelManager> manager) {
        channel_manager_ = std::move(manager);
    }

    // Statistics
    [[nodiscard]] uint64_t streams_opened() const { return streams_opened_; }
    [[nodiscard]] uint64_t streams_rejected() const { return streams_rejected_; }
    [[nodiscard]] uint64_t bytes_exited() const { return bytes_exited_; }

private:
    const Config* config_{nullptr};
    policy::ExitPolicy exit_policy_;
    std::shared_ptr<core::ChannelManager> channel_manager_;

    // Active exit connections (stream_id -> connection)
    struct ExitConnection {
        core::StreamId stream_id;
        core::CircuitId circuit_id;
        std::unique_ptr<net::TcpConnection> connection;
        std::string address;
        uint16_t port;
    };
    std::unordered_map<core::StreamId, std::shared_ptr<ExitConnection>> exit_connections_;
    mutable std::mutex connections_mutex_;

    // Statistics
    std::atomic<uint64_t> streams_opened_{0};
    std::atomic<uint64_t> streams_rejected_{0};
    std::atomic<uint64_t> bytes_exited_{0};

    // Internal handlers
    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_data(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& cell
    );

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_end(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& cell
    );

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_resolve(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& cell
    );

    // Connect to external host
    [[nodiscard]] std::expected<std::shared_ptr<ExitConnection>, core::CircuitError>
    connect_external(
        core::StreamId stream_id,
        core::CircuitId circuit_id,
        const std::string& address,
        uint16_t port
    );

    // Send data to external connection
    [[nodiscard]] std::expected<void, core::CircuitError>
    send_external(
        std::shared_ptr<ExitConnection> conn,
        std::span<const uint8_t> data
    );

    // Parse BEGIN cell address:port
    [[nodiscard]] std::expected<std::pair<std::string, uint16_t>, core::CircuitError>
    parse_begin_address(const core::RelayCell& begin_cell) const;
};

}  // namespace tor::modes
