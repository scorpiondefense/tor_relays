#include "tor/modes/middle_relay.hpp"
#include "tor/modes/bridge_relay.hpp"
#include "tor/modes/exit_relay.hpp"
#include "tor/modes/guard_relay.hpp"
#include "tor/util/config.hpp"

namespace tor::modes {

MiddleRelay::MiddleRelay() = default;

MiddleRelay::MiddleRelay(const ::tor::util::Config* config) : config_(config) {}

bool MiddleRelay::allows_operation(RelayOperation op) const {
    switch (op) {
        case RelayOperation::ForwardRelay:
            return true;  // Primary function
        case RelayOperation::CreateStreams:
            return false; // No exit streams
        case RelayOperation::ExitToInternet:
            return false; // No exit traffic
        case RelayOperation::ResolveDns:
            return false; // No DNS
        case RelayOperation::BeginDir:
            return true;  // Directory connections OK
        case RelayOperation::PublishDescriptor:
            return true;  // Published in directory
        case RelayOperation::AcceptRendezvous:
            return true;  // Can participate in HS circuits
        default:
            return false;
    }
}

std::expected<void, core::CircuitError>
MiddleRelay::handle_relay_cell(
    std::shared_ptr<core::Circuit> circuit,
    core::RelayCell& cell
) {
    // For middle relay, most relay cells are forwarded
    switch (cell.command) {
        case core::RelayCommand::EXTEND2:
            return handle_extend(circuit, cell);

        case core::RelayCommand::EXTENDED2:
        case core::RelayCommand::DATA:
        case core::RelayCommand::END:
        case core::RelayCommand::CONNECTED:
        case core::RelayCommand::SENDME:
        case core::RelayCommand::TRUNCATE:
        case core::RelayCommand::TRUNCATED:
            // Forward to appropriate hop
            return forward_to_next_hop(circuit, cell);

        case core::RelayCommand::BEGIN:
        case core::RelayCommand::RESOLVE:
            // Middle relay doesn't handle these - reject
            return std::unexpected(core::CircuitError::CellProcessingFailed);

        default:
            // Forward unknown cells
            return forward_to_next_hop(circuit, cell);
    }
}

std::expected<void, core::CircuitError>
MiddleRelay::handle_begin(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& begin_cell
) {
    // Middle relay does not handle BEGIN cells
    // Send END cell with EXITPOLICY reason
    return std::unexpected(core::CircuitError::CellProcessingFailed);
}

std::expected<void, core::CircuitError>
MiddleRelay::handle_extend(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& extend_cell
) {
    if (!channel_manager_) {
        return std::unexpected(core::CircuitError::InvalidState);
    }

    // Parse EXTEND2 cell to get next hop info
    // Connect to next hop and forward CREATE2
    // This would involve:
    // 1. Parse link specifiers from extend_cell
    // 2. Connect to next hop
    // 3. Send CREATE2 with handshake data
    // 4. Wait for CREATED2
    // 5. Send EXTENDED2 back to origin

    return {};
}

std::string MiddleRelay::descriptor_additions() const {
    // Middle relay doesn't add special descriptor fields
    return "";
}

std::expected<void, std::string> MiddleRelay::validate_config() const {
    // Middle relay configuration is always valid
    return {};
}

std::expected<void, core::CircuitError>
MiddleRelay::forward_to_next_hop(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& cell
) {
    auto next_channel = circuit->next_hop_channel();
    if (!next_channel) {
        return std::unexpected(core::CircuitError::CircuitNotFound);
    }

    // Encrypt for next hop and send
    auto encrypted = circuit->encrypt_relay(cell);
    if (!encrypted) {
        return std::unexpected(encrypted.error());
    }

    auto send_result = next_channel->send(*encrypted);
    if (!send_result) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    return {};
}

std::expected<void, core::CircuitError>
MiddleRelay::forward_to_prev_hop(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& cell
) {
    auto prev_channel = circuit->prev_hop_channel();
    if (!prev_channel) {
        return std::unexpected(core::CircuitError::CircuitNotFound);
    }

    auto encrypted = circuit->encrypt_relay(cell);
    if (!encrypted) {
        return std::unexpected(encrypted.error());
    }

    auto send_result = prev_channel->send(*encrypted);
    if (!send_result) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    return {};
}

// Factory function
std::unique_ptr<RelayBehavior> create_behavior(RelayMode mode, const ::tor::util::Config* config) {
    switch (mode) {
        case RelayMode::Middle:
            return std::make_unique<MiddleRelay>(config);
        case RelayMode::Exit:
            return std::make_unique<ExitRelay>(config);
        case RelayMode::Bridge:
            return std::make_unique<BridgeRelay>(config);
        case RelayMode::Guard:
            return std::make_unique<GuardRelay>(config);
        default:
            return std::make_unique<MiddleRelay>(config);
    }
}

std::expected<RelayMode, std::string> parse_relay_mode(const std::string& str) {
    if (str == "middle" || str == "Middle" || str == "MIDDLE") {
        return RelayMode::Middle;
    }
    if (str == "exit" || str == "Exit" || str == "EXIT") {
        return RelayMode::Exit;
    }
    if (str == "bridge" || str == "Bridge" || str == "BRIDGE") {
        return RelayMode::Bridge;
    }
    if (str == "guard" || str == "Guard" || str == "GUARD") {
        return RelayMode::Guard;
    }
    return std::unexpected("Unknown relay mode: " + str);
}

}  // namespace tor::modes
