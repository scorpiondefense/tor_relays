#include "tor/modes/guard_relay.hpp"
#include "tor/util/config.hpp"
#include <functional>
#include <sstream>

namespace tor::modes {

GuardRelay::GuardRelay() {
    requirements_ = EligibilityRequirements::default_requirements();
}

GuardRelay::GuardRelay(const ::tor::util::Config* config) : config_(config) {
    requirements_ = EligibilityRequirements::default_requirements();

    if (config_) {
        // Apply config overrides for guard settings
        requirements_.min_uptime = config_->guard.min_uptime;
        requirements_.min_bandwidth = config_->guard.min_bandwidth;
        max_tracked_clients_ = config_->guard.max_tracked_clients;
    }
}

bool GuardRelay::allows_operation(RelayOperation op) const {
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
            return true;  // Published in directory (required for Guard flag)
        case RelayOperation::AcceptRendezvous:
            return true;  // Can participate in HS circuits
        default:
            return false;
    }
}

std::expected<void, core::CircuitError>
GuardRelay::handle_relay_cell(
    std::shared_ptr<core::Circuit> circuit,
    core::RelayCell& cell
) {
    // Track statistics
    stats_.cells_forwarded.fetch_add(1, std::memory_order_relaxed);

    // For guard relay, most relay cells are forwarded
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
            // Guard relay doesn't handle these - reject
            return std::unexpected(core::CircuitError::CellProcessingFailed);

        default:
            // Forward unknown cells
            return forward_to_next_hop(circuit, cell);
    }
}

std::expected<void, core::CircuitError>
GuardRelay::handle_begin(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& begin_cell
) {
    // Guard relay does not handle BEGIN cells
    // Send END cell with EXITPOLICY reason
    return std::unexpected(core::CircuitError::CellProcessingFailed);
}

std::expected<void, core::CircuitError>
GuardRelay::handle_extend(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& extend_cell
) {
    if (!channel_manager_) {
        return std::unexpected(core::CircuitError::InvalidState);
    }

    // Track this as a guard circuit (client is extending through us)
    stats_.circuits_as_guard.fetch_add(1, std::memory_order_relaxed);

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

std::string GuardRelay::descriptor_additions() const {
    std::ostringstream oss;

    // Add guard-specific descriptor fields
    auto duty_time = stats_.guard_duty_time();
    if (duty_time.count() > 0) {
        oss << "guard-uptime " << duty_time.count() << "\n";
    }

    oss << "guard-circuits " << stats_.circuits_as_guard.load() << "\n";
    oss << "guard-clients " << stats_.unique_clients.load() << "\n";

    return oss.str();
}

std::expected<void, std::string> GuardRelay::validate_config() const {
    // Guard relay configuration validation
    if (config_) {
        if (config_->guard.min_bandwidth == 0) {
            return std::unexpected("Guard relay requires minimum bandwidth > 0");
        }
        if (config_->guard.min_uptime.count() == 0) {
            return std::unexpected("Guard relay requires minimum uptime > 0");
        }
    }
    return {};
}

void GuardRelay::record_client(const std::string& client_id) {
    // Track clients by default; skip only if explicitly disabled in config
    if (config_ && !config_->guard.track_clients) {
        return;
    }

    size_t hash = hash_client_id(client_id);

    std::lock_guard<std::mutex> lock(clients_mutex_);

    // Limit tracked clients to prevent memory exhaustion
    if (client_hashes_.size() >= max_tracked_clients_) {
        // Remove oldest entries (simple strategy: clear half)
        auto it = client_hashes_.begin();
        size_t to_remove = max_tracked_clients_ / 2;
        for (size_t i = 0; i < to_remove && it != client_hashes_.end(); ++i) {
            it = client_hashes_.erase(it);
        }
    }

    auto [_, inserted] = client_hashes_.insert(hash);
    if (inserted) {
        stats_.unique_clients.fetch_add(1, std::memory_order_relaxed);
    }
}

bool GuardRelay::meets_guard_requirements() const {
    // Check uptime requirement
    auto duty_time = stats_.guard_duty_time();
    if (duty_time < requirements_.min_uptime) {
        return false;
    }

    // Bandwidth check would require integration with bandwidth manager
    // For now, we assume bandwidth requirements are met if we're running
    // Real implementation would check config_->relay.bandwidth

    return true;
}

void GuardRelay::start_guard_duty() {
    if (!stats_.guard_duty_active.exchange(true)) {
        stats_.guard_duty_start = std::chrono::steady_clock::now();
    }
}

std::expected<void, core::CircuitError>
GuardRelay::forward_to_next_hop(
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
GuardRelay::forward_to_prev_hop(
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

size_t GuardRelay::hash_client_id(const std::string& client_id) const {
    // Use std::hash for privacy-preserving client tracking
    // In production, would use a cryptographic hash with periodic rotation
    return std::hash<std::string>{}(client_id);
}

}  // namespace tor::modes
