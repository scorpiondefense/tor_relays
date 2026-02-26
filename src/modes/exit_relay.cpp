#include "tor/modes/exit_relay.hpp"
#include "tor/util/config.hpp"
#include <sstream>

namespace tor::modes {

ExitRelay::ExitRelay() {
    exit_policy_ = policy::ExitPolicy::reject_all();
}

ExitRelay::ExitRelay(const ::tor::util::Config* config) : config_(config) {
    if (config_) {
        exit_policy_ = config_->exit.exit_policy;
        if (config_->exit.reduced_exit_policy) {
            use_reduced_policy();
        }
    } else {
        exit_policy_ = policy::ExitPolicy::reject_all();
    }
}

bool ExitRelay::allows_operation(RelayOperation op) const {
    switch (op) {
        case RelayOperation::ForwardRelay:
            return true;   // Also forwards relay cells
        case RelayOperation::CreateStreams:
            return true;   // Can create exit streams
        case RelayOperation::ExitToInternet:
            return true;   // Primary function
        case RelayOperation::ResolveDns:
            return true;   // DNS resolution for exit
        case RelayOperation::BeginDir:
            return true;   // Directory connections OK
        case RelayOperation::PublishDescriptor:
            return true;   // Published in directory with exit policy
        case RelayOperation::AcceptRendezvous:
            return true;   // Can participate in HS circuits
        default:
            return false;
    }
}

std::expected<void, core::CircuitError>
ExitRelay::handle_relay_cell(
    std::shared_ptr<core::Circuit> circuit,
    core::RelayCell& cell
) {
    switch (cell.command) {
        case core::RelayCommand::EXTEND2:
            return handle_extend(circuit, cell);

        case core::RelayCommand::BEGIN:
            return handle_begin(circuit, cell);

        case core::RelayCommand::DATA:
            return handle_data(circuit, cell);

        case core::RelayCommand::END:
            return handle_end(circuit, cell);

        case core::RelayCommand::RESOLVE:
            return handle_resolve(circuit, cell);

        case core::RelayCommand::EXTENDED2:
        case core::RelayCommand::CONNECTED:
        case core::RelayCommand::SENDME:
        case core::RelayCommand::TRUNCATE:
        case core::RelayCommand::TRUNCATED:
            // Forward to previous hop
            return {};

        default:
            return {};
    }
}

std::expected<void, core::CircuitError>
ExitRelay::handle_begin(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& begin_cell
) {
    auto addr_result = parse_begin_address(begin_cell);
    if (!addr_result) {
        streams_rejected_.fetch_add(1, std::memory_order_relaxed);
        return std::unexpected(addr_result.error());
    }

    auto& [address, port] = *addr_result;

    // Check exit policy
    if (!allows_exit(address, port)) {
        streams_rejected_.fetch_add(1, std::memory_order_relaxed);
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    streams_opened_.fetch_add(1, std::memory_order_relaxed);
    return {};
}

std::expected<void, core::CircuitError>
ExitRelay::handle_extend(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& extend_cell
) {
    if (!channel_manager_) {
        return std::unexpected(core::CircuitError::InvalidState);
    }

    // Parse EXTEND2 cell to get next hop info
    // Connect to next hop and forward CREATE2
    return {};
}

std::string ExitRelay::descriptor_additions() const {
    std::ostringstream oss;

    // Include exit policy in descriptor
    auto policy_str = exit_policy_.to_string();
    if (!policy_str.empty()) {
        oss << policy_str;
    }

    return oss.str();
}

std::expected<void, std::string> ExitRelay::validate_config() const {
    if (config_) {
        if (config_->relay.or_port == 0) {
            return std::unexpected("Exit relay requires a valid OR port");
        }
        // Exit relay should have at least one accept rule in its policy
        if (exit_policy_.is_empty() && !config_->exit.reduced_exit_policy) {
            return std::unexpected("Exit relay requires an exit policy");
        }
    }
    return {};
}

void ExitRelay::use_reduced_policy() {
    exit_policy_ = policy::ExitPolicy::reduced();
}

bool ExitRelay::allows_exit(const std::string& address, uint16_t port) const {
    return exit_policy_.allows(address, port);
}

std::expected<void, core::CircuitError>
ExitRelay::handle_data(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& cell
) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto it = exit_connections_.find(cell.stream_id);
    if (it == exit_connections_.end()) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    auto send_result = send_external(it->second,
        std::span<const uint8_t>(cell.data));
    if (!send_result) {
        return std::unexpected(send_result.error());
    }

    bytes_exited_.fetch_add(cell.data.size(), std::memory_order_relaxed);
    return {};
}

std::expected<void, core::CircuitError>
ExitRelay::handle_end(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& cell
) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    exit_connections_.erase(cell.stream_id);
    return {};
}

std::expected<void, core::CircuitError>
ExitRelay::handle_resolve(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& cell
) {
    // DNS resolution would be performed here
    // For now, indicate success
    return {};
}

std::expected<std::shared_ptr<ExitRelay::ExitConnection>, core::CircuitError>
ExitRelay::connect_external(
    core::StreamId stream_id,
    core::CircuitId circuit_id,
    const std::string& address,
    uint16_t port
) {
    auto conn = std::make_shared<ExitConnection>();
    conn->stream_id = stream_id;
    conn->circuit_id = circuit_id;
    conn->address = address;
    conn->port = port;

    // Actual TCP connection would be established here
    // conn->connection = ...

    std::lock_guard<std::mutex> lock(connections_mutex_);
    exit_connections_[stream_id] = conn;
    return conn;
}

std::expected<void, core::CircuitError>
ExitRelay::send_external(
    std::shared_ptr<ExitConnection> conn,
    std::span<const uint8_t> data
) {
    if (!conn || !conn->connection) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    auto write_result = conn->connection->write(data);
    if (!write_result) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    return {};
}

std::expected<std::pair<std::string, uint16_t>, core::CircuitError>
ExitRelay::parse_begin_address(const core::RelayCell& begin_cell) const {
    // BEGIN cell payload is "address:port\0"
    std::string payload(
        reinterpret_cast<const char*>(begin_cell.data.data()),
        begin_cell.data.size());

    // Remove null terminator if present
    if (!payload.empty() && payload.back() == '\0') {
        payload.pop_back();
    }

    auto colon_pos = payload.rfind(':');
    if (colon_pos == std::string::npos) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    std::string address = payload.substr(0, colon_pos);
    std::string port_str = payload.substr(colon_pos + 1);

    uint16_t port = 0;
    try {
        auto port_val = std::stoul(port_str);
        if (port_val > 65535) {
            return std::unexpected(core::CircuitError::CellProcessingFailed);
        }
        port = static_cast<uint16_t>(port_val);
    } catch (...) {
        return std::unexpected(core::CircuitError::CellProcessingFailed);
    }

    return std::make_pair(address, port);
}

}  // namespace tor::modes
