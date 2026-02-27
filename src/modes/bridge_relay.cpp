#include "tor/modes/bridge_relay.hpp"
#include "tor/util/config.hpp"
#include <fstream>
#include <sstream>

namespace tor::modes {

BridgeRelay::BridgeRelay() = default;

BridgeRelay::BridgeRelay(const ::tor::util::Config* config) : config_(config) {
    if (config_) {
        distribution_ = config_->bridge.distribution;
        transport_name_ = config_->bridge.transport;
        bridge_authority_ = config_->bridge.bridge_authority;
    }
}

bool BridgeRelay::allows_operation(RelayOperation op) const {
    switch (op) {
        case RelayOperation::ForwardRelay:
            return true;   // Primary function
        case RelayOperation::CreateStreams:
            return false;  // No exit streams
        case RelayOperation::ExitToInternet:
            return false;  // No exit traffic
        case RelayOperation::ResolveDns:
            return false;  // No DNS
        case RelayOperation::BeginDir:
            return true;   // Directory connections OK
        case RelayOperation::PublishDescriptor:
            return false;  // Bridges don't publish to public directory
        case RelayOperation::AcceptRendezvous:
            return true;   // Can participate in HS circuits
        default:
            return false;
    }
}

std::expected<void, core::CircuitError>
BridgeRelay::handle_relay_cell(
    std::shared_ptr<core::Circuit> circuit,
    core::RelayCell& cell
) {
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
            return forward_to_next_hop(circuit, cell);

        case core::RelayCommand::BEGIN:
        case core::RelayCommand::RESOLVE:
            return std::unexpected(core::CircuitError::CellProcessingFailed);

        default:
            return forward_to_next_hop(circuit, cell);
    }
}

std::expected<void, core::CircuitError>
BridgeRelay::handle_begin(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& begin_cell
) {
    // Bridge relay does not handle BEGIN cells
    return std::unexpected(core::CircuitError::CellProcessingFailed);
}

std::expected<void, core::CircuitError>
BridgeRelay::handle_extend(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& extend_cell
) {
    if (!channel_manager_) {
        return std::unexpected(core::CircuitError::InvalidState);
    }

    clients_served_.fetch_add(1, std::memory_order_relaxed);

    // Parse EXTEND2 cell to get next hop info
    // Connect to next hop and forward CREATE2
    return {};
}

std::string BridgeRelay::descriptor_additions() const {
    std::ostringstream oss;

    if (!transport_name_.empty()) {
        oss << "transport " << transport_name_ << "\n";
    }

    oss << "bridge-distribution-request " << distribution_name(distribution_) << "\n";

    return oss.str();
}

std::expected<void, std::string> BridgeRelay::validate_config() const {
    if (config_) {
        if (config_->relay.or_port == 0) {
            return std::unexpected("Bridge relay requires a valid OR port");
        }
    }
    return {};
}

std::string BridgeRelay::bridge_line() const {
    if (!config_) {
        return "";
    }

    // Read fingerprint from data directory
    std::string fingerprint_hex;
    if (!config_->relay.data_dir.empty()) {
        auto fp_path = config_->relay.data_dir / "fingerprint";
        std::ifstream fp_file(fp_path);
        if (fp_file) {
            std::string nickname;
            fp_file >> nickname >> fingerprint_hex;
        }
    }

    std::ostringstream oss;
    oss << "Bridge ";

    if (!transport_name_.empty()) {
        oss << transport_name_ << " ";
    }

    std::string address = config_->relay.address;
    if (address.empty()) {
        address = "0.0.0.0";
    }

    // Use transport port for obfs4, OR port for plain bridge
    if (transport_name_ == "obfs4" && config_->bridge.transport_port > 0) {
        oss << address << ":" << config_->bridge.transport_port;
    } else {
        oss << address << ":" << config_->relay.or_port;
    }

    if (!fingerprint_hex.empty()) {
        oss << " " << fingerprint_hex;
    }

    // Append obfs4 cert and iat-mode
    if (transport_name_ == "obfs4" && obfs4_cert_) {
        oss << " cert=" << *obfs4_cert_;
        oss << " iat-mode=" << static_cast<int>(config_->bridge.iat_mode);
    }

    return oss.str();
}

std::expected<void, core::CircuitError>
BridgeRelay::forward_to_next_hop(
    std::shared_ptr<core::Circuit> circuit,
    const core::RelayCell& cell
) {
    auto next_channel = circuit->next_hop_channel();
    if (!next_channel) {
        return std::unexpected(core::CircuitError::CircuitNotFound);
    }

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
BridgeRelay::forward_to_prev_hop(
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

// Distribution parsing
std::expected<BridgeRelay::Distribution, std::string>
parse_distribution(const std::string& str) {
    if (str == "none" || str == "None" || str == "NONE") {
        return BridgeRelay::Distribution::None;
    }
    if (str == "https" || str == "Https" || str == "HTTPS") {
        return BridgeRelay::Distribution::Https;
    }
    if (str == "email" || str == "Email" || str == "EMAIL") {
        return BridgeRelay::Distribution::Email;
    }
    if (str == "moat" || str == "Moat" || str == "MOAT") {
        return BridgeRelay::Distribution::Moat;
    }
    if (str == "any" || str == "Any" || str == "ANY") {
        return BridgeRelay::Distribution::Any;
    }
    return std::unexpected("Unknown distribution method: " + str);
}

}  // namespace tor::modes
