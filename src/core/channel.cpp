#include "tor/core/channel.hpp"
#include "tor/core/circuit.hpp"
#include "tor/net/connection.hpp"
#include "tor/protocol/cell_parser.hpp"
#include "tor/util/logging.hpp"

namespace tor::core {

// --- Channel ---

Channel::Channel()
    : created_at_(std::chrono::steady_clock::now()) {}

Channel::~Channel() {
    close();
}

void Channel::set_link_version(uint16_t version) {
    link_version_ = version;
    if (cell_reader_) {
        cell_reader_->set_link_version(version);
    }
}

void Channel::set_connection(std::shared_ptr<net::TlsConnection> conn) {
    connection_ = std::move(conn);
    // Start with link_version 3 (2-byte circuit IDs) for VERSIONS negotiation
    link_version_ = 3;
    cell_reader_ = std::make_unique<protocol::CellReader>(link_version_);
}

std::expected<void, ChannelError> Channel::send(const Cell& cell) {
    std::lock_guard lock(send_mutex_);

    if (connection_) {
        protocol::CellParser parser(link_version_);
        auto bytes = parser.serialize_cell(cell);
        auto result = connection_->write(
            std::span<const uint8_t>(bytes.data(), bytes.size()));
        if (!result) {
            return std::unexpected(ChannelError::SendFailed);
        }
        ++cells_sent_;
        bytes_sent_ += core::CELL_LEN;
        return {};
    }

    // Stub behavior (no connection)
    if (state_ != ChannelState::Open) {
        return std::unexpected(ChannelError::NotConnected);
    }
    ++cells_sent_;
    bytes_sent_ += CELL_LEN;
    return {};
}

std::expected<void, ChannelError> Channel::send(const VariableCell& cell) {
    std::lock_guard lock(send_mutex_);

    if (connection_) {
        protocol::CellParser parser(link_version_);
        auto bytes = parser.serialize_variable_cell(cell);
        auto result = connection_->write(
            std::span<const uint8_t>(bytes.data(), bytes.size()));
        if (!result) {
            return std::unexpected(ChannelError::SendFailed);
        }
        ++cells_sent_;
        bytes_sent_ += bytes.size();
        return {};
    }

    // Stub behavior
    if (state_ != ChannelState::Open) {
        return std::unexpected(ChannelError::NotConnected);
    }
    ++cells_sent_;
    bytes_sent_ += CELL_HEADER_LEN + 2 + cell.payload_length();
    return {};
}

std::expected<Cell, ChannelError> Channel::receive() {
    std::lock_guard lock(recv_mutex_);

    if (connection_ && cell_reader_) {
        auto buf = std::array<uint8_t, 4096>{};
        while (!cell_reader_->has_cell()) {
            auto result = connection_->read(
                std::span<uint8_t>(buf.data(), buf.size()));
            if (!result || *result == 0) {
                return std::unexpected(ChannelError::ReceiveFailed);
            }
            cell_reader_->feed(std::span<const uint8_t>(buf.data(), *result));
        }

        auto cell = cell_reader_->take_cell();
        if (!cell) {
            return std::unexpected(ChannelError::ReceiveFailed);
        }
        ++cells_received_;
        bytes_received_ += core::CELL_LEN;
        return *cell;
    }

    // Stub behavior
    if (state_ != ChannelState::Open) {
        return std::unexpected(ChannelError::NotConnected);
    }
    return std::unexpected(ChannelError::ReceiveFailed);
}

std::expected<VariableCell, ChannelError> Channel::receive_variable() {
    std::lock_guard lock(recv_mutex_);

    if (!connection_ || !cell_reader_) {
        return std::unexpected(ChannelError::NotConnected);
    }

    auto buf = std::array<uint8_t, 4096>{};
    while (!cell_reader_->has_cell()) {
        auto result = connection_->read(
            std::span<uint8_t>(buf.data(), buf.size()));
        if (!result || *result == 0) {
            return std::unexpected(ChannelError::ReceiveFailed);
        }
        cell_reader_->feed(std::span<const uint8_t>(buf.data(), *result));
    }

    auto cell = cell_reader_->take_variable_cell();
    if (!cell) {
        return std::unexpected(ChannelError::ReceiveFailed);
    }
    ++cells_received_;
    bytes_received_ += 5 + 2 + cell->payload.size();
    return std::move(*cell);
}

std::expected<Channel::AnyCell, ChannelError> Channel::receive_any() {
    std::lock_guard lock(recv_mutex_);

    if (!connection_ || !cell_reader_) {
        return std::unexpected(ChannelError::NotConnected);
    }

    auto buf = std::array<uint8_t, 4096>{};
    while (!cell_reader_->has_cell()) {
        auto result = connection_->read(
            std::span<uint8_t>(buf.data(), buf.size()));
        if (!result || *result == 0) {
            return std::unexpected(ChannelError::ReceiveFailed);
        }
        cell_reader_->feed(std::span<const uint8_t>(buf.data(), *result));
    }

    auto header = cell_reader_->peek_header();
    if (!header) {
        return std::unexpected(ChannelError::ReceiveFailed);
    }

    AnyCell any{};
    if (is_variable_length_command(header->command)) {
        auto cell = cell_reader_->take_variable_cell();
        if (!cell) return std::unexpected(ChannelError::ReceiveFailed);
        any.is_variable = true;
        any.variable_cell = std::move(*cell);
        ++cells_received_;
        bytes_received_ += 5 + 2 + any.variable_cell.payload.size();
    } else {
        auto cell = cell_reader_->take_cell();
        if (!cell) return std::unexpected(ChannelError::ReceiveFailed);
        any.is_variable = false;
        any.fixed_cell = std::move(*cell);
        ++cells_received_;
        bytes_received_ += core::CELL_LEN;
    }

    return any;
}

void Channel::close() {
    state_ = ChannelState::Closed;
    if (connection_) {
        connection_->close();
    }
}

// --- ChannelManager ---

ChannelManager::ChannelManager() = default;

ChannelManager::~ChannelManager() {
    close_all();
}

std::expected<std::shared_ptr<Channel>, ChannelError>
ChannelManager::get_or_create(
    const crypto::NodeId& peer_id,
    const std::string& address,
    uint16_t port
) {
    std::lock_guard lock(mutex_);

    auto it = channels_.find(peer_id);
    if (it != channels_.end() && it->second->is_open()) {
        return it->second;
    }

    // Create new channel
    auto channel = std::make_shared<Channel>();
    channel->set_peer_node_id(peer_id);
    channel->set_remote_address(address);
    channel->set_remote_port(port);
    channel->set_circuit_table(std::make_shared<CircuitTable>());

    // In a full implementation, would perform TLS connect + link protocol handshake here
    // For now, mark as open
    channel->set_state(ChannelState::Open);

    channels_[peer_id] = channel;
    return channel;
}

std::shared_ptr<Channel> ChannelManager::get(const crypto::NodeId& peer_id) const {
    std::lock_guard lock(mutex_);
    auto it = channels_.find(peer_id);
    if (it != channels_.end()) {
        return it->second;
    }
    return nullptr;
}

void ChannelManager::add(const crypto::NodeId& peer_id, std::shared_ptr<Channel> channel) {
    std::lock_guard lock(mutex_);
    channels_[peer_id] = std::move(channel);
}

void ChannelManager::remove(const crypto::NodeId& peer_id) {
    std::lock_guard lock(mutex_);
    channels_.erase(peer_id);
}

std::vector<std::shared_ptr<Channel>> ChannelManager::all() const {
    std::lock_guard lock(mutex_);
    std::vector<std::shared_ptr<Channel>> result;
    result.reserve(channels_.size());
    for (const auto& [id, channel] : channels_) {
        result.push_back(channel);
    }
    return result;
}

size_t ChannelManager::size() const {
    std::lock_guard lock(mutex_);
    return channels_.size();
}

void ChannelManager::close_all() {
    std::lock_guard lock(mutex_);
    for (auto& [id, channel] : channels_) {
        channel->close();
    }
    channels_.clear();
}

void ChannelManager::cleanup_idle(std::chrono::seconds max_idle) {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto it = channels_.begin(); it != channels_.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second->created_at()
        );
        if (age > max_idle && it->second->is_open()) {
            it->second->close();
            it = channels_.erase(it);
        } else {
            ++it;
        }
    }
}

// --- Utility ---

std::string channel_error_message(ChannelError err) {
    switch (err) {
        case ChannelError::NotConnected:      return "Channel not connected";
        case ChannelError::AlreadyConnected:   return "Channel already connected";
        case ChannelError::ConnectionFailed:   return "Connection failed";
        case ChannelError::HandshakeFailed:    return "Handshake failed";
        case ChannelError::SendFailed:         return "Send failed";
        case ChannelError::ReceiveFailed:      return "Receive failed";
        case ChannelError::Closed:             return "Channel closed";
        case ChannelError::Timeout:            return "Channel timeout";
        case ChannelError::ProtocolViolation:  return "Protocol violation";
        default:                               return "Unknown channel error";
    }
}

const char* channel_state_name(ChannelState state) {
    switch (state) {
        case ChannelState::Opening: return "Opening";
        case ChannelState::Open:    return "Open";
        case ChannelState::Closing: return "Closing";
        case ChannelState::Closed:  return "Closed";
        case ChannelState::Failed:  return "Failed";
        default:                    return "Unknown";
    }
}

}  // namespace tor::core
