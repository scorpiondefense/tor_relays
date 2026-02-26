#include "tor/core/channel.hpp"
#include "tor/core/circuit.hpp"

namespace tor::core {

// --- Channel ---

Channel::Channel()
    : created_at_(std::chrono::steady_clock::now()) {}

Channel::~Channel() {
    close();
}

std::expected<void, ChannelError> Channel::send(const Cell& cell) {
    if (state_ != ChannelState::Open) {
        return std::unexpected(ChannelError::NotConnected);
    }

    std::lock_guard lock(send_mutex_);

    // In a full implementation, this would serialize the cell and write
    // to the TLS connection. For now, track statistics.
    ++cells_sent_;
    bytes_sent_ += CELL_LEN;

    return {};
}

std::expected<void, ChannelError> Channel::send(const VariableCell& cell) {
    if (state_ != ChannelState::Open) {
        return std::unexpected(ChannelError::NotConnected);
    }

    std::lock_guard lock(send_mutex_);

    ++cells_sent_;
    bytes_sent_ += CELL_HEADER_LEN + 2 + cell.payload_length();  // +2 for length field

    return {};
}

std::expected<Cell, ChannelError> Channel::receive() {
    if (state_ != ChannelState::Open) {
        return std::unexpected(ChannelError::NotConnected);
    }

    std::lock_guard lock(recv_mutex_);

    // In a full implementation, this would read from the TLS connection
    // and deserialize. For now, return an error.
    return std::unexpected(ChannelError::ReceiveFailed);
}

void Channel::close() {
    state_ = ChannelState::Closed;
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
