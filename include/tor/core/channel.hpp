#pragma once

#include "tor/core/cell.hpp"
#include "tor/crypto/keys.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Forward declarations
namespace tor::net {
class TlsConnection;
}

namespace tor::protocol {
class CellReader;
}

namespace tor::core {

// Forward declarations
class Circuit;
class CircuitTable;

// Channel error types
enum class ChannelError {
    NotConnected,
    AlreadyConnected,
    ConnectionFailed,
    HandshakeFailed,
    SendFailed,
    ReceiveFailed,
    Closed,
    Timeout,
    ProtocolViolation,
};

// Channel state
enum class ChannelState {
    Opening,
    Open,
    Closing,
    Closed,
    Failed,
};

// Channel represents a TLS connection to another relay
class Channel : public std::enable_shared_from_this<Channel> {
public:
    Channel();
    ~Channel();

    // Non-copyable
    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    // Identity
    [[nodiscard]] const crypto::Ed25519PublicKey& peer_identity() const { return peer_identity_; }
    void set_peer_identity(const crypto::Ed25519PublicKey& key) { peer_identity_ = key; }

    [[nodiscard]] const crypto::NodeId& peer_node_id() const { return peer_node_id_; }
    void set_peer_node_id(const crypto::NodeId& id) { peer_node_id_ = id; }

    // State
    [[nodiscard]] ChannelState state() const { return state_; }
    [[nodiscard]] bool is_open() const { return state_ == ChannelState::Open; }
    void set_state(ChannelState state) { state_ = state; }

    // Link protocol version
    [[nodiscard]] uint16_t link_version() const { return link_version_; }
    void set_link_version(uint16_t version);

    // Connection-backed I/O
    void set_connection(std::shared_ptr<net::TlsConnection> conn);

    // Send a fixed-size cell
    [[nodiscard]] std::expected<void, ChannelError> send(const Cell& cell);

    // Send a variable-length cell
    [[nodiscard]] std::expected<void, ChannelError> send(const VariableCell& cell);

    // Receive a fixed-size cell (blocking)
    [[nodiscard]] std::expected<Cell, ChannelError> receive();

    // Receive a variable-length cell (blocking)
    [[nodiscard]] std::expected<VariableCell, ChannelError> receive_variable();

    // Receive any cell type (fixed or variable)
    struct AnyCell {
        bool is_variable;
        Cell fixed_cell;
        VariableCell variable_cell;
    };
    [[nodiscard]] std::expected<AnyCell, ChannelError> receive_any();

    // Close the channel
    void close();

    // TLS certificate (DER encoded) for CERTS cell
    [[nodiscard]] const std::vector<uint8_t>& tls_cert_der() const { return tls_cert_der_; }
    void set_tls_cert_der(std::vector<uint8_t> der) { tls_cert_der_ = std::move(der); }

    // Circuit table for this channel
    [[nodiscard]] std::shared_ptr<CircuitTable> circuit_table() const { return circuit_table_; }
    void set_circuit_table(std::shared_ptr<CircuitTable> table) { circuit_table_ = std::move(table); }

    // Connection info
    [[nodiscard]] const std::string& remote_address() const { return remote_address_; }
    [[nodiscard]] uint16_t remote_port() const { return remote_port_; }
    void set_remote_address(const std::string& addr) { remote_address_ = addr; }
    void set_remote_port(uint16_t port) { remote_port_ = port; }

    // Statistics
    [[nodiscard]] uint64_t cells_sent() const { return cells_sent_; }
    [[nodiscard]] uint64_t cells_received() const { return cells_received_; }
    [[nodiscard]] uint64_t bytes_sent() const { return bytes_sent_; }
    [[nodiscard]] uint64_t bytes_received() const { return bytes_received_; }

    // Creation time
    [[nodiscard]] std::chrono::steady_clock::time_point created_at() const { return created_at_; }

private:
    crypto::Ed25519PublicKey peer_identity_;
    crypto::NodeId peer_node_id_;
    ChannelState state_{ChannelState::Opening};
    uint16_t link_version_{4};

    std::shared_ptr<CircuitTable> circuit_table_;

    std::string remote_address_;
    uint16_t remote_port_{0};

    // Statistics
    std::atomic<uint64_t> cells_sent_{0};
    std::atomic<uint64_t> cells_received_{0};
    std::atomic<uint64_t> bytes_sent_{0};
    std::atomic<uint64_t> bytes_received_{0};

    std::chrono::steady_clock::time_point created_at_;

    mutable std::mutex send_mutex_;
    mutable std::mutex recv_mutex_;

    // Connection-backed I/O
    std::shared_ptr<net::TlsConnection> connection_;
    std::vector<uint8_t> tls_cert_der_;
    std::unique_ptr<protocol::CellReader> cell_reader_;
};

// Channel manager: manages TLS connections to other relays
class ChannelManager {
public:
    ChannelManager();
    ~ChannelManager();

    // Get or create channel to a peer
    [[nodiscard]] std::expected<std::shared_ptr<Channel>, ChannelError>
    get_or_create(
        const crypto::NodeId& peer_id,
        const std::string& address,
        uint16_t port
    );

    // Get existing channel to peer
    [[nodiscard]] std::shared_ptr<Channel> get(const crypto::NodeId& peer_id) const;

    // Register an inbound channel
    void add(const crypto::NodeId& peer_id, std::shared_ptr<Channel> channel);

    // Remove channel
    void remove(const crypto::NodeId& peer_id);

    // Get all channels
    [[nodiscard]] std::vector<std::shared_ptr<Channel>> all() const;

    // Get channel count
    [[nodiscard]] size_t size() const;

    // Close all channels
    void close_all();

    // Cleanup idle channels
    void cleanup_idle(std::chrono::seconds max_idle);

private:
    mutable std::mutex mutex_;
    std::unordered_map<crypto::NodeId, std::shared_ptr<Channel>> channels_;
};

// Utility
[[nodiscard]] std::string channel_error_message(ChannelError err);
[[nodiscard]] const char* channel_state_name(ChannelState state);

}  // namespace tor::core
