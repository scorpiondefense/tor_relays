#pragma once

#include "tor/core/cell.hpp"
#include "tor/core/circuit.hpp"
#include "tor/core/channel.hpp"
#include "tor/crypto/ntor.hpp"
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>

namespace tor::protocol {

// Relay protocol error types
enum class RelayProtocolError {
    InvalidCell,
    CircuitNotFound,
    StreamNotFound,
    HandshakeFailed,
    CryptoError,
    ProtocolViolation,
    PolicyViolation,
    ResourceExhausted,
    Timeout,
};

// Relay cell handling result
enum class RelayCellAction {
    Forward,      // Forward to next/prev hop
    Process,      // Process locally (e.g., BEGIN, DATA)
    Drop,         // Drop cell (e.g., unrecognized)
    Destroy,      // Destroy circuit
};

// CREATE2/CREATED2 handler
class CircuitCreateHandler {
public:
    CircuitCreateHandler() = default;

    // Handle incoming CREATE2 cell
    [[nodiscard]] std::expected<
        std::pair<core::Cell, crypto::NtorKeyMaterial>,
        RelayProtocolError
    > handle_create2(
        const core::Cell& create2_cell,
        const crypto::NodeId& our_node_id,
        const crypto::Curve25519SecretKey& our_onion_key
    );

    // Create CREATE2 cell for extending circuit
    [[nodiscard]] std::expected<core::Cell, RelayProtocolError>
    create_create2_cell(
        core::CircuitId circuit_id,
        const crypto::NodeId& target_node_id,
        const crypto::Curve25519PublicKey& target_onion_key,
        crypto::NtorClientHandshake& handshake
    );

    // Handle incoming CREATED2 cell
    [[nodiscard]] std::expected<crypto::NtorKeyMaterial, RelayProtocolError>
    handle_created2(
        const core::Cell& created2_cell,
        crypto::NtorClientHandshake& handshake
    );

    // Create CREATED2 response cell
    [[nodiscard]] core::Cell create_created2_cell(
        core::CircuitId circuit_id,
        std::span<const uint8_t> handshake_data
    );
};

// EXTEND2/EXTENDED2 handler
class CircuitExtendHandler {
public:
    CircuitExtendHandler() = default;

    // Parse EXTEND2 relay cell
    struct ExtendRequest {
        std::vector<core::LinkSpecifier> link_specs;
        core::HandshakeType handshake_type;
        std::vector<uint8_t> handshake_data;
    };

    [[nodiscard]] std::expected<ExtendRequest, RelayProtocolError>
    parse_extend2(const core::RelayCell& cell);

    // Create EXTEND2 relay cell
    [[nodiscard]] core::RelayCell create_extend2(
        const std::vector<core::LinkSpecifier>& link_specs,
        core::HandshakeType handshake_type,
        std::span<const uint8_t> handshake_data
    );

    // Create EXTENDED2 relay cell
    [[nodiscard]] core::RelayCell create_extended2(
        std::span<const uint8_t> handshake_data
    );

    // Parse EXTENDED2 relay cell
    [[nodiscard]] std::expected<std::vector<uint8_t>, RelayProtocolError>
    parse_extended2(const core::RelayCell& cell);
};

// Stream data handler (BEGIN, DATA, END, CONNECTED)
class StreamHandler {
public:
    StreamHandler() = default;

    // Parse BEGIN cell
    struct BeginRequest {
        std::string address;
        uint16_t port;
        uint32_t flags;
    };

    [[nodiscard]] std::expected<BeginRequest, RelayProtocolError>
    parse_begin(const core::RelayCell& cell);

    // Create CONNECTED response
    [[nodiscard]] core::RelayCell create_connected(
        core::StreamId stream_id,
        uint32_t ipv4_address,
        uint32_t ttl
    );

    [[nodiscard]] core::RelayCell create_connected_ipv6(
        core::StreamId stream_id,
        std::span<const uint8_t, 16> ipv6_address,
        uint32_t ttl
    );

    // Create END cell
    [[nodiscard]] core::RelayCell create_end(
        core::StreamId stream_id,
        core::EndReason reason
    );

    // Parse END cell
    [[nodiscard]] std::expected<core::EndReason, RelayProtocolError>
    parse_end(const core::RelayCell& cell);

    // Create DATA cell
    [[nodiscard]] core::RelayCell create_data(
        core::StreamId stream_id,
        std::span<const uint8_t> data
    );
};

// SENDME flow control handler
class SendmeHandler {
public:
    SendmeHandler() = default;

    // Check if SENDME should be sent (circuit level)
    [[nodiscard]] bool should_send_circuit_sendme(
        std::shared_ptr<core::Circuit> circuit
    ) const;

    // Check if SENDME should be sent (stream level)
    [[nodiscard]] bool should_send_stream_sendme(
        std::shared_ptr<core::Stream> stream
    ) const;

    // Create circuit-level SENDME
    [[nodiscard]] core::RelayCell create_circuit_sendme();

    // Create stream-level SENDME
    [[nodiscard]] core::RelayCell create_stream_sendme(core::StreamId stream_id);

    // Process received SENDME
    [[nodiscard]] std::expected<void, RelayProtocolError>
    handle_sendme(
        const core::RelayCell& cell,
        std::shared_ptr<core::Circuit> circuit
    );

    // Constants
    static constexpr int32_t CIRCUIT_WINDOW_START = 1000;
    static constexpr int32_t CIRCUIT_WINDOW_INCREMENT = 100;
    static constexpr int32_t STREAM_WINDOW_START = 500;
    static constexpr int32_t STREAM_WINDOW_INCREMENT = 50;
};

// Main relay protocol handler
class RelayProtocolHandler {
public:
    RelayProtocolHandler();
    ~RelayProtocolHandler() = default;

    // Process incoming cell from channel
    [[nodiscard]] std::expected<RelayCellAction, RelayProtocolError>
    handle_cell(
        const core::Cell& cell,
        std::shared_ptr<core::Channel> channel,
        std::shared_ptr<core::CircuitTable> circuit_table
    );

    // Process relay cell (after decryption)
    [[nodiscard]] std::expected<RelayCellAction, RelayProtocolError>
    handle_relay_cell(
        const core::RelayCell& relay_cell,
        std::shared_ptr<core::Circuit> circuit
    );

    // Forward relay cell to next hop
    [[nodiscard]] std::expected<void, RelayProtocolError>
    forward_relay(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& cell,
        bool to_origin
    );

    // Create and send DESTROY cell
    [[nodiscard]] std::expected<void, RelayProtocolError>
    destroy_circuit(
        std::shared_ptr<core::Circuit> circuit,
        core::DestroyReason reason
    );

    // Set handler callbacks
    using BeginHandler = std::function<std::expected<void, RelayProtocolError>(
        std::shared_ptr<core::Circuit>,
        core::StreamId,
        const std::string&,
        uint16_t
    )>;

    using DataHandler = std::function<std::expected<void, RelayProtocolError>(
        std::shared_ptr<core::Circuit>,
        core::StreamId,
        std::span<const uint8_t>
    )>;

    void set_begin_handler(BeginHandler handler) { begin_handler_ = std::move(handler); }
    void set_data_handler(DataHandler handler) { data_handler_ = std::move(handler); }

private:
    CircuitCreateHandler create_handler_;
    CircuitExtendHandler extend_handler_;
    StreamHandler stream_handler_;
    SendmeHandler sendme_handler_;

    BeginHandler begin_handler_;
    DataHandler data_handler_;

    // Handle specific cell commands
    [[nodiscard]] std::expected<RelayCellAction, RelayProtocolError>
    handle_create2(
        const core::Cell& cell,
        std::shared_ptr<core::Channel> channel,
        std::shared_ptr<core::CircuitTable> circuit_table
    );

    [[nodiscard]] std::expected<RelayCellAction, RelayProtocolError>
    handle_destroy(
        const core::Cell& cell,
        std::shared_ptr<core::CircuitTable> circuit_table
    );
};

// Utility
[[nodiscard]] std::string relay_protocol_error_message(RelayProtocolError err);
[[nodiscard]] const char* relay_cell_action_name(RelayCellAction action);

}  // namespace tor::protocol
