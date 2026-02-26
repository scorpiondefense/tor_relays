#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace tor::core {

// Cell constants
constexpr size_t CELL_LEN = 514;       // Fixed cell size (link protocol v4+)
constexpr size_t PAYLOAD_LEN = 509;    // Cell payload size
constexpr size_t MAX_PAYLOAD_LEN = 509;
constexpr size_t CELL_HEADER_LEN = 5;  // CircuitId(4) + Command(1) for v4+
constexpr size_t RELAY_HEADER_LEN = 11; // Relay cell header within payload

// Circuit ID type (4 bytes in link protocol v4+)
using CircuitId = uint32_t;

// Stream ID type (2 bytes)
using StreamId = uint16_t;

// Cell commands (tor spec section 3)
enum class CellCommand : uint8_t {
    PADDING           = 0,
    CREATE            = 1,
    CREATED           = 2,
    RELAY             = 3,
    DESTROY           = 4,
    CREATE_FAST       = 5,
    CREATED_FAST      = 6,
    NETINFO           = 8,
    RELAY_EARLY       = 9,
    CREATE2           = 10,
    CREATED2          = 11,
    PADDING_NEGOTIATE = 12,

    // Variable-length commands (128+)
    VERSIONS          = 7,    // Special: variable length
    VPADDING          = 128,
    CERTS             = 129,
    AUTH_CHALLENGE     = 130,
    AUTHENTICATE      = 131,
    AUTHORIZE         = 132,
};

// Relay cell commands (tor spec section 6.1)
enum class RelayCommand : uint8_t {
    BEGIN             = 1,
    DATA              = 2,
    END               = 3,
    CONNECTED         = 4,
    SENDME            = 5,
    EXTEND            = 6,
    EXTENDED          = 7,
    TRUNCATE          = 8,
    TRUNCATED         = 9,
    DROP              = 10,
    RESOLVE           = 11,
    RESOLVED          = 12,
    BEGIN_DIR         = 13,
    EXTEND2           = 14,
    EXTENDED2         = 15,

    // Rendezvous / hidden services
    ESTABLISH_INTRO   = 32,
    ESTABLISH_RENDEZVOUS = 33,
    INTRODUCE1        = 34,
    INTRODUCE2        = 35,
    RENDEZVOUS1       = 36,
    RENDEZVOUS2       = 37,
    INTRO_ESTABLISHED = 38,
    RENDEZVOUS_ESTABLISHED = 39,
    INTRODUCE_ACK     = 40,
};

// Handshake type for CREATE2/EXTEND2
enum class HandshakeType : uint16_t {
    TAP   = 0,   // Legacy TAP handshake
    NTOR  = 2,   // ntor handshake (preferred)
};

// END cell reason codes
enum class EndReason : uint8_t {
    MISC            = 1,
    RESOLVEFAILED   = 2,
    CONNECTREFUSED  = 3,
    EXITPOLICY      = 4,
    DESTROY         = 5,
    DONE            = 6,
    TIMEOUT         = 7,
    NOROUTE         = 8,
    HIBERNATING     = 9,
    INTERNAL        = 10,
    RESOURCELIMIT   = 11,
    CONNRESET       = 12,
    TORPROTOCOL     = 13,
    NOTDIRECTORY    = 14,
};

// DESTROY cell reason codes
enum class DestroyReason : uint8_t {
    NONE            = 0,
    PROTOCOL        = 1,
    INTERNAL        = 2,
    REQUESTED       = 3,
    HIBERNATING     = 4,
    RESOURCELIMIT   = 5,
    CONNECTFAILED   = 6,
    OR_IDENTITY     = 7,
    CHANNEL_CLOSED  = 8,
    FINISHED        = 9,
    TIMEOUT         = 10,
    DESTROYED       = 11,
    NOSUCHSERVICE   = 12,
};

// Link specifier types
enum class LinkSpecType : uint8_t {
    IPv4        = 0,   // 4 bytes IP + 2 bytes port
    IPv6        = 1,   // 16 bytes IP + 2 bytes port
    LEGACY_ID   = 2,   // 20 bytes SHA-1 identity
    ED25519_ID  = 3,   // 32 bytes Ed25519 identity
};

// Link specifier (used in EXTEND2/CREATE2)
struct LinkSpecifier {
    LinkSpecType type;
    std::vector<uint8_t> data;

    [[nodiscard]] size_t size() const { return data.size(); }
};

// Fixed-size cell (514 bytes for link protocol v4+)
struct Cell {
    CircuitId circuit_id{0};
    CellCommand command{CellCommand::PADDING};
    std::array<uint8_t, PAYLOAD_LEN> payload{};

    Cell() = default;
    Cell(CircuitId id, CellCommand cmd) : circuit_id(id), command(cmd) {}

    [[nodiscard]] std::span<const uint8_t> payload_span() const {
        return std::span<const uint8_t>(payload);
    }

    [[nodiscard]] std::span<uint8_t> payload_span() {
        return std::span<uint8_t>(payload);
    }
};

// Variable-length cell
struct VariableCell {
    CircuitId circuit_id{0};
    CellCommand command{CellCommand::VERSIONS};
    std::vector<uint8_t> payload;

    VariableCell() = default;
    VariableCell(CircuitId id, CellCommand cmd, std::vector<uint8_t> data)
        : circuit_id(id), command(cmd), payload(std::move(data)) {}

    [[nodiscard]] size_t payload_length() const { return payload.size(); }
};

// Relay cell (inside a RELAY or RELAY_EARLY cell payload)
struct RelayCell {
    RelayCommand command{RelayCommand::DATA};
    uint16_t recognized{0};  // Set to 0 when cell is for us
    StreamId stream_id{0};
    uint32_t digest{0};       // Running digest
    std::vector<uint8_t> data;

    RelayCell() = default;
    RelayCell(RelayCommand cmd, StreamId sid)
        : command(cmd), stream_id(sid) {}
    RelayCell(RelayCommand cmd, StreamId sid, std::vector<uint8_t> payload_data)
        : command(cmd), stream_id(sid), data(std::move(payload_data)) {}

    [[nodiscard]] size_t data_length() const { return data.size(); }
};

// CREATE2 cell data
struct Create2Data {
    HandshakeType handshake_type{HandshakeType::NTOR};
    std::vector<uint8_t> handshake_data;
};

// CREATED2 cell data
struct Created2Data {
    std::vector<uint8_t> handshake_data;
};

// NETINFO cell data
struct NetInfoData {
    uint32_t timestamp{0};               // Unix timestamp
    std::vector<uint8_t> other_address;  // Address of the other side
    std::vector<std::vector<uint8_t>> our_addresses;  // Our addresses
};

// Check if a command uses variable-length cells
[[nodiscard]] constexpr bool is_variable_length_command(CellCommand cmd) {
    switch (cmd) {
        case CellCommand::VERSIONS:
        case CellCommand::VPADDING:
        case CellCommand::CERTS:
        case CellCommand::AUTH_CHALLENGE:
        case CellCommand::AUTHENTICATE:
        case CellCommand::AUTHORIZE:
            return true;
        default:
            return static_cast<uint8_t>(cmd) >= 128;
    }
}

// Command name for debugging/logging
[[nodiscard]] const char* cell_command_name(CellCommand cmd);
[[nodiscard]] const char* relay_command_name(RelayCommand cmd);
[[nodiscard]] const char* end_reason_name(EndReason reason);
[[nodiscard]] const char* destroy_reason_name(DestroyReason reason);

}  // namespace tor::core
