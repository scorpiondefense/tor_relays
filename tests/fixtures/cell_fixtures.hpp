#pragma once

#include "tor/core/cell.hpp"
#include <array>
#include <vector>

namespace tor::test::fixtures {

// Pre-built cell fixtures for testing

// Valid CREATE2 cell with ntor handshake
inline core::Cell create2_ntor_cell() {
    core::Cell cell;
    cell.circuit_id = 0x12345678;
    cell.command = core::CellCommand::CREATE2;

    // Handshake type (2 bytes) = ntor (0x0002)
    cell.payload[0] = 0x00;
    cell.payload[1] = 0x02;

    // Handshake length (2 bytes) = 84 bytes
    cell.payload[2] = 0x00;
    cell.payload[3] = 0x54;

    // Handshake data: node_id (20) + key_id (32) + client_pk (32)
    // Fill with test pattern
    for (size_t i = 0; i < 84; ++i) {
        cell.payload[4 + i] = static_cast<uint8_t>(i);
    }

    return cell;
}

// Valid CREATED2 cell
inline core::Cell created2_cell() {
    core::Cell cell;
    cell.circuit_id = 0x12345678;
    cell.command = core::CellCommand::CREATED2;

    // Handshake length (2 bytes) = 64 bytes
    cell.payload[0] = 0x00;
    cell.payload[1] = 0x40;

    // Handshake data: server_pk (32) + auth (32)
    for (size_t i = 0; i < 64; ++i) {
        cell.payload[2 + i] = static_cast<uint8_t>(i);
    }

    return cell;
}

// Valid RELAY cell
inline core::Cell relay_data_cell(core::CircuitId circuit_id, core::StreamId stream_id) {
    core::Cell cell;
    cell.circuit_id = circuit_id;
    cell.command = core::CellCommand::RELAY;

    // Relay cell header
    cell.payload[0] = static_cast<uint8_t>(core::RelayCommand::DATA);  // Command
    cell.payload[1] = 0x00;  // Recognized (high)
    cell.payload[2] = 0x00;  // Recognized (low)
    cell.payload[3] = static_cast<uint8_t>(stream_id >> 8);  // Stream ID high
    cell.payload[4] = static_cast<uint8_t>(stream_id);       // Stream ID low
    cell.payload[5] = 0x00;  // Digest (would be computed)
    cell.payload[6] = 0x00;
    cell.payload[7] = 0x00;
    cell.payload[8] = 0x00;
    cell.payload[9] = 0x00;  // Length high
    cell.payload[10] = 0x10; // Length low (16 bytes)

    // Test data
    for (size_t i = 0; i < 16; ++i) {
        cell.payload[11 + i] = static_cast<uint8_t>(i);
    }

    return cell;
}

// DESTROY cell
inline core::Cell destroy_cell(core::CircuitId circuit_id, core::DestroyReason reason) {
    return core::Cell::destroy(circuit_id, reason);
}

// PADDING cell
inline core::Cell padding_cell() {
    return core::Cell::padding(0);
}

// Valid VERSIONS cell
inline core::VariableCell versions_cell() {
    std::array<uint16_t, 2> versions = {4, 5};
    return core::VariableCell::versions(versions);
}

// Raw cell bytes for testing parser
inline std::array<uint8_t, core::CELL_LEN> raw_padding_cell() {
    std::array<uint8_t, core::CELL_LEN> data{};
    // Circuit ID = 0
    // Command = PADDING (0)
    // Rest is zeros
    return data;
}

// Invalid cell (truncated)
inline std::vector<uint8_t> truncated_cell() {
    return std::vector<uint8_t>(100, 0);  // Only 100 bytes
}

// Invalid cell (bad command)
inline std::array<uint8_t, core::CELL_LEN> invalid_command_cell() {
    std::array<uint8_t, core::CELL_LEN> data{};
    data[4] = 0xFF;  // Invalid command
    return data;
}

// NETINFO cell data
inline core::NetInfoData netinfo_data() {
    core::NetInfoData data;
    data.timestamp = 1234567890;
    data.other_address = {192, 168, 1, 1};  // IPv4
    data.my_addresses.push_back({10, 0, 0, 1});  // Our IPv4
    return data;
}

}  // namespace tor::test::fixtures
