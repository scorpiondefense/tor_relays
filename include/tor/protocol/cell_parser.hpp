#pragma once

#include "tor/core/cell.hpp"
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace tor::protocol {

// Cell parser error types
enum class CellParserError {
    InsufficientData,
    InvalidLength,
    InvalidCommand,
    InvalidPayload,
    UnknownVersion,
    ParseError,
};

// Binary serialization utilities
class BinaryReader {
public:
    explicit BinaryReader(std::span<const uint8_t> data);

    // Read primitives (big-endian)
    [[nodiscard]] std::expected<uint8_t, CellParserError> read_u8();
    [[nodiscard]] std::expected<uint16_t, CellParserError> read_u16();
    [[nodiscard]] std::expected<uint32_t, CellParserError> read_u32();
    [[nodiscard]] std::expected<uint64_t, CellParserError> read_u64();

    // Read bytes
    [[nodiscard]] std::expected<std::vector<uint8_t>, CellParserError>
    read_bytes(size_t count);

    // Read into existing buffer
    [[nodiscard]] std::expected<void, CellParserError>
    read_into(std::span<uint8_t> buffer);

    // Read length-prefixed data
    [[nodiscard]] std::expected<std::vector<uint8_t>, CellParserError>
    read_u8_prefixed();
    [[nodiscard]] std::expected<std::vector<uint8_t>, CellParserError>
    read_u16_prefixed();

    // Skip bytes
    [[nodiscard]] std::expected<void, CellParserError> skip(size_t count);

    // Position info
    [[nodiscard]] size_t position() const { return pos_; }
    [[nodiscard]] size_t remaining() const { return data_.size() - pos_; }
    [[nodiscard]] bool at_end() const { return pos_ >= data_.size(); }

    // Get remaining data
    [[nodiscard]] std::span<const uint8_t> remaining_span() const {
        return data_.subspan(pos_);
    }

private:
    std::span<const uint8_t> data_;
    size_t pos_{0};
};

// Binary serialization writer
class BinaryWriter {
public:
    BinaryWriter() = default;
    explicit BinaryWriter(size_t reserve);

    // Write primitives (big-endian)
    void write_u8(uint8_t value);
    void write_u16(uint16_t value);
    void write_u32(uint32_t value);
    void write_u64(uint64_t value);

    // Write bytes
    void write_bytes(std::span<const uint8_t> data);

    // Write with length prefix
    void write_u8_prefixed(std::span<const uint8_t> data);
    void write_u16_prefixed(std::span<const uint8_t> data);

    // Write padding (zeros)
    void write_padding(size_t count);

    // Get result
    [[nodiscard]] const std::vector<uint8_t>& data() const { return buffer_; }
    [[nodiscard]] std::vector<uint8_t> take() { return std::move(buffer_); }
    [[nodiscard]] size_t size() const { return buffer_.size(); }

    // Clear and reuse
    void clear() { buffer_.clear(); }

private:
    std::vector<uint8_t> buffer_;
};

// Cell parser/serializer
class CellParser {
public:
    CellParser() = default;
    explicit CellParser(uint16_t link_version);

    // Set link protocol version (affects circuit ID size)
    void set_link_version(uint16_t version) { link_version_ = version; }
    [[nodiscard]] uint16_t link_version() const { return link_version_; }

    // Parse fixed-size cell
    [[nodiscard]] std::expected<core::Cell, CellParserError>
    parse_cell(std::span<const uint8_t> data) const;

    // Parse variable-length cell
    [[nodiscard]] std::expected<core::VariableCell, CellParserError>
    parse_variable_cell(std::span<const uint8_t> data) const;

    // Parse cell header only (to determine type)
    struct CellHeader {
        core::CircuitId circuit_id;
        core::CellCommand command;
        uint16_t length;  // For variable cells only
    };

    [[nodiscard]] std::expected<CellHeader, CellParserError>
    parse_header(std::span<const uint8_t> data) const;

    // Serialize fixed-size cell
    [[nodiscard]] std::array<uint8_t, core::CELL_LEN>
    serialize_cell(const core::Cell& cell) const;

    // Serialize variable-length cell
    [[nodiscard]] std::vector<uint8_t>
    serialize_variable_cell(const core::VariableCell& cell) const;

    // Get expected cell size for command
    [[nodiscard]] size_t cell_size(core::CellCommand cmd) const;

    // Check if command is variable-length
    [[nodiscard]] bool is_variable_length(core::CellCommand cmd) const;

    // Parse relay cell payload
    [[nodiscard]] std::expected<core::RelayCell, CellParserError>
    parse_relay_cell(std::span<const uint8_t> payload) const;

    // Serialize relay cell payload
    [[nodiscard]] std::array<uint8_t, core::PAYLOAD_LEN>
    serialize_relay_cell(const core::RelayCell& relay) const;

    // Parse specific cell types
    [[nodiscard]] std::expected<core::Create2Data, CellParserError>
    parse_create2(std::span<const uint8_t> payload) const;

    [[nodiscard]] std::expected<core::Created2Data, CellParserError>
    parse_created2(std::span<const uint8_t> payload) const;

    [[nodiscard]] std::expected<core::NetInfoData, CellParserError>
    parse_netinfo(std::span<const uint8_t> payload) const;

    // Parse link specifiers (from EXTEND2)
    [[nodiscard]] std::expected<std::vector<core::LinkSpecifier>, CellParserError>
    parse_link_specifiers(std::span<const uint8_t> data) const;

    // Serialize link specifiers
    [[nodiscard]] std::vector<uint8_t>
    serialize_link_specifiers(std::span<const core::LinkSpecifier> specs) const;

private:
    uint16_t link_version_{4};

    [[nodiscard]] size_t circuit_id_len() const {
        return link_version_ >= 4 ? 4 : 2;
    }
};

// Stream-based cell reader (accumulates data until complete cell)
class CellReader {
public:
    CellReader();
    explicit CellReader(uint16_t link_version);

    // Feed data to reader
    void feed(std::span<const uint8_t> data);

    // Check if complete cell is available
    [[nodiscard]] bool has_cell() const;

    // Get and remove next cell (fixed-size)
    [[nodiscard]] std::expected<core::Cell, CellParserError> take_cell();

    // Get and remove next variable cell
    [[nodiscard]] std::expected<core::VariableCell, CellParserError>
    take_variable_cell();

    // Set link version
    void set_link_version(uint16_t version) {
        link_version_ = version;
        parser_.set_link_version(version);
    }

    // Clear buffer
    void clear() { buffer_.clear(); }

    // Get buffered data size
    [[nodiscard]] size_t buffered() const { return buffer_.size(); }

    // Peek at next cell header without consuming
    [[nodiscard]] std::expected<CellParser::CellHeader, CellParserError>
    peek_header() const;

private:
    CellParser parser_;
    std::vector<uint8_t> buffer_;
    uint16_t link_version_{4};
};

// Utility
[[nodiscard]] std::string cell_parser_error_message(CellParserError err);

}  // namespace tor::protocol
