#include "tor/protocol/cell_parser.hpp"
#include <algorithm>
#include <cstring>

namespace tor::protocol {

// --- BinaryReader ---

BinaryReader::BinaryReader(std::span<const uint8_t> data)
    : data_(data) {}

std::expected<uint8_t, CellParserError> BinaryReader::read_u8() {
    if (remaining() < 1) return std::unexpected(CellParserError::InsufficientData);
    return data_[pos_++];
}

std::expected<uint16_t, CellParserError> BinaryReader::read_u16() {
    if (remaining() < 2) return std::unexpected(CellParserError::InsufficientData);
    uint16_t val = (static_cast<uint16_t>(data_[pos_]) << 8) |
                    static_cast<uint16_t>(data_[pos_ + 1]);
    pos_ += 2;
    return val;
}

std::expected<uint32_t, CellParserError> BinaryReader::read_u32() {
    if (remaining() < 4) return std::unexpected(CellParserError::InsufficientData);
    uint32_t val = (static_cast<uint32_t>(data_[pos_]) << 24) |
                   (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                   (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                    static_cast<uint32_t>(data_[pos_ + 3]);
    pos_ += 4;
    return val;
}

std::expected<uint64_t, CellParserError> BinaryReader::read_u64() {
    if (remaining() < 8) return std::unexpected(CellParserError::InsufficientData);
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | static_cast<uint64_t>(data_[pos_ + i]);
    }
    pos_ += 8;
    return val;
}

std::expected<std::vector<uint8_t>, CellParserError>
BinaryReader::read_bytes(size_t count) {
    if (remaining() < count) return std::unexpected(CellParserError::InsufficientData);
    std::vector<uint8_t> result(data_.begin() + pos_, data_.begin() + pos_ + count);
    pos_ += count;
    return result;
}

std::expected<void, CellParserError>
BinaryReader::read_into(std::span<uint8_t> buffer) {
    if (remaining() < buffer.size()) return std::unexpected(CellParserError::InsufficientData);
    std::memcpy(buffer.data(), data_.data() + pos_, buffer.size());
    pos_ += buffer.size();
    return {};
}

std::expected<std::vector<uint8_t>, CellParserError>
BinaryReader::read_u8_prefixed() {
    auto len = read_u8();
    if (!len) return std::unexpected(len.error());
    return read_bytes(*len);
}

std::expected<std::vector<uint8_t>, CellParserError>
BinaryReader::read_u16_prefixed() {
    auto len = read_u16();
    if (!len) return std::unexpected(len.error());
    return read_bytes(*len);
}

std::expected<void, CellParserError> BinaryReader::skip(size_t count) {
    if (remaining() < count) return std::unexpected(CellParserError::InsufficientData);
    pos_ += count;
    return {};
}

// --- BinaryWriter ---

BinaryWriter::BinaryWriter(size_t reserve) {
    buffer_.reserve(reserve);
}

void BinaryWriter::write_u8(uint8_t value) {
    buffer_.push_back(value);
}

void BinaryWriter::write_u16(uint16_t value) {
    buffer_.push_back(static_cast<uint8_t>(value >> 8));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void BinaryWriter::write_u32(uint32_t value) {
    buffer_.push_back(static_cast<uint8_t>(value >> 24));
    buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void BinaryWriter::write_u64(uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        buffer_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void BinaryWriter::write_bytes(std::span<const uint8_t> data) {
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void BinaryWriter::write_u8_prefixed(std::span<const uint8_t> data) {
    write_u8(static_cast<uint8_t>(data.size()));
    write_bytes(data);
}

void BinaryWriter::write_u16_prefixed(std::span<const uint8_t> data) {
    write_u16(static_cast<uint16_t>(data.size()));
    write_bytes(data);
}

void BinaryWriter::write_padding(size_t count) {
    buffer_.insert(buffer_.end(), count, 0);
}

// --- CellParser ---

CellParser::CellParser(uint16_t link_version) : link_version_(link_version) {}

std::expected<CellParser::CellHeader, CellParserError>
CellParser::parse_header(std::span<const uint8_t> data) const {
    BinaryReader reader(data);
    CellHeader header{};

    if (circuit_id_len() == 4) {
        auto cid = reader.read_u32();
        if (!cid) return std::unexpected(cid.error());
        header.circuit_id = *cid;
    } else {
        auto cid = reader.read_u16();
        if (!cid) return std::unexpected(cid.error());
        header.circuit_id = *cid;
    }

    auto cmd = reader.read_u8();
    if (!cmd) return std::unexpected(cmd.error());
    header.command = static_cast<core::CellCommand>(*cmd);

    if (core::is_variable_length_command(header.command)) {
        auto len = reader.read_u16();
        if (!len) return std::unexpected(len.error());
        header.length = *len;
    } else {
        header.length = core::PAYLOAD_LEN;
    }

    return header;
}

std::expected<core::Cell, CellParserError>
CellParser::parse_cell(std::span<const uint8_t> data) const {
    size_t expected_size = circuit_id_len() + 1 + core::PAYLOAD_LEN;
    if (data.size() < expected_size) {
        return std::unexpected(CellParserError::InsufficientData);
    }

    BinaryReader reader(data);
    core::Cell cell;

    if (circuit_id_len() == 4) {
        auto cid = reader.read_u32();
        if (!cid) return std::unexpected(cid.error());
        cell.circuit_id = *cid;
    } else {
        auto cid = reader.read_u16();
        if (!cid) return std::unexpected(cid.error());
        cell.circuit_id = *cid;
    }

    auto cmd = reader.read_u8();
    if (!cmd) return std::unexpected(cmd.error());
    cell.command = static_cast<core::CellCommand>(*cmd);

    auto payload_result = reader.read_into(cell.payload);
    if (!payload_result) return std::unexpected(payload_result.error());

    return cell;
}

std::expected<core::VariableCell, CellParserError>
CellParser::parse_variable_cell(std::span<const uint8_t> data) const {
    size_t header_size = circuit_id_len() + 1 + 2; // circ_id + cmd + length
    if (data.size() < header_size) {
        return std::unexpected(CellParserError::InsufficientData);
    }

    BinaryReader reader(data);
    core::VariableCell cell;

    if (circuit_id_len() == 4) {
        auto cid = reader.read_u32();
        if (!cid) return std::unexpected(cid.error());
        cell.circuit_id = *cid;
    } else {
        auto cid = reader.read_u16();
        if (!cid) return std::unexpected(cid.error());
        cell.circuit_id = *cid;
    }

    auto cmd = reader.read_u8();
    if (!cmd) return std::unexpected(cmd.error());
    cell.command = static_cast<core::CellCommand>(*cmd);

    auto len = reader.read_u16();
    if (!len) return std::unexpected(len.error());

    auto payload = reader.read_bytes(*len);
    if (!payload) return std::unexpected(payload.error());
    cell.payload = std::move(*payload);

    return cell;
}

std::array<uint8_t, core::CELL_LEN>
CellParser::serialize_cell(const core::Cell& cell) const {
    std::array<uint8_t, core::CELL_LEN> out{};
    BinaryWriter writer(core::CELL_LEN);

    if (circuit_id_len() == 4) {
        writer.write_u32(cell.circuit_id);
    } else {
        writer.write_u16(static_cast<uint16_t>(cell.circuit_id));
    }

    writer.write_u8(static_cast<uint8_t>(cell.command));
    writer.write_bytes(cell.payload);

    const auto& buf = writer.data();
    std::memcpy(out.data(), buf.data(), std::min(buf.size(), out.size()));
    return out;
}

std::vector<uint8_t>
CellParser::serialize_variable_cell(const core::VariableCell& cell) const {
    BinaryWriter writer(circuit_id_len() + 1 + 2 + cell.payload.size());

    if (circuit_id_len() == 4) {
        writer.write_u32(cell.circuit_id);
    } else {
        writer.write_u16(static_cast<uint16_t>(cell.circuit_id));
    }

    writer.write_u8(static_cast<uint8_t>(cell.command));
    writer.write_u16(static_cast<uint16_t>(cell.payload.size()));
    writer.write_bytes(cell.payload);

    return writer.take();
}

size_t CellParser::cell_size(core::CellCommand cmd) const {
    if (core::is_variable_length_command(cmd)) {
        return 0; // Variable, depends on payload
    }
    return circuit_id_len() + 1 + core::PAYLOAD_LEN;
}

bool CellParser::is_variable_length(core::CellCommand cmd) const {
    return core::is_variable_length_command(cmd);
}

std::expected<core::RelayCell, CellParserError>
CellParser::parse_relay_cell(std::span<const uint8_t> payload) const {
    if (payload.size() < core::RELAY_HEADER_LEN) {
        return std::unexpected(CellParserError::InsufficientData);
    }

    BinaryReader reader(payload);
    core::RelayCell relay;

    auto cmd = reader.read_u8();
    if (!cmd) return std::unexpected(cmd.error());
    relay.command = static_cast<core::RelayCommand>(*cmd);

    auto recognized = reader.read_u16();
    if (!recognized) return std::unexpected(recognized.error());
    relay.recognized = *recognized;

    auto stream_id = reader.read_u16();
    if (!stream_id) return std::unexpected(stream_id.error());
    relay.stream_id = *stream_id;

    auto digest = reader.read_u32();
    if (!digest) return std::unexpected(digest.error());
    relay.digest = *digest;

    auto data_len = reader.read_u16();
    if (!data_len) return std::unexpected(data_len.error());

    if (*data_len > reader.remaining()) {
        return std::unexpected(CellParserError::InvalidLength);
    }

    auto data = reader.read_bytes(*data_len);
    if (!data) return std::unexpected(data.error());
    relay.data = std::move(*data);

    return relay;
}

std::array<uint8_t, core::PAYLOAD_LEN>
CellParser::serialize_relay_cell(const core::RelayCell& relay) const {
    std::array<uint8_t, core::PAYLOAD_LEN> out{};
    BinaryWriter writer(core::PAYLOAD_LEN);

    writer.write_u8(static_cast<uint8_t>(relay.command));
    writer.write_u16(relay.recognized);
    writer.write_u16(relay.stream_id);
    writer.write_u32(relay.digest);
    writer.write_u16(static_cast<uint16_t>(relay.data.size()));
    writer.write_bytes(relay.data);

    const auto& buf = writer.data();
    std::memcpy(out.data(), buf.data(), std::min(buf.size(), out.size()));
    return out;
}

std::expected<core::Create2Data, CellParserError>
CellParser::parse_create2(std::span<const uint8_t> payload) const {
    BinaryReader reader(payload);
    core::Create2Data data;

    auto htype = reader.read_u16();
    if (!htype) return std::unexpected(htype.error());
    data.handshake_type = static_cast<core::HandshakeType>(*htype);

    auto hlen = reader.read_u16();
    if (!hlen) return std::unexpected(hlen.error());

    auto hdata = reader.read_bytes(*hlen);
    if (!hdata) return std::unexpected(hdata.error());
    data.handshake_data = std::move(*hdata);

    return data;
}

std::expected<core::Created2Data, CellParserError>
CellParser::parse_created2(std::span<const uint8_t> payload) const {
    BinaryReader reader(payload);
    core::Created2Data data;

    auto hlen = reader.read_u16();
    if (!hlen) return std::unexpected(hlen.error());

    auto hdata = reader.read_bytes(*hlen);
    if (!hdata) return std::unexpected(hdata.error());
    data.handshake_data = std::move(*hdata);

    return data;
}

std::expected<core::NetInfoData, CellParserError>
CellParser::parse_netinfo(std::span<const uint8_t> payload) const {
    BinaryReader reader(payload);
    core::NetInfoData data;

    auto timestamp = reader.read_u32();
    if (!timestamp) return std::unexpected(timestamp.error());
    data.timestamp = *timestamp;

    // Other address (the address we see for the peer)
    auto other_type = reader.read_u8();
    if (!other_type) return std::unexpected(other_type.error());

    auto other_len = reader.read_u8();
    if (!other_len) return std::unexpected(other_len.error());

    auto other_addr = reader.read_bytes(*other_len);
    if (!other_addr) return std::unexpected(other_addr.error());

    // Prepend type byte
    data.other_address.push_back(*other_type);
    data.other_address.insert(data.other_address.end(),
                              other_addr->begin(), other_addr->end());

    // Our addresses
    auto num_addrs = reader.read_u8();
    if (!num_addrs) return std::unexpected(num_addrs.error());

    for (uint8_t i = 0; i < *num_addrs; ++i) {
        auto addr_type = reader.read_u8();
        if (!addr_type) return std::unexpected(addr_type.error());

        auto addr_len = reader.read_u8();
        if (!addr_len) return std::unexpected(addr_len.error());

        auto addr_data = reader.read_bytes(*addr_len);
        if (!addr_data) return std::unexpected(addr_data.error());

        std::vector<uint8_t> addr;
        addr.push_back(*addr_type);
        addr.insert(addr.end(), addr_data->begin(), addr_data->end());
        data.our_addresses.push_back(std::move(addr));
    }

    return data;
}

std::expected<std::vector<core::LinkSpecifier>, CellParserError>
CellParser::parse_link_specifiers(std::span<const uint8_t> data) const {
    BinaryReader reader(data);
    auto count = reader.read_u8();
    if (!count) return std::unexpected(count.error());

    std::vector<core::LinkSpecifier> specs;
    for (uint8_t i = 0; i < *count; ++i) {
        auto type = reader.read_u8();
        if (!type) return std::unexpected(type.error());

        auto len = reader.read_u8();
        if (!len) return std::unexpected(len.error());

        auto spec_data = reader.read_bytes(*len);
        if (!spec_data) return std::unexpected(spec_data.error());

        specs.push_back({static_cast<core::LinkSpecType>(*type),
                         std::move(*spec_data)});
    }

    return specs;
}

std::vector<uint8_t>
CellParser::serialize_link_specifiers(std::span<const core::LinkSpecifier> specs) const {
    BinaryWriter writer;
    writer.write_u8(static_cast<uint8_t>(specs.size()));
    for (const auto& spec : specs) {
        writer.write_u8(static_cast<uint8_t>(spec.type));
        writer.write_u8(static_cast<uint8_t>(spec.data.size()));
        writer.write_bytes(spec.data);
    }
    return writer.take();
}

// --- CellReader ---

CellReader::CellReader() = default;

CellReader::CellReader(uint16_t link_version)
    : parser_(link_version), link_version_(link_version) {}

void CellReader::feed(std::span<const uint8_t> data) {
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

std::expected<CellParser::CellHeader, CellParserError>
CellReader::peek_header() const {
    size_t circ_id_len = link_version_ >= 4 ? 4 : 2;
    size_t min_header = circ_id_len + 1; // circ_id + command

    if (buffer_.size() < min_header) {
        return std::unexpected(CellParserError::InsufficientData);
    }

    return parser_.parse_header(buffer_);
}

bool CellReader::has_cell() const {
    auto header = peek_header();
    if (!header) return false;

    size_t circ_id_len = link_version_ >= 4 ? 4 : 2;

    if (core::is_variable_length_command(header->command)) {
        size_t needed = circ_id_len + 1 + 2 + header->length;
        return buffer_.size() >= needed;
    } else {
        size_t needed = circ_id_len + 1 + core::PAYLOAD_LEN;
        return buffer_.size() >= needed;
    }
}

std::expected<core::Cell, CellParserError> CellReader::take_cell() {
    auto result = parser_.parse_cell(buffer_);
    if (!result) return result;

    size_t consumed = parser_.cell_size(result->command);
    if (consumed == 0) consumed = (link_version_ >= 4 ? 4 : 2) + 1 + core::PAYLOAD_LEN;
    buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);

    return result;
}

std::expected<core::VariableCell, CellParserError>
CellReader::take_variable_cell() {
    auto result = parser_.parse_variable_cell(buffer_);
    if (!result) return result;

    size_t circ_id_len = link_version_ >= 4 ? 4 : 2;
    size_t consumed = circ_id_len + 1 + 2 + result->payload.size();
    buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);

    return result;
}

// --- Utility ---

std::string cell_parser_error_message(CellParserError err) {
    switch (err) {
        case CellParserError::InsufficientData: return "Insufficient data";
        case CellParserError::InvalidLength:    return "Invalid length";
        case CellParserError::InvalidCommand:   return "Invalid command";
        case CellParserError::InvalidPayload:   return "Invalid payload";
        case CellParserError::UnknownVersion:   return "Unknown version";
        case CellParserError::ParseError:       return "Parse error";
        default:                                return "Unknown parser error";
    }
}

}  // namespace tor::protocol
