#include "tor/core/circuit.hpp"
#include "tor/core/channel.hpp"

namespace tor::core {

// --- Stream ---

Stream::Stream(StreamId id, CircuitId circuit_id)
    : id_(id), circuit_id_(circuit_id) {}

// --- Circuit ---

Circuit::Circuit() = default;

Circuit::Circuit(CircuitId id, CircuitDirection direction)
    : id_(id), direction_(direction) {}

Circuit::~Circuit() = default;

void Circuit::set_crypto(HopCryptoState crypto) {
    crypto_ = std::make_unique<HopCryptoState>(std::move(crypto));
}

std::expected<Cell, CircuitError>
Circuit::encrypt_relay(const RelayCell& relay_cell) {
    if (state_ != CircuitState::Open) {
        return std::unexpected(CircuitError::InvalidState);
    }

    // Build relay cell payload
    Cell cell(id_, CellCommand::RELAY);

    // Relay header: command(1) + recognized(2) + stream_id(2) + digest(4) + length(2) = 11 bytes
    auto& payload = cell.payload;
    payload.fill(0);

    size_t offset = 0;
    payload[offset++] = static_cast<uint8_t>(relay_cell.command);

    // Recognized field (0 for outgoing)
    payload[offset++] = 0;
    payload[offset++] = 0;

    // Stream ID (big-endian)
    payload[offset++] = static_cast<uint8_t>(relay_cell.stream_id >> 8);
    payload[offset++] = static_cast<uint8_t>(relay_cell.stream_id & 0xFF);

    // Digest placeholder (will be computed)
    size_t digest_offset = offset;
    payload[offset++] = 0;
    payload[offset++] = 0;
    payload[offset++] = 0;
    payload[offset++] = 0;

    // Data length (big-endian)
    uint16_t data_len = static_cast<uint16_t>(relay_cell.data.size());
    payload[offset++] = static_cast<uint8_t>(data_len >> 8);
    payload[offset++] = static_cast<uint8_t>(data_len & 0xFF);

    // Copy data
    if (!relay_cell.data.empty()) {
        size_t copy_len = std::min(relay_cell.data.size(),
                                   PAYLOAD_LEN - RELAY_HEADER_LEN);
        std::copy_n(relay_cell.data.begin(), copy_len,
                    payload.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    // Compute digest if crypto is set up
    if (crypto_) {
        auto digest_span = std::span<const uint8_t>(payload.data(), PAYLOAD_LEN);
        auto digest_result = crypto_->forward_digest.update_and_digest(digest_span);
        if (digest_result) {
            uint32_t digest_val = *digest_result;
            payload[digest_offset]     = static_cast<uint8_t>((digest_val >> 24) & 0xFF);
            payload[digest_offset + 1] = static_cast<uint8_t>((digest_val >> 16) & 0xFF);
            payload[digest_offset + 2] = static_cast<uint8_t>((digest_val >> 8) & 0xFF);
            payload[digest_offset + 3] = static_cast<uint8_t>(digest_val & 0xFF);
        }

        // Encrypt
        auto encrypt_span = std::span<uint8_t>(payload.data(), PAYLOAD_LEN);
        auto enc_result = crypto_->forward_cipher.process(encrypt_span);
        if (!enc_result) {
            return std::unexpected(CircuitError::CryptoFailed);
        }
    }

    ++cells_relayed_;
    return cell;
}

std::expected<RelayCell, CircuitError>
Circuit::decrypt_relay(const Cell& cell) {
    if (state_ != CircuitState::Open) {
        return std::unexpected(CircuitError::InvalidState);
    }

    // Make a mutable copy of the payload for decryption
    std::array<uint8_t, PAYLOAD_LEN> payload = cell.payload;

    // Decrypt if crypto is set up
    if (crypto_) {
        auto decrypt_span = std::span<uint8_t>(payload.data(), PAYLOAD_LEN);
        auto dec_result = crypto_->backward_cipher.process(decrypt_span);
        if (!dec_result) {
            return std::unexpected(CircuitError::CryptoFailed);
        }
    }

    // Parse relay header
    size_t offset = 0;
    RelayCell relay;

    relay.command = static_cast<RelayCommand>(payload[offset++]);

    // Recognized field
    relay.recognized = static_cast<uint16_t>(
        (static_cast<uint16_t>(payload[offset]) << 8) |
         static_cast<uint16_t>(payload[offset + 1])
    );
    offset += 2;

    // Stream ID
    relay.stream_id = static_cast<StreamId>(
        (static_cast<uint16_t>(payload[offset]) << 8) |
         static_cast<uint16_t>(payload[offset + 1])
    );
    offset += 2;

    // Digest
    relay.digest = (static_cast<uint32_t>(payload[offset]) << 24) |
                   (static_cast<uint32_t>(payload[offset + 1]) << 16) |
                   (static_cast<uint32_t>(payload[offset + 2]) << 8) |
                    static_cast<uint32_t>(payload[offset + 3]);
    offset += 4;

    // Data length
    uint16_t data_len = static_cast<uint16_t>(
        (static_cast<uint16_t>(payload[offset]) << 8) |
         static_cast<uint16_t>(payload[offset + 1])
    );
    offset += 2;

    // Validate data length
    if (data_len > PAYLOAD_LEN - RELAY_HEADER_LEN) {
        return std::unexpected(CircuitError::CellProcessingFailed);
    }

    // Copy data
    relay.data.assign(
        payload.begin() + static_cast<std::ptrdiff_t>(offset),
        payload.begin() + static_cast<std::ptrdiff_t>(offset + data_len)
    );

    ++cells_relayed_;
    return relay;
}

std::shared_ptr<Stream> Circuit::get_stream(StreamId id) const {
    std::lock_guard lock(streams_mutex_);
    auto it = streams_.find(id);
    if (it != streams_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<Stream> Circuit::create_stream(StreamId id) {
    std::lock_guard lock(streams_mutex_);
    auto stream = std::make_shared<Stream>(id, id_);
    streams_[id] = stream;
    return stream;
}

void Circuit::remove_stream(StreamId id) {
    std::lock_guard lock(streams_mutex_);
    streams_.erase(id);
}

size_t Circuit::stream_count() const {
    std::lock_guard lock(streams_mutex_);
    return streams_.size();
}

void Circuit::close() {
    state_ = CircuitState::Closed;
    std::lock_guard lock(streams_mutex_);
    streams_.clear();
}

// --- CircuitTable ---

void CircuitTable::add(CircuitId id, std::shared_ptr<Circuit> circuit) {
    std::lock_guard lock(mutex_);
    circuits_[id] = std::move(circuit);
}

void CircuitTable::remove(CircuitId id) {
    std::lock_guard lock(mutex_);
    circuits_.erase(id);
}

std::shared_ptr<Circuit> CircuitTable::find(CircuitId id) const {
    std::lock_guard lock(mutex_);
    auto it = circuits_.find(id);
    if (it != circuits_.end()) {
        return it->second;
    }
    return nullptr;
}

bool CircuitTable::contains(CircuitId id) const {
    std::lock_guard lock(mutex_);
    return circuits_.count(id) > 0;
}

std::vector<std::shared_ptr<Circuit>> CircuitTable::all() const {
    std::lock_guard lock(mutex_);
    std::vector<std::shared_ptr<Circuit>> result;
    result.reserve(circuits_.size());
    for (const auto& [id, circuit] : circuits_) {
        result.push_back(circuit);
    }
    return result;
}

size_t CircuitTable::size() const {
    std::lock_guard lock(mutex_);
    return circuits_.size();
}

void CircuitTable::clear() {
    std::lock_guard lock(mutex_);
    circuits_.clear();
}

CircuitId CircuitTable::allocate_id() {
    std::lock_guard lock(mutex_);
    while (circuits_.count(next_id_) > 0) {
        ++next_id_;
        if (next_id_ == 0) next_id_ = 1;  // Skip 0
    }
    return next_id_++;
}

// --- Utility ---

std::string circuit_error_message(CircuitError err) {
    switch (err) {
        case CircuitError::CircuitNotFound:     return "Circuit not found";
        case CircuitError::CircuitClosed:        return "Circuit is closed";
        case CircuitError::CircuitDestroyed:     return "Circuit was destroyed";
        case CircuitError::InvalidState:         return "Invalid circuit state";
        case CircuitError::CryptoFailed:         return "Cryptographic operation failed";
        case CircuitError::CellProcessingFailed: return "Cell processing failed";
        case CircuitError::StreamNotFound:       return "Stream not found";
        case CircuitError::StreamClosed:         return "Stream is closed";
        case CircuitError::TooManyStreams:        return "Too many streams on circuit";
        case CircuitError::ResourceExhausted:    return "Resource exhausted";
        case CircuitError::Timeout:              return "Circuit operation timed out";
        case CircuitError::ProtocolViolation:    return "Protocol violation";
        default:                                 return "Unknown circuit error";
    }
}

const char* circuit_state_name(CircuitState state) {
    switch (state) {
        case CircuitState::Building: return "Building";
        case CircuitState::Open:     return "Open";
        case CircuitState::Closing:  return "Closing";
        case CircuitState::Closed:   return "Closed";
        case CircuitState::Failed:   return "Failed";
        default:                     return "Unknown";
    }
}

}  // namespace tor::core
