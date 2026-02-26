#pragma once

#include "tor/core/cell.hpp"
#include "tor/crypto/aes_ctr.hpp"
#include "tor/crypto/hash.hpp"
#include "tor/crypto/keys.hpp"
#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Forward declarations
namespace tor::core {
class Channel;
}

namespace tor::core {

// Circuit error types
enum class CircuitError {
    CircuitNotFound,
    CircuitClosed,
    CircuitDestroyed,
    InvalidState,
    CryptoFailed,
    CellProcessingFailed,
    StreamNotFound,
    StreamClosed,
    TooManyStreams,
    ResourceExhausted,
    Timeout,
    ProtocolViolation,
};

// Circuit state
enum class CircuitState {
    Building,       // Handshake in progress
    Open,           // Ready for relay cells
    Closing,        // Teardown in progress
    Closed,         // Fully closed
    Failed,         // Creation failed
};

// Circuit direction (relative to this relay)
enum class CircuitDirection {
    Forward,   // Toward the exit/destination
    Backward,  // Toward the origin/client
};

// Crypto state for one hop of a circuit
struct HopCryptoState {
    crypto::AesCtr128 forward_cipher;   // Encrypt for forward direction
    crypto::AesCtr128 backward_cipher;  // Encrypt for backward direction
    crypto::RunningDigest forward_digest;  // Digest for forward cells
    crypto::RunningDigest backward_digest; // Digest for backward cells

    HopCryptoState() = default;
    HopCryptoState(HopCryptoState&&) = default;
    HopCryptoState& operator=(HopCryptoState&&) = default;

    // Non-copyable
    HopCryptoState(const HopCryptoState&) = delete;
    HopCryptoState& operator=(const HopCryptoState&) = delete;
};

// Stream within a circuit
class Stream {
public:
    enum class State {
        Connecting,
        Open,
        HalfClosed,
        Closed,
    };

    Stream() = default;
    Stream(StreamId id, CircuitId circuit_id);
    ~Stream() = default;

    [[nodiscard]] StreamId id() const { return id_; }
    [[nodiscard]] CircuitId circuit_id() const { return circuit_id_; }
    [[nodiscard]] State state() const { return state_; }
    [[nodiscard]] bool is_open() const { return state_ == State::Open; }

    void set_state(State state) { state_ = state; }

    // Flow control
    [[nodiscard]] int32_t delivery_window() const { return delivery_window_; }
    [[nodiscard]] int32_t package_window() const { return package_window_; }
    void decrement_delivery_window() { --delivery_window_; }
    void decrement_package_window() { --package_window_; }
    void increment_delivery_window(int32_t amount) { delivery_window_ += amount; }
    void increment_package_window(int32_t amount) { package_window_ += amount; }

private:
    StreamId id_{0};
    CircuitId circuit_id_{0};
    State state_{State::Connecting};

    // SENDME flow control windows
    int32_t delivery_window_{500};
    int32_t package_window_{500};
};

// Circuit represents one hop's view of a circuit
class Circuit : public std::enable_shared_from_this<Circuit> {
public:
    Circuit();
    Circuit(CircuitId id, CircuitDirection direction);
    ~Circuit();

    // Non-copyable
    Circuit(const Circuit&) = delete;
    Circuit& operator=(const Circuit&) = delete;

    // Identity
    [[nodiscard]] CircuitId id() const { return id_; }
    [[nodiscard]] CircuitState state() const { return state_; }
    [[nodiscard]] CircuitDirection direction() const { return direction_; }

    void set_state(CircuitState state) { state_ = state; }
    void set_id(CircuitId id) { id_ = id; }

    // Channel management (prev = toward client, next = toward exit)
    [[nodiscard]] std::shared_ptr<Channel> prev_hop_channel() const { return prev_channel_; }
    [[nodiscard]] std::shared_ptr<Channel> next_hop_channel() const { return next_channel_; }
    void set_prev_hop_channel(std::shared_ptr<Channel> ch) { prev_channel_ = std::move(ch); }
    void set_next_hop_channel(std::shared_ptr<Channel> ch) { next_channel_ = std::move(ch); }

    // Circuit IDs at each end (may differ)
    [[nodiscard]] CircuitId prev_circuit_id() const { return prev_circuit_id_; }
    [[nodiscard]] CircuitId next_circuit_id() const { return next_circuit_id_; }
    void set_prev_circuit_id(CircuitId id) { prev_circuit_id_ = id; }
    void set_next_circuit_id(CircuitId id) { next_circuit_id_ = id; }

    // Crypto operations
    void set_crypto(HopCryptoState crypto);

    // Encrypt relay cell for sending
    [[nodiscard]] std::expected<Cell, CircuitError>
    encrypt_relay(const RelayCell& relay_cell);

    // Decrypt relay cell received
    [[nodiscard]] std::expected<RelayCell, CircuitError>
    decrypt_relay(const Cell& cell);

    // Stream management
    [[nodiscard]] std::shared_ptr<Stream> get_stream(StreamId id) const;
    [[nodiscard]] std::shared_ptr<Stream> create_stream(StreamId id);
    void remove_stream(StreamId id);
    [[nodiscard]] size_t stream_count() const;

    // Flow control
    [[nodiscard]] int32_t delivery_window() const { return delivery_window_; }
    [[nodiscard]] int32_t package_window() const { return package_window_; }
    void decrement_delivery_window() { --delivery_window_; }
    void decrement_package_window() { --package_window_; }
    void increment_delivery_window(int32_t amount) { delivery_window_ += amount; }
    void increment_package_window(int32_t amount) { package_window_ += amount; }

    // Statistics
    [[nodiscard]] uint64_t cells_relayed() const { return cells_relayed_; }

    // Close the circuit
    void close();

private:
    CircuitId id_{0};
    CircuitState state_{CircuitState::Building};
    CircuitDirection direction_{CircuitDirection::Forward};

    // Channels to adjacent hops
    std::shared_ptr<Channel> prev_channel_;
    std::shared_ptr<Channel> next_channel_;
    CircuitId prev_circuit_id_{0};
    CircuitId next_circuit_id_{0};

    // Crypto state for this hop
    std::unique_ptr<HopCryptoState> crypto_;

    // Active streams
    mutable std::mutex streams_mutex_;
    std::unordered_map<StreamId, std::shared_ptr<Stream>> streams_;

    // Flow control (circuit-level SENDME)
    int32_t delivery_window_{1000};
    int32_t package_window_{1000};

    // Statistics
    std::atomic<uint64_t> cells_relayed_{0};
};

// Circuit table: maps circuit IDs to circuits on a given channel
class CircuitTable {
public:
    CircuitTable() = default;
    ~CircuitTable() = default;

    // Add circuit
    void add(CircuitId id, std::shared_ptr<Circuit> circuit);

    // Remove circuit
    void remove(CircuitId id);

    // Find circuit by ID
    [[nodiscard]] std::shared_ptr<Circuit> find(CircuitId id) const;

    // Check if circuit exists
    [[nodiscard]] bool contains(CircuitId id) const;

    // Get all circuits
    [[nodiscard]] std::vector<std::shared_ptr<Circuit>> all() const;

    // Get circuit count
    [[nodiscard]] size_t size() const;

    // Clear all circuits
    void clear();

    // Generate a new unique circuit ID
    [[nodiscard]] CircuitId allocate_id();

private:
    mutable std::mutex mutex_;
    std::unordered_map<CircuitId, std::shared_ptr<Circuit>> circuits_;
    CircuitId next_id_{1};
};

// Utility
[[nodiscard]] std::string circuit_error_message(CircuitError err);
[[nodiscard]] const char* circuit_state_name(CircuitState state);

}  // namespace tor::core
