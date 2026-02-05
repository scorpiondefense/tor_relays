#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <span>
#include <vector>

namespace tor::test {

// Mock socket for network testing without real connections
class MockSocket {
public:
    MockSocket() = default;

    // Inject data to be read from socket
    void inject_data(std::span<const uint8_t> data) {
        std::lock_guard<std::mutex> lock(mutex_);
        read_buffer_.insert(read_buffer_.end(), data.begin(), data.end());
    }

    // Read from socket (returns injected data)
    size_t read(std::span<uint8_t> buffer) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t to_read = std::min(buffer.size(), read_buffer_.size());
        std::copy(read_buffer_.begin(), read_buffer_.begin() + to_read, buffer.begin());
        read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + to_read);
        return to_read;
    }

    // Write to socket (stores in send buffer)
    size_t write(std::span<const uint8_t> data) {
        std::lock_guard<std::mutex> lock(mutex_);
        sent_data_.insert(sent_data_.end(), data.begin(), data.end());
        return data.size();
    }

    // Get all data that was "sent"
    std::vector<uint8_t> drain_sent_data() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto data = std::move(sent_data_);
        sent_data_.clear();
        return data;
    }

    // Check if there's data to read
    bool has_data() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return !read_buffer_.empty();
    }

    // Connect two mock sockets (bidirectional)
    void connect_to(MockSocket& peer) {
        peer_ = &peer;
        peer.peer_ = this;
    }

    // Transfer sent data to peer's read buffer
    void flush_to_peer() {
        if (!peer_) return;

        std::lock_guard<std::mutex> lock(mutex_);
        std::lock_guard<std::mutex> peer_lock(peer_->mutex_);

        peer_->read_buffer_.insert(peer_->read_buffer_.end(),
                                   sent_data_.begin(), sent_data_.end());
        sent_data_.clear();
    }

    // Clear all buffers
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        read_buffer_.clear();
        sent_data_.clear();
    }

private:
    std::vector<uint8_t> read_buffer_;
    std::vector<uint8_t> sent_data_;
    MockSocket* peer_{nullptr};
    mutable std::mutex mutex_;
};

// Mock channel for testing
class MockChannel {
public:
    MockChannel() = default;

    void set_socket(MockSocket* socket) { socket_ = socket; }
    MockSocket* socket() { return socket_; }

    // Simulate sending a cell
    template<typename Cell>
    void send_cell(const Cell& cell) {
        auto data = cell.serialize();
        if (socket_) {
            socket_->write(std::span<const uint8_t>(data.data(), data.size()));
        }
    }

    // Receive cell data
    std::vector<uint8_t> receive_data(size_t max_size) {
        std::vector<uint8_t> buffer(max_size);
        if (socket_) {
            size_t read = socket_->read(buffer);
            buffer.resize(read);
        }
        return buffer;
    }

private:
    MockSocket* socket_{nullptr};
};

}  // namespace tor::test
