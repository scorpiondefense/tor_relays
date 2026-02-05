#pragma once

#include "tor/crypto/tls.hpp"
#include <boost/asio.hpp>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace tor::net {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// Connection error types
enum class ConnectionError {
    NotConnected,
    AlreadyConnected,
    ConnectionFailed,
    ConnectionRefused,
    ConnectionReset,
    Timeout,
    HostUnreachable,
    NetworkUnreachable,
    AddressInUse,
    TlsError,
    ReadError,
    WriteError,
    Closed,
    InvalidAddress,
};

// Connection state
enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    TlsHandshake,
    Ready,
    Closing,
    Closed,
    Error,
};

// Async read completion handler
using ReadHandler = std::function<void(std::expected<size_t, ConnectionError>)>;

// Async write completion handler
using WriteHandler = std::function<void(std::expected<size_t, ConnectionError>)>;

// Async connect completion handler
using ConnectHandler = std::function<void(std::expected<void, ConnectionError>)>;

// Basic TCP connection
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    explicit TcpConnection(asio::io_context& io_context);
    ~TcpConnection();

    // Disable copying
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    // Synchronous connect
    [[nodiscard]] std::expected<void, ConnectionError>
    connect(const std::string& host, uint16_t port);

    // Asynchronous connect
    void async_connect(
        const std::string& host,
        uint16_t port,
        ConnectHandler handler
    );

    // Initialize from accepted socket
    void accept(tcp::socket socket);

    // Synchronous read
    [[nodiscard]] std::expected<size_t, ConnectionError>
    read(std::span<uint8_t> buffer);

    // Synchronous read exactly n bytes
    [[nodiscard]] std::expected<void, ConnectionError>
    read_exactly(std::span<uint8_t> buffer);

    // Asynchronous read
    void async_read(std::span<uint8_t> buffer, ReadHandler handler);

    // Asynchronous read exactly n bytes
    void async_read_exactly(std::span<uint8_t> buffer, ReadHandler handler);

    // Synchronous write
    [[nodiscard]] std::expected<size_t, ConnectionError>
    write(std::span<const uint8_t> data);

    // Asynchronous write
    void async_write(std::span<const uint8_t> data, WriteHandler handler);

    // Close connection
    void close();

    // State queries
    [[nodiscard]] ConnectionState state() const { return state_; }
    [[nodiscard]] bool is_connected() const {
        return state_ == ConnectionState::Connected ||
               state_ == ConnectionState::Ready;
    }
    [[nodiscard]] bool is_open() const { return socket_.is_open(); }

    // Connection info
    [[nodiscard]] std::string remote_address() const;
    [[nodiscard]] uint16_t remote_port() const;
    [[nodiscard]] std::string local_address() const;
    [[nodiscard]] uint16_t local_port() const;

    // Get native socket
    [[nodiscard]] tcp::socket& socket() { return socket_; }
    [[nodiscard]] const tcp::socket& socket() const { return socket_; }
    [[nodiscard]] int native_handle() const { return static_cast<int>(socket_.native_handle()); }

    // Set socket options
    void set_no_delay(bool enable);
    void set_keep_alive(bool enable);
    void set_receive_buffer_size(size_t size);
    void set_send_buffer_size(size_t size);

    // Timeout settings
    void set_read_timeout(std::chrono::milliseconds timeout);
    void set_write_timeout(std::chrono::milliseconds timeout);
    void set_connect_timeout(std::chrono::milliseconds timeout);

protected:
    asio::io_context& io_context_;
    tcp::socket socket_;
    tcp::resolver resolver_;
    ConnectionState state_{ConnectionState::Disconnected};

    std::chrono::milliseconds read_timeout_{30000};
    std::chrono::milliseconds write_timeout_{30000};
    std::chrono::milliseconds connect_timeout_{30000};
};

// TLS-wrapped TCP connection
class TlsConnection : public TcpConnection {
public:
    TlsConnection(asio::io_context& io_context, crypto::TlsContext& tls_ctx);
    ~TlsConnection();

    // Perform TLS handshake after TCP connect
    [[nodiscard]] std::expected<void, ConnectionError>
    tls_handshake(bool as_client = true);

    // Async TLS handshake
    void async_tls_handshake(bool as_client, ConnectHandler handler);

    // TLS-aware read/write
    [[nodiscard]] std::expected<size_t, ConnectionError>
    read(std::span<uint8_t> buffer);

    [[nodiscard]] std::expected<void, ConnectionError>
    read_exactly(std::span<uint8_t> buffer);

    [[nodiscard]] std::expected<size_t, ConnectionError>
    write(std::span<const uint8_t> data);

    void async_read(std::span<uint8_t> buffer, ReadHandler handler);
    void async_write(std::span<const uint8_t> data, WriteHandler handler);

    // TLS info
    [[nodiscard]] bool is_tls_ready() const { return tls_ready_; }
    [[nodiscard]] std::string cipher() const;
    [[nodiscard]] std::string tls_version() const;

    // Get peer certificate
    [[nodiscard]] std::expected<std::vector<uint8_t>, ConnectionError>
    peer_certificate() const;

    // TLS connection object
    [[nodiscard]] crypto::TlsConnection& tls() { return tls_conn_; }

private:
    crypto::TlsContext& tls_ctx_;
    crypto::TlsConnection tls_conn_;
    bool tls_ready_{false};
};

// Utility
[[nodiscard]] std::string connection_error_message(ConnectionError err);
[[nodiscard]] const char* connection_state_name(ConnectionState state);

// Convert boost error to ConnectionError
[[nodiscard]] ConnectionError from_boost_error(const boost::system::error_code& ec);

}  // namespace tor::net
