// Implementation - net/connection.cpp
#include "tor/net/connection.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

namespace tor::net {

// TcpConnection implementation
TcpConnection::TcpConnection(asio::io_context& io_context)
    : io_context_(io_context)
    , socket_(io_context)
    , resolver_(io_context) {}

TcpConnection::~TcpConnection() {
    close();
}

std::expected<void, ConnectionError> TcpConnection::connect(
    const std::string& host, uint16_t port) {
    try {
        state_ = ConnectionState::Connecting;
        boost::system::error_code ec;
        auto endpoints = resolver_.resolve(host, std::to_string(port), ec);
        if (ec) {
            state_ = ConnectionState::Error;
            return std::unexpected(ConnectionError::InvalidAddress);
        }
        
        boost::asio::connect(socket_, endpoints, ec);
        if (ec) {
            state_ = ConnectionState::Error;
            return std::unexpected(from_boost_error(ec));
        }
        
        state_ = ConnectionState::Connected;
        return {};
    } catch (...) {
        state_ = ConnectionState::Error;
        return std::unexpected(ConnectionError::ConnectionFailed);
    }
}

void TcpConnection::async_connect(
    const std::string& host, uint16_t port, ConnectHandler handler) {
    state_ = ConnectionState::Connecting;
    resolver_.async_resolve(host, std::to_string(port),
        [this, handler](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
            if (ec) {
                state_ = ConnectionState::Error;
                handler(std::unexpected(ConnectionError::InvalidAddress));
                return;
            }
            boost::asio::async_connect(socket_, endpoints,
                [this, handler](boost::system::error_code ec, const tcp::endpoint&) {
                    if (ec) {
                        state_ = ConnectionState::Error;
                        handler(std::unexpected(from_boost_error(ec)));
                    } else {
                        state_ = ConnectionState::Connected;
                        handler({});
                    }
                });
        });
}

void TcpConnection::accept(tcp::socket socket) {
    socket_ = std::move(socket);
    state_ = ConnectionState::Connected;
}

std::expected<size_t, ConnectionError> TcpConnection::read(std::span<uint8_t> buffer) {
    if (!is_connected()) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    try {
        boost::system::error_code ec;
        size_t bytes = socket_.read_some(boost::asio::buffer(buffer.data(), buffer.size()), ec);
        if (ec) {
            return std::unexpected(from_boost_error(ec));
        }
        return bytes;
    } catch (...) {
        return std::unexpected(ConnectionError::ReadError);
    }
}

std::expected<void, ConnectionError> TcpConnection::read_exactly(std::span<uint8_t> buffer) {
    if (!is_connected()) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    try {
        boost::system::error_code ec;
        boost::asio::read(socket_, boost::asio::buffer(buffer.data(), buffer.size()), ec);
        if (ec) {
            return std::unexpected(from_boost_error(ec));
        }
        return {};
    } catch (...) {
        return std::unexpected(ConnectionError::ReadError);
    }
}

void TcpConnection::async_read(std::span<uint8_t> buffer, ReadHandler handler) {
    socket_.async_read_some(boost::asio::buffer(buffer.data(), buffer.size()),
        [handler](boost::system::error_code ec, size_t bytes) {
            if (ec) {
                handler(std::unexpected(from_boost_error(ec)));
            } else {
                handler(bytes);
            }
        });
}

void TcpConnection::async_read_exactly(std::span<uint8_t> buffer, ReadHandler handler) {
    boost::asio::async_read(socket_, boost::asio::buffer(buffer.data(), buffer.size()),
        [handler](boost::system::error_code ec, size_t bytes) {
            if (ec) {
                handler(std::unexpected(from_boost_error(ec)));
            } else {
                handler(bytes);
            }
        });
}

std::expected<size_t, ConnectionError> TcpConnection::write(std::span<const uint8_t> data) {
    if (!is_connected()) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    try {
        boost::system::error_code ec;
        size_t bytes = boost::asio::write(socket_, boost::asio::buffer(data.data(), data.size()), ec);
        if (ec) {
            return std::unexpected(from_boost_error(ec));
        }
        return bytes;
    } catch (...) {
        return std::unexpected(ConnectionError::WriteError);
    }
}

void TcpConnection::async_write(std::span<const uint8_t> data, WriteHandler handler) {
    boost::asio::async_write(socket_, boost::asio::buffer(data.data(), data.size()),
        [handler](boost::system::error_code ec, size_t bytes) {
            if (ec) {
                handler(std::unexpected(from_boost_error(ec)));
            } else {
                handler(bytes);
            }
        });
}

void TcpConnection::close() {
    if (socket_.is_open()) {
        state_ = ConnectionState::Closing;
        boost::system::error_code ec;
        socket_.shutdown(tcp::socket::shutdown_both, ec);
        socket_.close(ec);
        state_ = ConnectionState::Closed;
    }
}

std::string TcpConnection::remote_address() const {
    if (!socket_.is_open()) return "";
    boost::system::error_code ec;
    auto endpoint = socket_.remote_endpoint(ec);
    if (ec) return "";
    return endpoint.address().to_string();
}

uint16_t TcpConnection::remote_port() const {
    if (!socket_.is_open()) return 0;
    boost::system::error_code ec;
    auto endpoint = socket_.remote_endpoint(ec);
    if (ec) return 0;
    return endpoint.port();
}

std::string TcpConnection::local_address() const {
    if (!socket_.is_open()) return "";
    boost::system::error_code ec;
    auto endpoint = socket_.local_endpoint(ec);
    if (ec) return "";
    return endpoint.address().to_string();
}

uint16_t TcpConnection::local_port() const {
    if (!socket_.is_open()) return 0;
    boost::system::error_code ec;
    auto endpoint = socket_.local_endpoint(ec);
    if (ec) return 0;
    return endpoint.port();
}

void TcpConnection::set_no_delay(bool enable) {
    boost::system::error_code ec;
    socket_.set_option(tcp::no_delay(enable), ec);
}

void TcpConnection::set_keep_alive(bool enable) {
    boost::system::error_code ec;
    socket_.set_option(boost::asio::socket_base::keep_alive(enable), ec);
}

void TcpConnection::set_receive_buffer_size(size_t size) {
    boost::system::error_code ec;
    socket_.set_option(boost::asio::socket_base::receive_buffer_size(static_cast<int>(size)), ec);
}

void TcpConnection::set_send_buffer_size(size_t size) {
    boost::system::error_code ec;
    socket_.set_option(boost::asio::socket_base::send_buffer_size(static_cast<int>(size)), ec);
}

void TcpConnection::set_read_timeout(std::chrono::milliseconds timeout) {
    read_timeout_ = timeout;
}

void TcpConnection::set_write_timeout(std::chrono::milliseconds timeout) {
    write_timeout_ = timeout;
}

void TcpConnection::set_connect_timeout(std::chrono::milliseconds timeout) {
    connect_timeout_ = timeout;
}

// TlsConnection implementation
TlsConnection::TlsConnection(asio::io_context& io_context, crypto::TlsContext& tls_ctx)
    : TcpConnection(io_context)
    , tls_ctx_(tls_ctx) {}

TlsConnection::~TlsConnection() = default;

std::expected<void, ConnectionError> TlsConnection::tls_handshake(bool as_client) {
    if (!socket_.is_open()) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    state_ = ConnectionState::TlsHandshake;
    
    // Initialize TLS connection with context and socket fd
    auto init_result = tls_conn_.init(tls_ctx_, socket_.native_handle());
    if (!init_result) {
        state_ = ConnectionState::Error;
        return std::unexpected(ConnectionError::TlsError);
    }
    
    // Perform handshake based on role
    std::expected<void, crypto::TlsError> result;
    if (as_client) {
        result = tls_conn_.connect();
    } else {
        result = tls_conn_.accept();
    }
    
    if (!result) {
        state_ = ConnectionState::Error;
        return std::unexpected(ConnectionError::TlsError);
    }
    
    tls_ready_ = true;
    state_ = ConnectionState::Ready;
    return {};
}

void TlsConnection::async_tls_handshake(bool as_client, ConnectHandler handler) {
    // Async handshake - for now, run sync in a post
    auto result = tls_handshake(as_client);
    boost::asio::post(io_context_, [handler, result]() {
        handler(result);
    });
}

std::expected<size_t, ConnectionError> TlsConnection::read(std::span<uint8_t> buffer) {
    if (!tls_ready_) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    auto result = tls_conn_.read(buffer);
    if (!result) {
        return std::unexpected(ConnectionError::ReadError);
    }
    return *result;
}

std::expected<void, ConnectionError> TlsConnection::read_exactly(std::span<uint8_t> buffer) {
    if (!tls_ready_) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    size_t total = 0;
    while (total < buffer.size()) {
        auto result = tls_conn_.read(buffer.subspan(total));
        if (!result) {
            return std::unexpected(ConnectionError::ReadError);
        }
        total += *result;
    }
    return {};
}

std::expected<size_t, ConnectionError> TlsConnection::write(std::span<const uint8_t> data) {
    if (!tls_ready_) {
        return std::unexpected(ConnectionError::NotConnected);
    }
    auto result = tls_conn_.write(data);
    if (!result) {
        return std::unexpected(ConnectionError::WriteError);
    }
    return *result;
}

void TlsConnection::async_read(std::span<uint8_t> buffer, ReadHandler handler) {
    // Async read - run sync in a post for now
    auto result = read(buffer);
    boost::asio::post(io_context_, [handler, result]() {
        handler(result);
    });
}

void TlsConnection::async_write(std::span<const uint8_t> data, WriteHandler handler) {
    // Async write - run sync in a post for now
    auto result = write(data);
    boost::asio::post(io_context_, [handler, result]() {
        handler(result);
    });
}

std::string TlsConnection::cipher() const {
    return tls_conn_.get_cipher();
}

std::string TlsConnection::tls_version() const {
    return tls_conn_.get_version();
}

std::expected<std::vector<uint8_t>, ConnectionError> TlsConnection::peer_certificate() const {
    auto result = tls_conn_.get_peer_certificate();
    if (!result) {
        return std::unexpected(ConnectionError::TlsError);
    }
    return *result;
}

// Utility functions
std::string connection_error_message(ConnectionError err) {
    switch (err) {
        case ConnectionError::NotConnected: return "Not connected";
        case ConnectionError::AlreadyConnected: return "Already connected";
        case ConnectionError::ConnectionFailed: return "Connection failed";
        case ConnectionError::ConnectionRefused: return "Connection refused";
        case ConnectionError::ConnectionReset: return "Connection reset";
        case ConnectionError::Timeout: return "Connection timeout";
        case ConnectionError::HostUnreachable: return "Host unreachable";
        case ConnectionError::NetworkUnreachable: return "Network unreachable";
        case ConnectionError::AddressInUse: return "Address in use";
        case ConnectionError::TlsError: return "TLS error";
        case ConnectionError::ReadError: return "Read error";
        case ConnectionError::WriteError: return "Write error";
        case ConnectionError::Closed: return "Connection closed";
        case ConnectionError::InvalidAddress: return "Invalid address";
        default: return "Unknown connection error";
    }
}

const char* connection_state_name(ConnectionState state) {
    switch (state) {
        case ConnectionState::Disconnected: return "Disconnected";
        case ConnectionState::Connecting: return "Connecting";
        case ConnectionState::Connected: return "Connected";
        case ConnectionState::TlsHandshake: return "TlsHandshake";
        case ConnectionState::Ready: return "Ready";
        case ConnectionState::Closing: return "Closing";
        case ConnectionState::Closed: return "Closed";
        case ConnectionState::Error: return "Error";
        default: return "Unknown";
    }
}

ConnectionError from_boost_error(const boost::system::error_code& ec) {
    if (ec == boost::asio::error::connection_refused) {
        return ConnectionError::ConnectionRefused;
    }
    if (ec == boost::asio::error::connection_reset) {
        return ConnectionError::ConnectionReset;
    }
    if (ec == boost::asio::error::timed_out) {
        return ConnectionError::Timeout;
    }
    if (ec == boost::asio::error::host_unreachable) {
        return ConnectionError::HostUnreachable;
    }
    if (ec == boost::asio::error::network_unreachable) {
        return ConnectionError::NetworkUnreachable;
    }
    if (ec == boost::asio::error::address_in_use) {
        return ConnectionError::AddressInUse;
    }
    if (ec == boost::asio::error::eof || ec == boost::asio::error::broken_pipe) {
        return ConnectionError::Closed;
    }
    return ConnectionError::ConnectionFailed;
}

}  // namespace tor::net
