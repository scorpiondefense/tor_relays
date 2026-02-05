#pragma once

#include "tor/net/connection.hpp"
#include "tor/crypto/tls.hpp"
#include <boost/asio.hpp>
#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace tor::net {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// Acceptor error types
enum class AcceptorError {
    BindFailed,
    ListenFailed,
    AcceptFailed,
    AlreadyListening,
    NotListening,
    Closed,
};

// Accepted connection handler
using AcceptHandler = std::function<void(
    std::expected<std::shared_ptr<TcpConnection>, AcceptorError>
)>;

// TLS accepted connection handler
using TlsAcceptHandler = std::function<void(
    std::expected<std::shared_ptr<TlsConnection>, AcceptorError>
)>;

// TCP connection acceptor
class TcpAcceptor {
public:
    explicit TcpAcceptor(asio::io_context& io_context);
    ~TcpAcceptor();

    // Disable copying
    TcpAcceptor(const TcpAcceptor&) = delete;
    TcpAcceptor& operator=(const TcpAcceptor&) = delete;

    // Start listening on address:port
    [[nodiscard]] std::expected<void, AcceptorError>
    listen(const std::string& address, uint16_t port, int backlog = 128);

    // Start listening on port (all interfaces)
    [[nodiscard]] std::expected<void, AcceptorError>
    listen(uint16_t port, int backlog = 128);

    // Start listening on IPv6
    [[nodiscard]] std::expected<void, AcceptorError>
    listen_ipv6(const std::string& address, uint16_t port, int backlog = 128);

    // Synchronous accept
    [[nodiscard]] std::expected<std::shared_ptr<TcpConnection>, AcceptorError>
    accept();

    // Asynchronous accept
    void async_accept(AcceptHandler handler);

    // Accept loop (calls handler for each connection until stopped)
    void start_accept_loop(AcceptHandler handler);

    // Stop accepting
    void stop();

    // Close acceptor
    void close();

    // State queries
    [[nodiscard]] bool is_listening() const { return listening_; }
    [[nodiscard]] bool is_open() const { return acceptor_.is_open(); }

    // Listening info
    [[nodiscard]] std::string local_address() const;
    [[nodiscard]] uint16_t local_port() const;

    // Socket options
    void set_reuse_address(bool enable);
    void set_reuse_port(bool enable);

protected:
    asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    std::atomic<bool> listening_{false};
    std::atomic<bool> accept_loop_running_{false};
};

// TLS connection acceptor
class TlsAcceptor : public TcpAcceptor {
public:
    TlsAcceptor(asio::io_context& io_context, crypto::TlsContext& tls_ctx);
    ~TlsAcceptor();

    // Accept and perform TLS handshake
    [[nodiscard]] std::expected<std::shared_ptr<TlsConnection>, AcceptorError>
    accept();

    // Async accept with TLS handshake
    void async_accept(TlsAcceptHandler handler);

    // Accept loop with TLS
    void start_accept_loop(TlsAcceptHandler handler);

private:
    crypto::TlsContext& tls_ctx_;
};

// Multi-address acceptor (listens on multiple addresses/ports)
class MultiAcceptor {
public:
    explicit MultiAcceptor(asio::io_context& io_context);
    ~MultiAcceptor();

    // Add listening address
    [[nodiscard]] std::expected<void, AcceptorError>
    add_listener(const std::string& address, uint16_t port);

    // Add IPv6 listener
    [[nodiscard]] std::expected<void, AcceptorError>
    add_ipv6_listener(const std::string& address, uint16_t port);

    // Start all listeners
    void start(AcceptHandler handler);

    // Stop all listeners
    void stop();

    // Get number of listeners
    [[nodiscard]] size_t listener_count() const { return acceptors_.size(); }

private:
    asio::io_context& io_context_;
    std::vector<std::unique_ptr<TcpAcceptor>> acceptors_;
};

// Utility
[[nodiscard]] std::string acceptor_error_message(AcceptorError err);

}  // namespace tor::net
