#pragma once

#include "tor/transport/obfs4.hpp"
#include "tor/net/acceptor.hpp"
#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace tor::transport {

// Callback for established obfs4 connections
// Called after successful handshake with the decrypted stream
using Obfs4ConnectionHandler = std::function<void(
    std::shared_ptr<net::TcpConnection> raw_conn,
    std::unique_ptr<Obfs4Framing> framing
)>;

// obfs4 transport listener
// Accepts TCP connections on a port, performs the obfs4 handshake,
// and proxies decrypted traffic to the local OR port.
class Obfs4Listener {
public:
    Obfs4Listener(
        boost::asio::io_context& io_context,
        const crypto::NodeId& node_id,
        const crypto::Curve25519SecretKey& identity_key,
        IatMode iat_mode = IatMode::Off);

    ~Obfs4Listener();

    // Disable copying
    Obfs4Listener(const Obfs4Listener&) = delete;
    Obfs4Listener& operator=(const Obfs4Listener&) = delete;

    // Start listening on address:port
    [[nodiscard]] std::expected<void, net::AcceptorError>
    start(const std::string& address, uint16_t port);

    // Stop listening
    void stop();

    // Get the obfs4 cert for bridge line generation
    [[nodiscard]] const std::string& cert() const { return cert_; }

    // Set the local OR port to proxy to (default: 9001)
    void set_or_port(uint16_t port) { or_port_ = port; }

    // Statistics
    [[nodiscard]] uint64_t connections_accepted() const {
        return connections_accepted_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t handshakes_completed() const {
        return handshakes_completed_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t handshakes_failed() const {
        return handshakes_failed_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] bool is_listening() const { return listening_; }

private:
    boost::asio::io_context& io_context_;
    crypto::NodeId node_id_;
    const crypto::Curve25519SecretKey& identity_key_;
    [[maybe_unused]] IatMode iat_mode_;
    std::string cert_;

    std::unique_ptr<net::TcpAcceptor> acceptor_;
    uint16_t or_port_{9001};
    std::atomic<bool> listening_{false};

    // Statistics
    std::atomic<uint64_t> connections_accepted_{0};
    std::atomic<uint64_t> handshakes_completed_{0};
    std::atomic<uint64_t> handshakes_failed_{0};

    // Handle a new TCP connection (perform handshake, then proxy)
    void handle_connection(std::shared_ptr<net::TcpConnection> conn);

    // Proxy data between obfs4 connection and local OR port
    void proxy_connection(
        std::shared_ptr<net::TcpConnection> obfs4_conn,
        std::shared_ptr<net::TcpConnection> or_conn,
        std::unique_ptr<Obfs4Framing> framing);
};

}  // namespace tor::transport
