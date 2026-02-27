// Implementation - net/acceptor.cpp
#include "tor/net/acceptor.hpp"
#include <boost/asio/ip/tcp.hpp>

namespace tor::net {

// TcpAcceptor implementation
TcpAcceptor::TcpAcceptor(asio::io_context& io_context)
    : io_context_(io_context)
    , acceptor_(io_context) {}

TcpAcceptor::~TcpAcceptor() {
    close();
}

std::expected<void, AcceptorError> TcpAcceptor::listen(
    const std::string& address, uint16_t port, int backlog) {
    if (listening_) {
        return std::unexpected(AcceptorError::AlreadyListening);
    }

    try {
        boost::system::error_code ec;
        auto endpoint = tcp::endpoint(asio::ip::make_address(address, ec), port);
        if (ec) {
            return std::unexpected(AcceptorError::BindFailed);
        }

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            return std::unexpected(AcceptorError::BindFailed);
        }

        acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(endpoint, ec);
        if (ec) {
            return std::unexpected(AcceptorError::BindFailed);
        }

        acceptor_.listen(backlog, ec);
        if (ec) {
            return std::unexpected(AcceptorError::ListenFailed);
        }

        listening_ = true;
        return {};
    } catch (...) {
        return std::unexpected(AcceptorError::BindFailed);
    }
}

std::expected<void, AcceptorError> TcpAcceptor::listen(uint16_t port, int backlog) {
    return listen("0.0.0.0", port, backlog);
}

std::expected<void, AcceptorError> TcpAcceptor::listen_ipv6(
    const std::string& address, uint16_t port, int backlog) {
    if (listening_) {
        return std::unexpected(AcceptorError::AlreadyListening);
    }

    try {
        boost::system::error_code ec;
        auto endpoint = tcp::endpoint(asio::ip::make_address_v6(address, ec), port);
        if (ec) {
            return std::unexpected(AcceptorError::BindFailed);
        }

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            return std::unexpected(AcceptorError::BindFailed);
        }

        acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(endpoint, ec);
        if (ec) {
            return std::unexpected(AcceptorError::BindFailed);
        }

        acceptor_.listen(backlog, ec);
        if (ec) {
            return std::unexpected(AcceptorError::ListenFailed);
        }

        listening_ = true;
        return {};
    } catch (...) {
        return std::unexpected(AcceptorError::BindFailed);
    }
}

std::expected<std::shared_ptr<TcpConnection>, AcceptorError> TcpAcceptor::accept() {
    if (!listening_) {
        return std::unexpected(AcceptorError::NotListening);
    }

    try {
        boost::system::error_code ec;
        tcp::socket socket(io_context_);
        acceptor_.accept(socket, ec);
        if (ec) {
            return std::unexpected(AcceptorError::AcceptFailed);
        }
        auto conn = std::make_shared<TcpConnection>(io_context_);
        conn->accept(std::move(socket));
        return conn;
    } catch (...) {
        return std::unexpected(AcceptorError::AcceptFailed);
    }
}

void TcpAcceptor::async_accept(AcceptHandler handler) {
    if (!listening_) {
        handler(std::unexpected(AcceptorError::NotListening));
        return;
    }

    auto socket = std::make_shared<tcp::socket>(io_context_);
    acceptor_.async_accept(*socket, [this, socket, handler](boost::system::error_code ec) {
        if (ec) {
            handler(std::unexpected(AcceptorError::AcceptFailed));
        } else {
            auto conn = std::make_shared<TcpConnection>(io_context_);
            conn->accept(std::move(*socket));
            handler(conn);
        }
    });
}

void TcpAcceptor::start_accept_loop(AcceptHandler handler) {
    accept_loop_running_ = true;
    async_accept([this, handler](auto result) {
        handler(result);
        if (accept_loop_running_ && listening_) {
            start_accept_loop(handler);
        }
    });
}

void TcpAcceptor::stop() {
    accept_loop_running_ = false;
    listening_ = false;
    boost::system::error_code ec;
    acceptor_.cancel(ec);
}

void TcpAcceptor::close() {
    stop();
    boost::system::error_code ec;
    acceptor_.close(ec);
}

std::string TcpAcceptor::local_address() const {
    if (!acceptor_.is_open()) return "";
    boost::system::error_code ec;
    auto endpoint = acceptor_.local_endpoint(ec);
    if (ec) return "";
    return endpoint.address().to_string();
}

uint16_t TcpAcceptor::local_port() const {
    if (!acceptor_.is_open()) return 0;
    boost::system::error_code ec;
    auto endpoint = acceptor_.local_endpoint(ec);
    if (ec) return 0;
    return endpoint.port();
}

void TcpAcceptor::set_reuse_address(bool enable) {
    boost::system::error_code ec;
    acceptor_.set_option(tcp::acceptor::reuse_address(enable), ec);
}

void TcpAcceptor::set_reuse_port(bool enable) {
    // SO_REUSEPORT may not be available on all platforms
#ifdef SO_REUSEPORT
    boost::system::error_code ec;
    acceptor_.set_option(boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>(enable), ec);
#endif
}

// TlsAcceptor implementation
TlsAcceptor::TlsAcceptor(asio::io_context& io_context, crypto::TlsContext& tls_ctx)
    : TcpAcceptor(io_context)
    , tls_ctx_(tls_ctx) {}

TlsAcceptor::~TlsAcceptor() = default;

std::expected<std::shared_ptr<TlsConnection>, AcceptorError> TlsAcceptor::accept() {
    // Create TLS connection
    auto tls_conn = std::make_shared<TlsConnection>(io_context_, tls_ctx_);
    
    // Accept TCP connection
    boost::system::error_code ec;
    acceptor_.accept(tls_conn->socket(), ec);
    if (ec) {
        return std::unexpected(AcceptorError::AcceptFailed);
    }
    
    // Perform TLS handshake (server side)
    auto handshake_result = tls_conn->tls_handshake(false);  // false = server
    if (!handshake_result) {
        return std::unexpected(AcceptorError::AcceptFailed);
    }
    return tls_conn;
}

void TlsAcceptor::async_accept(TlsAcceptHandler handler) {
    auto tls_conn = std::make_shared<TlsConnection>(io_context_, tls_ctx_);
    acceptor_.async_accept(tls_conn->socket(), [handler, tls_conn](boost::system::error_code ec) {
        if (ec) {
            handler(std::unexpected(AcceptorError::AcceptFailed));
            return;
        }
        
        tls_conn->async_tls_handshake(false, [handler, tls_conn](auto hs_result) {
            if (!hs_result) {
                handler(std::unexpected(AcceptorError::AcceptFailed));
            } else {
                handler(tls_conn);
            }
        });
    });
}

void TlsAcceptor::start_accept_loop(TlsAcceptHandler handler) {
    accept_loop_running_ = true;
    async_accept([this, handler](auto result) {
        handler(result);
        if (accept_loop_running_ && listening_) {
            start_accept_loop(handler);
        }
    });
}

// MultiAcceptor implementation
MultiAcceptor::MultiAcceptor(asio::io_context& io_context)
    : io_context_(io_context) {}

MultiAcceptor::~MultiAcceptor() {
    stop();
}

std::expected<void, AcceptorError> MultiAcceptor::add_listener(
    const std::string& address, uint16_t port) {
    auto acceptor = std::make_unique<TcpAcceptor>(io_context_);
    auto result = acceptor->listen(address, port);
    if (!result) {
        return result;
    }
    acceptors_.push_back(std::move(acceptor));
    return {};
}

std::expected<void, AcceptorError> MultiAcceptor::add_ipv6_listener(
    const std::string& address, uint16_t port) {
    auto acceptor = std::make_unique<TcpAcceptor>(io_context_);
    auto result = acceptor->listen_ipv6(address, port);
    if (!result) {
        return result;
    }
    acceptors_.push_back(std::move(acceptor));
    return {};
}

void MultiAcceptor::start(AcceptHandler handler) {
    for (auto& acceptor : acceptors_) {
        acceptor->start_accept_loop(handler);
    }
}

void MultiAcceptor::stop() {
    for (auto& acceptor : acceptors_) {
        acceptor->stop();
    }
}

// Utility
std::string acceptor_error_message(AcceptorError err) {
    switch (err) {
        case AcceptorError::BindFailed: return "Failed to bind to address";
        case AcceptorError::ListenFailed: return "Failed to start listening";
        case AcceptorError::AcceptFailed: return "Failed to accept connection";
        case AcceptorError::AlreadyListening: return "Already listening";
        case AcceptorError::NotListening: return "Not listening";
        case AcceptorError::Closed: return "Acceptor closed";
        default: return "Unknown acceptor error";
    }
}

}  // namespace tor::net
