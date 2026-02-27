#include "tor/transport/obfs4_listener.hpp"
#include "tor/util/logging.hpp"
#include <cstring>

namespace tor::transport {

Obfs4Listener::Obfs4Listener(
    boost::asio::io_context& io_context,
    const crypto::NodeId& node_id,
    const crypto::Curve25519SecretKey& identity_key,
    IatMode iat_mode)
    : io_context_(io_context)
    , node_id_(node_id)
    , identity_key_(identity_key)
    , iat_mode_(iat_mode)
{
    // Pre-compute the obfs4 cert at construction time
    Obfs4Identity identity;
    identity.node_id = node_id_;
    identity.ntor_public_key = identity_key_.public_key();
    cert_ = identity.to_cert();
}

Obfs4Listener::~Obfs4Listener() {
    stop();
}

std::expected<void, net::AcceptorError>
Obfs4Listener::start(const std::string& address, uint16_t port) {
    if (listening_) {
        return std::unexpected(net::AcceptorError::AlreadyListening);
    }

    acceptor_ = std::make_unique<net::TcpAcceptor>(io_context_);

    auto listen_result = acceptor_->listen(address, port);
    if (!listen_result) {
        return listen_result;
    }

    LOG_INFO("obfs4 listener started on {}:{}", address, port);
    LOG_INFO("obfs4 cert: {}", cert_);

    // Start accept loop
    acceptor_->start_accept_loop([this](auto result) {
        if (!result) {
            LOG_WARN("obfs4: accept error");
            return;
        }

        auto count = connections_accepted_.fetch_add(1, std::memory_order_relaxed) + 1;
        LOG_INFO("obfs4: accepted connection #{}", count);
        handle_connection(*result);
    });

    listening_ = true;
    return {};
}

void Obfs4Listener::stop() {
    if (!listening_) return;

    if (acceptor_) {
        acceptor_->close();
    }

    listening_ = false;
    LOG_INFO("obfs4 listener stopped");
}

void Obfs4Listener::handle_connection(std::shared_ptr<net::TcpConnection> conn) {
    LOG_INFO("obfs4: starting handshake for new connection");
    auto handshake = std::make_shared<Obfs4ServerHandshake>(node_id_, identity_key_);

    auto stats_completed = &handshakes_completed_;
    auto stats_failed = &handshakes_failed_;
    auto local_or_port = or_port_;
    auto& io = io_context_;

    auto buffer = std::make_shared<std::array<uint8_t, 4096>>();

    // Handshake state machine: read -> consume -> check state -> loop or finish
    struct HandshakeReader {
        std::shared_ptr<net::TcpConnection> conn;
        std::shared_ptr<Obfs4ServerHandshake> handshake;
        std::shared_ptr<std::array<uint8_t, 4096>> buffer;
        std::atomic<uint64_t>* completed;
        std::atomic<uint64_t>* failed;
        uint16_t or_port;
        boost::asio::io_context* io_ctx;

        void start() {
            read_more();
        }

        void read_more() {
            auto bytes_read = conn->read(
                std::span<uint8_t>(buffer->data(), buffer->size()));

            if (!bytes_read || *bytes_read == 0) {
                LOG_WARN("obfs4 handshake: connection closed during read");
                failed->fetch_add(1, std::memory_order_relaxed);
                return;
            }

            LOG_INFO("obfs4 handshake: received {} bytes", *bytes_read);

            auto data = std::span<const uint8_t>(buffer->data(), *bytes_read);
            auto consume_result = handshake->consume(data);
            if (!consume_result) {
                LOG_WARN("obfs4 handshake failed: {}",
                         obfs4_error_message(consume_result.error()));
                failed->fetch_add(1, std::memory_order_relaxed);
                return;
            }

            if (handshake->state() == Obfs4ServerHandshake::State::Completed) {
                auto hello = handshake->generate_server_hello();
                if (!hello) {
                    LOG_ERROR("obfs4: failed to generate server hello");
                    failed->fetch_add(1, std::memory_order_relaxed);
                    return;
                }

                auto hello_span = std::span<const uint8_t>(hello->data(), hello->size());
                auto write_result = conn->write(hello_span);
                if (!write_result) {
                    LOG_ERROR("obfs4: failed to send server hello");
                    failed->fetch_add(1, std::memory_order_relaxed);
                    return;
                }

                completed->fetch_add(1, std::memory_order_relaxed);
                LOG_INFO("obfs4 handshake completed successfully");

                // Set up framing with session keys
                auto framing = std::make_unique<Obfs4Framing>();
                const auto& keys = handshake->session_keys();
                framing->init_send(keys.send_key, keys.send_nonce);
                framing->init_recv(keys.recv_key, keys.recv_nonce);

                // Connect to local OR port and start proxying
                auto or_conn = std::make_shared<net::TcpConnection>(*io_ctx);
                auto connect_result = or_conn->connect("127.0.0.1", or_port);
                if (!connect_result) {
                    LOG_ERROR("obfs4: failed to connect to local OR port {}", or_port);
                    return;
                }

                proxy_loop(conn, or_conn, std::move(framing));
            } else if (handshake->state() == Obfs4ServerHandshake::State::Failed) {
                failed->fetch_add(1, std::memory_order_relaxed);
                return;
            } else {
                read_more();
            }
        }

        void proxy_loop(
            std::shared_ptr<net::TcpConnection> obfs4_conn,
            std::shared_ptr<net::TcpConnection> or_conn,
            std::unique_ptr<Obfs4Framing> framing) {

            auto shared_framing = std::shared_ptr<Obfs4Framing>(std::move(framing));
            auto proxy_buf = std::make_shared<std::array<uint8_t, 4096>>();

            while (true) {
                // Read encrypted data from obfs4 client
                auto obfs4_read = obfs4_conn->read(
                    std::span<uint8_t>(proxy_buf->data(), proxy_buf->size()));
                if (!obfs4_read || *obfs4_read == 0) {
                    break;
                }

                // Decrypt frames
                auto encrypted = std::span<const uint8_t>(proxy_buf->data(), *obfs4_read);
                auto frames = shared_framing->decode(encrypted);
                if (!frames) {
                    LOG_WARN("obfs4: frame decryption failed");
                    break;
                }

                // Forward decrypted data to OR port
                for (const auto& frame : frames->frames) {
                    auto frame_span = std::span<const uint8_t>(frame.data(), frame.size());
                    auto wr = or_conn->write(frame_span);
                    if (!wr) {
                        goto done;
                    }
                }

                // Read plaintext from OR port
                auto or_read = or_conn->read(
                    std::span<uint8_t>(proxy_buf->data(), proxy_buf->size()));
                if (or_read && *or_read > 0) {
                    auto plaintext = std::span<const uint8_t>(proxy_buf->data(), *or_read);
                    auto encoded = shared_framing->encode(plaintext);
                    auto enc_span = std::span<const uint8_t>(encoded.data(), encoded.size());
                    auto wr = obfs4_conn->write(enc_span);
                    if (!wr) {
                        break;
                    }
                }
            }
done:
            obfs4_conn->close();
            or_conn->close();
        }
    };

    auto reader = std::make_shared<HandshakeReader>(
        HandshakeReader{conn, handshake, buffer,
                        stats_completed, stats_failed, local_or_port, &io});
    reader->start();
}

void Obfs4Listener::proxy_connection(
    [[maybe_unused]] std::shared_ptr<net::TcpConnection> obfs4_conn,
    [[maybe_unused]] std::shared_ptr<net::TcpConnection> or_conn,
    [[maybe_unused]] std::unique_ptr<Obfs4Framing> framing) {
    // Proxy logic is handled inside HandshakeReader::proxy_loop
}

}  // namespace tor::transport
