#include "tor/transport/obfs4_listener.hpp"
#include "tor/util/logging.hpp"
#include "obfs4/transport/packet.hpp"
#include "obfs4/transport/framing.hpp"
#include "obfs4/common/csrand.hpp"
#include <cstring>
#include <thread>
#include <sstream>
#include <iomanip>

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

    // Spawn a thread per connection to avoid blocking the accept loop
    auto handshake = std::make_shared<Obfs4ServerHandshake>(node_id_, identity_key_);
    auto stats_completed = &handshakes_completed_;
    auto stats_failed = &handshakes_failed_;
    auto local_or_port = or_port_;
    auto& io = io_context_;

    std::thread([conn, handshake, stats_completed, stats_failed,
                 local_or_port, &io]() {
        auto buffer = std::array<uint8_t, 8192>{};

        // --- Phase 1: Handshake ---
        while (true) {
            auto bytes_read = conn->read(
                std::span<uint8_t>(buffer.data(), buffer.size()));

            if (!bytes_read || *bytes_read == 0) {
                LOG_WARN("obfs4 handshake: connection closed during read");
                stats_failed->fetch_add(1, std::memory_order_relaxed);
                return;
            }

            LOG_INFO("obfs4 handshake: received {} bytes", *bytes_read);

            // Debug: hex dump first 48 bytes to identify protocol
            {
                size_t dump_len = std::min<size_t>(*bytes_read, 48);
                std::ostringstream hex;
                for (size_t i = 0; i < dump_len; ++i)
                    hex << std::hex << std::setfill('0') << std::setw(2)
                        << static_cast<int>(buffer[i]);
                LOG_INFO("obfs4 handshake: first {} bytes hex: {}", dump_len, hex.str());

                // Detect TLS ClientHello (starts with 0x16 0x03)
                if (*bytes_read >= 3 && buffer[0] == 0x16 &&
                    buffer[1] == 0x03) {
                    LOG_WARN("obfs4 handshake: received TLS ClientHello, not obfs4 data");
                }
            }

            auto data = std::span<const uint8_t>(buffer.data(), *bytes_read);
            auto consume_result = handshake->consume(data);
            if (!consume_result) {
                LOG_WARN("obfs4 handshake failed: {}",
                         obfs4_error_message(consume_result.error()));
                stats_failed->fetch_add(1, std::memory_order_relaxed);
                return;
            }

            if (handshake->state() == Obfs4ServerHandshake::State::Completed) {
                break;
            }
            if (handshake->state() == Obfs4ServerHandshake::State::Failed) {
                stats_failed->fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }

        // --- Phase 2: Initialize framing and send server hello + seed frame ---
        const auto& keys = handshake->session_keys();

        auto framing = std::make_shared<Obfs4Framing>();
        framing->init_send(keys.send_key, keys.send_nonce, keys.send_drbg_seed);
        framing->init_recv(keys.recv_key, keys.recv_nonce, keys.recv_drbg_seed);

        // Generate the handshake response
        auto hello = handshake->generate_server_hello();
        if (!hello) {
            LOG_ERROR("obfs4: failed to generate server hello");
            stats_failed->fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Generate and append inline seed frame (PrngSeed packet)
        // The Go client (lyrebird) expects this immediately after the handshake.
        // Without it, the client waits forever → deadlock.
        auto seed_bytes = obfs4::common::random_bytes(24);
        auto seed_pkt = obfs4::transport::make_packet(
            obfs4::transport::PacketType::PrngSeed,
            std::span<const uint8_t>(seed_bytes.data(), seed_bytes.size()));
        auto seed_frame = framing->encode(
            std::span<const uint8_t>(seed_pkt.data(), seed_pkt.size()));

        // Append seed frame to server hello
        hello->insert(hello->end(), seed_frame.begin(), seed_frame.end());

        LOG_INFO("obfs4: sending server hello ({} bytes handshake + {} bytes seed frame)",
                 hello->size() - seed_frame.size(), seed_frame.size());

        auto hello_span = std::span<const uint8_t>(hello->data(), hello->size());
        auto write_result = conn->write(hello_span);
        if (!write_result) {
            LOG_ERROR("obfs4: failed to send server hello");
            stats_failed->fetch_add(1, std::memory_order_relaxed);
            return;
        }

        stats_completed->fetch_add(1, std::memory_order_relaxed);
        LOG_INFO("obfs4 handshake completed successfully");

        // --- Phase 3: Connect to local OR port ---
        auto or_conn = std::make_shared<net::TcpConnection>(io);
        auto connect_result = or_conn->connect("127.0.0.1", local_or_port);
        if (!connect_result) {
            LOG_ERROR("obfs4: failed to connect to local OR port {}", local_or_port);
            return;
        }

        LOG_INFO("obfs4: connected to local OR port {}, starting proxy", local_or_port);

        // --- Phase 4: Full-duplex bidirectional proxy ---
        // Two threads: one for each direction.
        // encode() and decode() access separate internal state (Encoder/Decoder),
        // so concurrent access from different threads is safe.
        std::atomic<bool> running{true};

        // Thread A: obfs4 client → OR port
        // Decode frames, parse packets, forward Payload data to OR
        std::thread client_to_or([&running, conn, or_conn, framing]() {
            auto buf = std::array<uint8_t, 4096>{};

            while (running.load(std::memory_order_relaxed)) {
                auto obfs4_read = conn->read(
                    std::span<uint8_t>(buf.data(), buf.size()));
                if (!obfs4_read || *obfs4_read == 0) {
                    LOG_WARN("obfs4 proxy: client connection closed");
                    break;
                }

                auto encrypted = std::span<const uint8_t>(buf.data(), *obfs4_read);
                auto frames = framing->decode(encrypted);
                if (!frames) {
                    LOG_WARN("obfs4 proxy: frame decryption failed (read {} bytes)",
                             *obfs4_read);
                    break;
                }

                // Process packet layer: extract payload from frames
                for (const auto& frame_payload : frames->frames) {
                    auto packets = obfs4::transport::parse_packets(
                        std::span<const uint8_t>(frame_payload.data(),
                                                 frame_payload.size()));

                    for (const auto& pkt : packets) {
                        if (pkt.type == obfs4::transport::PacketType::Payload
                            && !pkt.payload.empty()) {
                            auto wr = or_conn->write(
                                std::span<const uint8_t>(pkt.payload.data(),
                                                         pkt.payload.size()));
                            if (!wr) {
                                LOG_WARN("obfs4 proxy: OR write failed");
                                running.store(false, std::memory_order_relaxed);
                                return;
                            }
                        }
                        // PrngSeed packets: client updating DRBG (ignored for now)
                    }
                }
            }

            running.store(false, std::memory_order_relaxed);
            conn->close();
            or_conn->close();
        });

        // Thread B: OR port → obfs4 client
        // Read plaintext, wrap in Payload packet, encode frame, forward to client
        std::thread or_to_client([&running, conn, or_conn, framing]() {
            auto buf = std::array<uint8_t, 4096>{};

            while (running.load(std::memory_order_relaxed)) {
                auto or_read = or_conn->read(
                    std::span<uint8_t>(buf.data(), buf.size()));
                if (!or_read || *or_read == 0) {
                    LOG_WARN("obfs4 proxy: OR connection closed");
                    break;
                }

                auto plaintext = std::span<const uint8_t>(buf.data(), *or_read);

                // Split into chunks that fit in a single frame
                constexpr size_t max_chunk = obfs4::transport::MAX_FRAME_PAYLOAD
                                           - obfs4::transport::PACKET_OVERHEAD;
                size_t offset = 0;

                while (offset < plaintext.size()) {
                    size_t chunk_len = std::min(plaintext.size() - offset, max_chunk);
                    auto chunk = plaintext.subspan(offset, chunk_len);

                    // Wrap in Payload packet
                    auto pkt = obfs4::transport::make_packet(
                        obfs4::transport::PacketType::Payload, chunk);

                    // Encode as obfs4 frame
                    auto frame = framing->encode(
                        std::span<const uint8_t>(pkt.data(), pkt.size()));

                    auto wr = conn->write(
                        std::span<const uint8_t>(frame.data(), frame.size()));
                    if (!wr) {
                        LOG_WARN("obfs4 proxy: client write failed");
                        running.store(false, std::memory_order_relaxed);
                        return;
                    }

                    offset += chunk_len;
                }
            }

            running.store(false, std::memory_order_relaxed);
            conn->close();
            or_conn->close();
        });

        client_to_or.join();
        or_to_client.join();

        LOG_INFO("obfs4: proxy session ended");
    }).detach();
}

void Obfs4Listener::proxy_connection(
    [[maybe_unused]] std::shared_ptr<net::TcpConnection> obfs4_conn,
    [[maybe_unused]] std::shared_ptr<net::TcpConnection> or_conn,
    [[maybe_unused]] std::unique_ptr<Obfs4Framing> framing) {
    // Proxy logic is handled inside handle_connection thread
}

}  // namespace tor::transport
