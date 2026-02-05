#pragma once

#include "tor/modes/relay_behavior.hpp"
#include "tor/core/channel.hpp"
#include <memory>
#include <string>

namespace tor::modes {

// Bridge relay mode - unpublished entry point
// This mode:
// - Is NOT published in public directory
// - Published only to bridge authority (if configured)
// - Acts like middle relay (no exit traffic)
// - May use pluggable transports (obfs4, etc.)
// - Helps users bypass censorship
class BridgeRelay : public RelayBehavior {
public:
    // Bridge distribution methods
    enum class Distribution {
        None,       // Not distributed (private bridge)
        Https,      // bridges.torproject.org
        Email,      // Get bridges via email
        Moat,       // MOAT (built into Tor Browser)
        Any,        // Any method
    };

    BridgeRelay();
    explicit BridgeRelay(const Config* config);
    ~BridgeRelay() override = default;

    // RelayBehavior interface
    [[nodiscard]] RelayMode mode() const override { return RelayMode::Bridge; }
    [[nodiscard]] std::string mode_name() const override { return "Bridge"; }

    [[nodiscard]] bool allows_operation(RelayOperation op) const override;

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_relay_cell(
        std::shared_ptr<core::Circuit> circuit,
        core::RelayCell& cell
    ) override;

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_begin(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& begin_cell
    ) override;

    [[nodiscard]] std::expected<void, core::CircuitError>
    handle_extend(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& extend_cell
    ) override;

    [[nodiscard]] std::string descriptor_additions() const override;

    [[nodiscard]] std::expected<void, std::string> validate_config() const override;

    // Bridge-specific configuration
    void set_distribution(Distribution dist) { distribution_ = dist; }
    [[nodiscard]] Distribution distribution() const { return distribution_; }

    // Fingerprint for sharing (includes @type annotation)
    [[nodiscard]] std::string bridge_line() const;

    // Set channel manager for circuit extension
    void set_channel_manager(std::shared_ptr<core::ChannelManager> manager) {
        channel_manager_ = std::move(manager);
    }

    // Pluggable transport support
    void set_transport(const std::string& transport) { transport_name_ = transport; }
    [[nodiscard]] const std::string& transport() const { return transport_name_; }

    // Bridge authority publishing
    void set_bridge_authority(const std::string& address) { bridge_authority_ = address; }
    [[nodiscard]] const std::string& bridge_authority() const { return bridge_authority_; }

    // Statistics
    [[nodiscard]] uint64_t clients_served() const { return clients_served_; }

private:
    const Config* config_{nullptr};
    Distribution distribution_{Distribution::None};
    std::string transport_name_;
    std::string bridge_authority_;
    std::shared_ptr<core::ChannelManager> channel_manager_;

    // Statistics
    std::atomic<uint64_t> clients_served_{0};

    // Forward relay cell to next hop (same as middle relay)
    [[nodiscard]] std::expected<void, core::CircuitError>
    forward_to_next_hop(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& cell
    );

    // Forward relay cell to previous hop
    [[nodiscard]] std::expected<void, core::CircuitError>
    forward_to_prev_hop(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& cell
    );
};

// Distribution method parsing
[[nodiscard]] std::expected<BridgeRelay::Distribution, std::string>
parse_distribution(const std::string& str);

[[nodiscard]] constexpr const char* distribution_name(BridgeRelay::Distribution dist) {
    switch (dist) {
        case BridgeRelay::Distribution::None: return "none";
        case BridgeRelay::Distribution::Https: return "https";
        case BridgeRelay::Distribution::Email: return "email";
        case BridgeRelay::Distribution::Moat: return "moat";
        case BridgeRelay::Distribution::Any: return "any";
        default: return "unknown";
    }
}

}  // namespace tor::modes
