#pragma once

#include "tor/modes/relay_behavior.hpp"
#include "tor/core/channel.hpp"
#include <memory>

namespace tor::modes {

// Middle relay mode - forwards relay cells only
// This is the default and safest relay mode:
// - No exit traffic (reject *:*)
// - Published in directory (increases network diversity)
// - Forwards EXTEND/EXTENDED cells
// - Does not create streams
class MiddleRelay : public RelayBehavior {
public:
    MiddleRelay();
    explicit MiddleRelay(const Config* config);
    ~MiddleRelay() override = default;

    // RelayBehavior interface
    [[nodiscard]] RelayMode mode() const override { return RelayMode::Middle; }
    [[nodiscard]] std::string mode_name() const override { return "Middle"; }

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

    // Set channel manager for circuit extension
    void set_channel_manager(std::shared_ptr<core::ChannelManager> manager) {
        channel_manager_ = std::move(manager);
    }

private:
    const Config* config_{nullptr};
    std::shared_ptr<core::ChannelManager> channel_manager_;

    // Forward relay cell to next hop
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

}  // namespace tor::modes
