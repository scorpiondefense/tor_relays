#pragma once

#include "tor/modes/relay_behavior.hpp"
#include "tor/core/channel.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace tor::modes {

// Guard relay mode - entry point for client circuits
// Guards are the first hop in a Tor circuit and are selected
// by clients based on the Guard flag from directory authorities.
//
// Behavior similar to Middle relay:
// - No exit traffic (reject *:*)
// - Published in directory
// - Forwards EXTEND/EXTENDED cells
// - Does not create streams
//
// Additional guard-specific features:
// - Tracks unique client connections (privacy-preserving)
// - Monitors uptime for Guard flag eligibility
// - Reports guard-specific statistics
class GuardRelay : public RelayBehavior {
public:
    // Eligibility requirements for earning Guard flag
    struct EligibilityRequirements {
        std::chrono::seconds min_uptime{8 * 24 * 3600};  // 8 days
        size_t min_bandwidth{2 * 1024 * 1024};           // 2 MB/s

        [[nodiscard]] static EligibilityRequirements default_requirements() {
            return EligibilityRequirements{};
        }
    };

    // Guard-specific statistics
    struct GuardStats {
        std::atomic<uint64_t> unique_clients{0};
        std::atomic<uint64_t> circuits_as_guard{0};
        std::atomic<uint64_t> cells_forwarded{0};
        std::chrono::steady_clock::time_point guard_duty_start;
        std::atomic<bool> guard_duty_active{false};

        [[nodiscard]] std::chrono::seconds guard_duty_time() const {
            if (!guard_duty_active) {
                return std::chrono::seconds{0};
            }
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - guard_duty_start
            );
        }
    };

    GuardRelay();
    explicit GuardRelay(const ::tor::util::Config* config);
    ~GuardRelay() override = default;

    // RelayBehavior interface
    [[nodiscard]] RelayMode mode() const override { return RelayMode::Guard; }
    [[nodiscard]] std::string mode_name() const override { return "Guard"; }

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

    // Guard-specific methods

    // Record a client connection (privacy-preserving via hashing)
    void record_client(const std::string& client_id);

    // Check if this relay meets Guard flag requirements
    [[nodiscard]] bool meets_guard_requirements() const;

    // Start tracking guard duty time
    void start_guard_duty();

    // Get current guard statistics
    [[nodiscard]] const GuardStats& stats() const { return stats_; }

    // Get eligibility requirements
    [[nodiscard]] const EligibilityRequirements& requirements() const { return requirements_; }

private:
    const ::tor::util::Config* config_{nullptr};
    std::shared_ptr<core::ChannelManager> channel_manager_;
    EligibilityRequirements requirements_;
    mutable GuardStats stats_;

    // Track unique clients (store hashes for privacy)
    mutable std::mutex clients_mutex_;
    std::unordered_set<size_t> client_hashes_;
    size_t max_tracked_clients_{10000};

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

    // Hash client ID for privacy-preserving tracking
    [[nodiscard]] size_t hash_client_id(const std::string& client_id) const;
};

}  // namespace tor::modes
