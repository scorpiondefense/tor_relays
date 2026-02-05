#pragma once

#include "tor/core/cell.hpp"
#include "tor/core/circuit.hpp"
#include <expected>
#include <memory>
#include <string>

namespace tor::modes {

// Relay operation modes
enum class RelayMode {
    Middle,  // Forward relay cells only (most common)
    Exit,    // Connect to external hosts
    Bridge,  // Forward only, unpublished in directory
};

// Operations that modes can allow/deny
enum class RelayOperation {
    ForwardRelay,      // Forward relay cells to next hop
    CreateStreams,     // Create new streams (BEGIN cells)
    ExitToInternet,    // Exit to internet addresses
    ResolveDns,        // DNS resolution
    BeginDir,          // Directory connections
    PublishDescriptor, // Publish to directory authorities
    AcceptRendezvous,  // Accept hidden service rendezvous
};

// Forward declarations
class ExitPolicy;

// Abstract base class for relay behavior
class RelayBehavior {
public:
    virtual ~RelayBehavior() = default;

    // Get the mode type
    [[nodiscard]] virtual RelayMode mode() const = 0;

    // Mode name for logging/display
    [[nodiscard]] virtual std::string mode_name() const = 0;

    // Check if this mode allows a specific operation
    [[nodiscard]] virtual bool allows_operation(RelayOperation op) const = 0;

    // Handle incoming relay cell (after decryption)
    [[nodiscard]] virtual std::expected<void, core::CircuitError>
    handle_relay_cell(
        std::shared_ptr<core::Circuit> circuit,
        core::RelayCell& cell
    ) = 0;

    // Handle BEGIN cell (stream creation request)
    [[nodiscard]] virtual std::expected<void, core::CircuitError>
    handle_begin(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& begin_cell
    ) = 0;

    // Handle EXTEND2 cell (circuit extension request)
    [[nodiscard]] virtual std::expected<void, core::CircuitError>
    handle_extend(
        std::shared_ptr<core::Circuit> circuit,
        const core::RelayCell& extend_cell
    ) = 0;

    // Generate mode-specific descriptor additions
    [[nodiscard]] virtual std::string descriptor_additions() const = 0;

    // Validate configuration for this mode
    [[nodiscard]] virtual std::expected<void, std::string> validate_config() const = 0;

protected:
    RelayBehavior() = default;
};

// Factory function to create appropriate behavior
[[nodiscard]] std::unique_ptr<RelayBehavior> create_behavior(
    RelayMode mode,
    const class Config* config = nullptr
);

// Parse mode from string
[[nodiscard]] std::expected<RelayMode, std::string> parse_relay_mode(const std::string& str);

// Mode to string
[[nodiscard]] constexpr const char* relay_mode_name(RelayMode mode) {
    switch (mode) {
        case RelayMode::Middle: return "Middle";
        case RelayMode::Exit: return "Exit";
        case RelayMode::Bridge: return "Bridge";
        default: return "Unknown";
    }
}

// Operation to string
[[nodiscard]] constexpr const char* relay_operation_name(RelayOperation op) {
    switch (op) {
        case RelayOperation::ForwardRelay: return "ForwardRelay";
        case RelayOperation::CreateStreams: return "CreateStreams";
        case RelayOperation::ExitToInternet: return "ExitToInternet";
        case RelayOperation::ResolveDns: return "ResolveDns";
        case RelayOperation::BeginDir: return "BeginDir";
        case RelayOperation::PublishDescriptor: return "PublishDescriptor";
        case RelayOperation::AcceptRendezvous: return "AcceptRendezvous";
        default: return "Unknown";
    }
}

}  // namespace tor::modes

// Forward declaration for Config (avoid circular include)
namespace tor::util {
class Config;
}

namespace tor::modes {
using Config = tor::util::Config;
}
