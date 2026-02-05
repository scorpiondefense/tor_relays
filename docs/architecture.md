# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Tor Relay                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                        Application Layer                           │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │ │
│  │  │    Relay     │  │   Config     │  │   Logging    │             │ │
│  │  │   Manager    │  │   Manager    │  │   System     │             │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                  │                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         Mode Layer                                 │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │ │
│  │  │    Middle    │  │     Exit     │  │    Bridge    │             │ │
│  │  │    Relay     │  │    Relay     │  │    Relay     │             │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │ │
│  │                          │                                         │ │
│  │              ┌───────────┴───────────┐                            │ │
│  │              │   RelayBehavior       │  ◄── Strategy Pattern      │ │
│  │              │   Interface           │                            │ │
│  │              └───────────────────────┘                            │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                  │                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                        Protocol Layer                              │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │ │
│  │  │    Link      │  │    Cell      │  │    Relay     │             │ │
│  │  │   Protocol   │  │   Parser     │  │   Protocol   │             │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                  │                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         Core Layer                                 │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │ │
│  │  │   Circuit    │  │   Channel    │  │    Cell      │             │ │
│  │  │   Manager    │  │   Manager    │  │   Handler    │             │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                  │                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                        Crypto Layer                                │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │ │
│  │  │ Ed25519 │ │Curve25519│ │ AES-CTR │ │  SHA-1  │ │  ntor   │     │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │ │
│  │                          │                                         │ │
│  │              ┌───────────┴───────────┐                            │ │
│  │              │      OpenSSL 3.x      │                            │ │
│  │              └───────────────────────┘                            │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                  │                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                        Network Layer                               │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │ │
│  │  │  Connection  │  │   Acceptor   │  │   Resolver   │             │ │
│  │  │   Manager    │  │              │  │              │             │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │ │
│  │                          │                                         │ │
│  │              ┌───────────┴───────────┐                            │ │
│  │              │      Boost.Asio       │                            │ │
│  │              └───────────────────────┘                            │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### Core Components

#### Cell (`core/cell.hpp`)

The fundamental communication unit in Tor:

```cpp
struct Cell {
    CircuitId circuit_id;     // 4 bytes - identifies the circuit
    CellCommand command;      // 1 byte - cell type
    std::array<uint8_t, PAYLOAD_LEN> payload;  // 509 bytes
};

// Total: 514 bytes (fixed length)
```

Cell commands include:
- `PADDING` (0) - Keep-alive
- `CREATE2` (10) - Create circuit with ntor
- `CREATED2` (11) - Circuit created response
- `RELAY` (3) - Encrypted relay payload
- `DESTROY` (4) - Tear down circuit

#### Circuit (`core/circuit.hpp`)

Manages encryption state for a virtual path:

```cpp
class Circuit {
    CircuitId id_;
    CircuitState state_;  // Created, Extending, Open, Destroying, Closed
    std::vector<HopCryptoState> hops_;
    std::unordered_map<StreamId, std::shared_ptr<Stream>> streams_;
};
```

State machine:
```
Created ──► Extending ──► Open ──► Destroying ──► Closed
    │           │          │
    └───────────┴──────────┴──► Destroying (on error)
```

#### Channel (`core/channel.hpp`)

TLS-encrypted connection between relays:

```cpp
class Channel {
    std::shared_ptr<TlsConnection> connection_;
    PeerInfo peer_;
    std::vector<LinkVersion> negotiated_versions_;
};
```

Multiple circuits multiplex over a single channel.

### Crypto Components

#### Key Types (`crypto/keys.hpp`)

```cpp
// Long-term identity (signs descriptors)
class Ed25519SecretKey { /* 64 bytes */ };
class Ed25519PublicKey { /* 32 bytes */ };

// Ephemeral key exchange (ntor handshake)
class Curve25519SecretKey { /* 32 bytes */ };
class Curve25519PublicKey { /* 32 bytes */ };

// Relay fingerprint (SHA-1 of identity key)
class NodeId { /* 20 bytes */ };
```

#### ntor Handshake (`crypto/ntor.hpp`)

Key exchange protocol:

```
Client                                    Server
   │                                         │
   │  node_id(20) + key_id(32) + X(32)      │
   │────────────────────────────────────────►│
   │                                         │
   │              Y(32) + AUTH(32)           │
   │◄────────────────────────────────────────│
   │                                         │

Both derive: KEY_SEED → HKDF → Df, Db, Kf, Kb
```

### Mode System (Strategy Pattern)

```cpp
class RelayBehavior {
public:
    virtual RelayMode mode() const = 0;
    virtual Result<void> handle_relay_cell(Circuit&, RelayCell&) = 0;
    virtual Result<void> handle_begin(Circuit&, const RelayBeginCell&) = 0;
    virtual bool allows_operation(RelayOperation op) const = 0;
};

// Factory function
std::unique_ptr<RelayBehavior> create_behavior(RelayMode mode, const Config&);
```

Mode comparison:

| Operation | Middle | Exit | Bridge |
|-----------|--------|------|--------|
| Forward relay cells | ✓ | ✓ | ✓ |
| Extend circuits | ✓ | ✓ | ✓ |
| Exit to internet | ✗ | ✓ | ✗ |
| Publish descriptor | ✓ | ✓ | ✗ |
| Directory cache | Optional | Optional | ✗ |

### Exit Policy System

```cpp
class ExitPolicy {
    std::vector<ExitPolicyRule> rules_;

    bool allows(const IPAddress& addr, uint16_t port) const {
        for (const auto& rule : rules_) {
            if (rule.matches(addr, port)) {
                return rule.action == Action::Accept;
            }
        }
        return false;  // Default deny
    }
};
```

Built-in policies:
- `reject_all()` - For middle/bridge relays
- `accept_all()` - Open exit (not recommended)
- `reduced()` - Common safe ports only

## Data Flow

### Incoming Cell Processing

```
TLS Connection
      │
      ▼
┌─────────────┐
│   Channel   │ ─── Decrypt TLS
└─────────────┘
      │
      ▼
┌─────────────┐
│ Cell Parser │ ─── Parse 514-byte cell
└─────────────┘
      │
      ▼
┌─────────────┐
│  Circuit    │ ─── Lookup by circuit_id
│   Table     │
└─────────────┘
      │
      ▼
┌─────────────┐
│   Circuit   │ ─── Decrypt relay layer (if RELAY cell)
└─────────────┘
      │
      ▼
┌─────────────┐
│   Relay     │ ─── Process based on relay command
│  Behavior   │
└─────────────┘
```

### Outgoing Cell Processing

```
Application Data
      │
      ▼
┌─────────────┐
│   Stream    │ ─── Package into relay cells
└─────────────┘
      │
      ▼
┌─────────────┐
│   Circuit   │ ─── Encrypt relay layers (onion)
└─────────────┘
      │
      ▼
┌─────────────┐
│   Channel   │ ─── Queue for sending
└─────────────┘
      │
      ▼
┌─────────────┐
│    TLS      │ ─── Encrypt and send
│ Connection  │
└─────────────┘
```

## Threading Model

```
┌────────────────────────────────────────────────────┐
│                   Main Thread                       │
│  - Signal handling                                  │
│  - Configuration reload                             │
│  - Graceful shutdown coordination                   │
└────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  I/O Thread  │ │  I/O Thread  │ │  I/O Thread  │
│  (Asio)      │ │  (Asio)      │ │  (Asio)      │
│              │ │              │ │              │
│ - Accept     │ │ - Read/Write │ │ - Timers     │
│ - Connect    │ │ - TLS ops    │ │ - Cleanup    │
└──────────────┘ └──────────────┘ └──────────────┘
```

All I/O is asynchronous using Boost.Asio. The thread pool size is configurable but defaults to `std::thread::hardware_concurrency()`.

## Memory Management

- **Circuits**: Managed via `std::shared_ptr` in `CircuitTable`
- **Channels**: Reference counted, cleaned up when no circuits remain
- **Cells**: Stack allocated where possible, pooled for high throughput
- **Keys**: Secure memory allocation, zeroed on destruction

## Error Handling

Uses C++23-style `std::expected` (or equivalent):

```cpp
using Result<T> = std::expected<T, Error>;

Result<Cell> parse_cell(std::span<const uint8_t> data);

// Usage
auto result = parse_cell(buffer);
if (!result) {
    LOG_ERROR("Parse failed: {}", result.error().message());
    return result.error();
}
auto cell = std::move(*result);
```
