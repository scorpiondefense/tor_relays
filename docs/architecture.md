# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Tor Bridge Relay (v0.1.80)                       │
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
│  │                       Transport Layer                              │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │ │
│  │  │ Obfs4Listener│  │  Obfs4Server │  │ Obfs4Framing │   obfs4_cpp │ │
│  │  │    (:9443)   │  │  Handshake   │  │ encode/decode│   library   │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                  │                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         Mode Layer                                 │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │ │
│  │  │  Middle  │  │   Exit   │  │  Bridge  │  │  Guard   │          │ │
│  │  │  Relay   │  │  Relay   │  │  Relay   │  │  Relay   │          │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │ │
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
│  │  │ Ed25519 │ │Curve25519│ │RSA-1024 │ │ AES-CTR │ │  ntor   │     │ │
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
// Long-term identity (signs descriptors and Ed25519 certs)
class Ed25519SecretKey { /* 64 bytes: 32 seed + 32 public */ };
class Ed25519PublicKey { /* 32 bytes */ };

// ntor handshake key exchange + obfs4 identity
class Curve25519SecretKey { /* 32 bytes */ };
class Curve25519PublicKey { /* 32 bytes */ };

// Legacy identity required by Tor link protocol (CERTS cell types 1, 2, 7)
class Rsa1024Identity { /* EVP_PKEY wrapper, 1024-bit RSA */ };

// Relay fingerprint (SHA-1 of RSA public key DER)
class NodeId { /* 20 bytes */ };
```

All four key types are persisted in `/var/lib/tor/keys/` via `KeyStore`:

```cpp
struct RelayKeyPair {
    Ed25519SecretKey identity_key;      // ed25519_identity
    Curve25519SecretKey onion_key;      // curve25519_onion (determines obfs4 cert!)
    Rsa1024Identity rsa_identity;       // rsa1024_identity
    Ed25519SecretKey onion_ed_key;      // derived from onion_key seed, for cross-certs
    uint8_t onion_ed_sign_bit = 0;
};
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
    virtual Result<void> handle_begin(Circuit&, const RelayCell&) = 0;
    virtual Result<void> handle_extend(Circuit&, const RelayCell&) = 0;
    virtual bool allows_operation(RelayOperation op) const = 0;
    virtual std::string descriptor_additions() const = 0;
    virtual Result<void> validate_config() const = 0;
};

// Factory function
std::unique_ptr<RelayBehavior> create_behavior(RelayMode mode, const Config&);
```

Mode comparison:

| Operation | Middle | Exit | Bridge | Guard |
|-----------|--------|------|--------|-------|
| Forward relay cells | yes | yes | yes | yes |
| Extend circuits | yes | yes | yes | yes |
| Exit to internet | no | yes | no | no |
| Publish descriptor | yes | yes | no (bridge auth only) | yes |
| Directory cache | optional | optional | no | optional |
| Pluggable transport | no | no | yes (obfs4) | no |

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

### Bridge + obfs4 Incoming Flow

```
Client TCP (:9443)
      │
      ▼
┌─────────────┐
│ Obfs4       │ ─── Accept TCP, perform obfs4 handshake
│ Listener    │     (Elligator2 repr + HMAC mark + epoch MAC)
└─────────────┘
      │
      ▼
┌─────────────┐
│ Obfs4       │ ─── Deobfuscate length (SipHash DRBG XOR)
│ Framing     │     Decrypt frame (XSalsa20-Poly1305)
└─────────────┘
      │
      ▼
┌─────────────┐
│ Proxy to    │ ─── Forward decrypted bytes to localhost:9002 (OR port)
│ OR port     │
└─────────────┘
      │
      ▼
(standard relay cell processing below)
```

### Standard Incoming Cell Processing

```
TLS Connection (:9002)
      │
      ▼
┌─────────────┐
│   Channel   │ ─── Decrypt TLS
└─────────────┘
      │
      ▼
┌─────────────┐
│ Cell Parser │ ─── Parse 514-byte cell (or variable-length)
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
│  Behavior   │     (EXTEND2 → connect to next hop in reader thread)
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
│  - Signal handling (SIGINT, SIGTERM, SIGHUP)       │
│  - Configuration reload                             │
│  - Graceful shutdown coordination                   │
└────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼────────────────────┐
        ▼               ▼                    ▼
┌──────────────┐ ┌──────────────┐ ┌────────────────┐
│  Connection  │ │  Connection  │ │  Obfs4Listener │
│  Thread      │ │  Thread      │ │  Accept Thread │
│  (detached)  │ │  (detached)  │ │                │
│              │ │              │ │ - TCP accept    │
│ - TLS I/O    │ │ - TLS I/O    │ │ - obfs4 h/s    │
│ - Cell read  │ │ - Cell read  │ │ - Proxy to OR  │
│ - Relay cell │ │ - Relay cell │ └────────────────┘
│   dispatch   │ │   dispatch   │
└──────┬───────┘ └──────────────┘
       │
       ▼ (on EXTEND2)
┌──────────────┐
│  Reader      │
│  Thread      │
│  (detached)  │
│              │
│ - Connect to │
│   next hop   │
│ - TLS h/s    │
│ - Forward    │
│   EXTENDED2  │
└──────────────┘
```

Each accepted connection gets a detached thread. When an EXTEND2 cell arrives, the handler spawns a new detached reader thread to connect to the next hop, perform TLS + link handshake, and forward CREATE2/CREATED2. This avoids blocking the client-side reader.

**Known issue (fixed in v0.1.80):** The EXTEND2 handler previously suffered a SIGSEGV from use-after-free when the `ext_io`/`ext_tls` objects went out of scope before the reader thread finished. The fix ensures these objects have the correct lifetime (moved into the reader thread closure).

## Memory Management

- **Circuits**: Managed via `std::shared_ptr` in `CircuitTable`
- **Channels**: Reference counted, cleaned up when no circuits remain
- **Cells**: Stack allocated where possible, pooled for high throughput
- **Keys**: Secure memory allocation, zeroed on destruction

## obfs4 Transport Integration

The `obfs4_cpp` library is a sibling directory in the monorepo, linked via CMake `add_subdirectory`. The `tor::transport` namespace provides thin wrappers around the obfs4_cpp types:

- `Obfs4ServerHandshake` -- state machine wrapping `obfs4::transport::ServerHandshake`
- `Obfs4Framing` -- encode/decode wrapping `obfs4::transport::Encoder`/`Decoder`
- `Obfs4Drbg` -- SipHash-2-4 DRBG wrapping `obfs4::common::HashDrbg`
- `Obfs4Listener` -- TCP acceptor that performs handshake, then proxies to local OR port

The obfs4 identity is `Obfs4Identity{node_id, curve25519_onion_pubkey}`, serialized as `base64url_nopad(node_id[20] || pubkey[32])` for the `cert=` parameter in bridge lines.

## Error Handling

Uses C++23 `std::expected`:

```cpp
template<typename T>
using Result = std::expected<T, Error>;

Result<Cell> parse_cell(std::span<const uint8_t> data);

// Usage
auto result = parse_cell(buffer);
if (!result) {
    LOG_ERROR("Parse failed: {}", result.error().message());
    return result.error();
}
auto cell = std::move(*result);
```
