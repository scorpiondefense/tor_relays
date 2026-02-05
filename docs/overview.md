# Overview

## What is a Tor Relay?

A Tor relay is a server that participates in the Tor network by forwarding encrypted traffic. This implementation provides a full-featured relay that can operate in three modes:

### Middle Relay (Default)

Middle relays are the workhorses of the Tor network. They:
- Forward encrypted relay cells between other relays
- Never see unencrypted traffic
- Are not listed as exit points
- Carry the lowest legal/abuse risk

### Exit Relay

Exit relays are the connection point between Tor and the regular internet:
- Connect to destination servers on behalf of Tor users
- See the destination (but not the source) of traffic
- Require careful exit policy configuration
- Carry higher abuse complaint risk

### Bridge Relay

Bridges are unlisted entry points for censored users:
- Not published in the main Tor directory
- Distributed through BridgeDB or other means
- Help users in censored regions access Tor
- Can use pluggable transports for obfuscation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Tor Relay                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Middle    │  │    Exit     │  │   Bridge    │   Modes      │
│  │   Relay     │  │    Relay    │  │   Relay     │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         └────────────────┼────────────────┘                      │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Relay Behavior Interface                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                       │
│         ┌────────────────┼────────────────┐                     │
│         ▼                ▼                ▼                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Circuit   │  │   Channel   │  │  Directory  │   Core       │
│  │   Manager   │  │   Manager   │  │   Client    │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                     │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Crypto Layer                            │  │
│  │  Ed25519 │ Curve25519 │ AES-CTR │ SHA │ ntor │ TLS 1.3    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Network Layer                            │  │
│  │              Boost.Asio │ OpenSSL                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### Cell Protocol

The fundamental unit of communication in Tor. Cells are 514-byte fixed-length packets containing:
- Circuit ID (4 bytes)
- Command (1 byte)
- Payload (509 bytes)

### Circuits

Virtual paths through the Tor network consisting of multiple hops. Each hop has its own encryption layer.

### Channels

TLS-encrypted connections between relays. Multiple circuits can share a single channel.

### ntor Handshake

The key exchange protocol used to establish circuit encryption keys using Curve25519 ECDH.

## Protocol Versions

This implementation supports:
- Link protocol versions 4 and 5
- Cell format version 4 (4-byte circuit IDs)
- CREATE2/CREATED2 with ntor handshake

## Performance Characteristics

- Asynchronous I/O using Boost.Asio
- Connection pooling via channel multiplexing
- Token bucket rate limiting
- Configurable bandwidth limits
