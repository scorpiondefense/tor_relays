# Overview

## What is This?

A production C++23 Tor bridge relay with integrated obfs4 pluggable transport. Current version: **v0.1.80**.

While the codebase supports middle, exit, guard, and bridge modes, **bridge mode with obfs4** is the primary deployment target. The relay implements the Tor v3 link protocol, ntor handshake, and circuit extension, running as a Docker/Kubernetes workload on DigitalOcean.

## Operating Modes

### Bridge Relay (Primary)

The production deployment mode. Bridges are unlisted entry points for censored users:
- Not published in the main Tor directory
- Distributed through BridgeDB or other means
- Integrated obfs4 pluggable transport for traffic obfuscation
- Connection flow: obfs4 handshake on port 9443, proxied to OR port 9002 for TLS + v3 link protocol
- Bridge line format: `Bridge obfs4 <IP>:9443 <FINGERPRINT> cert=<CERT> iat-mode=0`

### Middle Relay

Middle relays forward encrypted relay cells between other relays. They never see unencrypted traffic, are not listed as exit points, and carry the lowest legal/abuse risk.

### Exit Relay

Exit relays connect to destination servers on behalf of Tor users. They see the destination (but not the source) of traffic and require careful exit policy configuration.

### Guard Relay

Entry guards serve as the first hop for client circuits. They require high uptime and stability.

## Connection Flow (Bridge + obfs4)

```
Client                            Bridge Relay
  │                                    │
  │  TCP connect to :9443              │
  │───────────────────────────────────►│  Obfs4Listener accepts
  │                                    │
  │  obfs4 handshake (Elligator2      │
  │  + ntor + SipHash DRBG framing)   │
  │◄──────────────────────────────────►│  Obfs4ServerHandshake
  │                                    │
  │  [obfs4 tunnel established]        │  Proxy to local :9002
  │                                    │
  │  TLS 1.2+ handshake               │
  │◄──────────────────────────────────►│
  │                                    │
  │  VERSIONS → ← VERSIONS            │  v3 link protocol
  │  ← CERTS (types 1-7)              │
  │  ← AUTH_CHALLENGE                  │
  │  NETINFO → ← NETINFO              │
  │                                    │
  │  CREATE_FAST / CREATE2 (ntor)      │  Circuit creation
  │◄──────────────────────────────────►│
  │                                    │
  │  RELAY_EARLY(EXTEND2)              │  Circuit extension
  │───────────────────────────────────►│──► connect to next hop
  │  ← RELAY(EXTENDED2)               │◄──
  │                                    │
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Tor Bridge Relay                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Transport Layer                         │   │
│  │  ┌─────────────────┐  ┌─────────────────┐                │   │
│  │  │  Obfs4Listener  │  │  Obfs4Framing   │  obfs4_cpp     │   │
│  │  │  (:9443)        │  │  (encode/decode) │  (sibling dir) │   │
│  │  └─────────────────┘  └─────────────────┘                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          │                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────┐ │
│  │   Bridge    │  │   Middle    │  │    Exit     │  │ Guard  │ │
│  │   Relay     │  │   Relay     │  │    Relay    │  │ Relay  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └───┬────┘ │
│         └────────────────┼────────────────┘──────────────┘      │
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
│  │  Ed25519 │ Curve25519 │ RSA-1024 │ AES-CTR │ ntor │ TLS  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Network Layer                            │  │
│  │              Boost.Asio │ OpenSSL 3.x                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### Cell Protocol

The fundamental unit of communication in Tor. Cells are 514-byte fixed-length packets containing:
- Circuit ID (4 bytes)
- Command (1 byte)
- Payload (509 bytes)

Variable-length cells (VERSIONS, CERTS, AUTH_CHALLENGE) use a 2-byte length field after the command.

### Circuits

Virtual paths through the Tor network consisting of multiple hops. Each hop has its own encryption layer. Created via CREATE_FAST (single hop) or CREATE2/EXTEND2 (ntor handshake, type 2).

### Channels

TLS-encrypted connections between relays. Multiple circuits can share a single channel.

### ntor Handshake

The key exchange protocol used to establish circuit encryption keys using Curve25519 ECDH. This is handshake type 2 in CREATE2/EXTEND2 cells. ntor-v3 (type 3) is not yet supported.

### Key Types

Four key types are persisted in `/var/lib/tor/keys/`:

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| `ed25519_identity` | Ed25519 | Long-term identity, signs descriptors and certs |
| `ed25519_onion` | Ed25519 | Derived from curve25519_onion seed, for cross-certs |
| `curve25519_onion` | Curve25519 | ntor handshake key exchange; also determines the obfs4 cert |
| `rsa1024_identity` | RSA-1024 | Legacy identity for Tor link protocol CERTS cell (types 1, 2, 7) |

The `curve25519_onion` key is critical: it determines the obfs4 certificate. Losing it breaks all existing client bridge lines.

## Protocol Versions

This implementation supports:
- Link protocol versions 4 and 5 (v3 link handshake)
- Cell format version 4 (4-byte circuit IDs)
- CREATE_FAST, CREATE2/CREATED2 with ntor handshake
- EXTEND2/EXTENDED2 for circuit extension
- Proto line: `Relay=1-3` (only ntor handshake type 2; ntor-v3 not supported)

## Deployment

- **Ports**: 9002 (OR), 9443 (obfs4)
- **Runtime**: Docker/Kubernetes on DigitalOcean
- **Key persistence**: Kubernetes PVC mounted at `/var/lib/tor/`
- **Build**: C++23, GCC 14+, OpenSSL 3.x, Boost 1.82+

## Threading Model

- Detached threads per accepted connection
- Separate reader threads spawned for EXTEND2 next-hop connections
- Main thread handles signal dispatch and shutdown coordination
