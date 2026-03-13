# Tor Relay

A production-ready Tor relay implementation in C++23 supporting runtime mode switching between **Middle**, **Exit**, **Guard**, and **Bridge** relay modes with integrated **obfs4** pluggable transport.

## Features

- **Multiple Relay Modes**: Middle (default), Exit, Guard, and Bridge
- **obfs4 Pluggable Transport**: Built-in obfs4 support via [obfs4_cpp](../obfs4_cpp) for censorship-resistant bridge connections
- **Modern C++23**: Uses `std::expected`, `std::format`, concepts, `std::span`
- **Async I/O**: Built on Boost.Asio for high performance
- **Strong Cryptography**: Ed25519, Curve25519, RSA-1024, AES-128-CTR via OpenSSL 3.x
- **ntor Handshake**: Secure circuit key exchange (CREATE2/CREATED2)
- **v3 Link Protocol**: Full link handshake with Ed25519 certificate chain (CERTS, AUTH_CHALLENGE, NETINFO)
- **Circuit Extension**: EXTEND2/EXTENDED2 relay cell forwarding to upstream Tor relays
- **Exit Policies**: Flexible rule-based traffic filtering with CIDR support
- **Persistent Key Store**: Ed25519 identity, Curve25519 onion, RSA-1024, and onion Ed25519 keys persisted across restarts
- **Docker + Kubernetes**: Production deployment with PersistentVolumeClaim for key persistence
- **Comprehensive Tests**: Unit and integration tests with Catch2

## Quick Start

### Local Build

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install build-essential cmake libssl-dev libboost-all-dev g++-14

# Build (requires obfs4_cpp sibling directory)
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_CXX_COMPILER=/usr/bin/g++-14 \
         -DCMAKE_C_COMPILER=/usr/bin/gcc-14
cmake --build . --parallel

# Run as middle relay
./tor_relay --mode middle --port 9001

# Run as bridge with obfs4
./tor_relay --mode bridge --port 9002 -f -l info --data-dir /var/lib/tor
```

### Docker

```bash
# Build from monorepo root (needs both tor_relays/ and obfs4_cpp/)
docker build -f infrastructure/docker/Dockerfile.tor-relays -t tor-relays .

# Run as bridge
docker run -d \
    --name tor-bridge \
    -p 9002:9002 \
    -p 9443:9443 \
    -v tor-data:/var/lib/tor \
    tor-relays -m bridge -p 9002 -n MyBridge -f -l info --data-dir /var/lib/tor
```

### Kubernetes (Production)

See [docs/deployment.md](docs/deployment.md) for full Kubernetes deployment with obfs4 bridge.

```bash
# Apply manifests
kubectl apply -f infrastructure/k8s/tor/

# Check bridge status
kubectl -n scorpion-intelligence logs -l app.kubernetes.io/name=scorpion-tor-bridge

# Get obfs4 bridge line from logs
kubectl -n scorpion-intelligence logs -l app.kubernetes.io/name=scorpion-tor-bridge | grep "Bridge line:"
```

## Relay Modes

| Mode | Description | Risk Level | Use Case |
|------|-------------|------------|----------|
| **Middle** | Forward relay cells only | Low | Default, safest option |
| **Guard** | Entry relay for Tor clients | Low | Stable, high-uptime nodes |
| **Exit** | Connect to external internet | High | Requires careful policy |
| **Bridge** | Unlisted entry point with obfs4 | Medium | Help censored users |

## Bridge Mode with obfs4

The bridge mode includes a built-in obfs4 pluggable transport server. When a Tor client connects:

1. **obfs4 handshake** - Client connects to the obfs4 port (e.g., 9443), performs the obfs4 key exchange
2. **TLS tunnel** - obfs4 proxies to the local OR port, TLS handshake occurs
3. **Link protocol** - v3/v4/v5 link handshake with Ed25519 certificate chain
4. **Circuit creation** - Client sends CREATE_FAST or CREATE2 (ntor) to establish a circuit
5. **Directory fetch** - Client downloads consensus and microdescriptors through the bridge
6. **Circuit extension** - Client sends EXTEND2 relay cells; bridge forwards CREATE2 to upstream Tor relays
7. **Full connectivity** - Client builds 3-hop circuits through the bridge to the wider Tor network

The bridge line for Tor Browser looks like:
```
Bridge obfs4 <IP>:<obfs4_port> <fingerprint> cert=<obfs4_cert> iat-mode=0
```

The bridge logs the full bridge line at startup for easy copy-paste.

## Configuration

Copy and edit the example configuration:

```bash
cp config/relay.toml.example config/relay.toml
```

Key settings:

```toml
[relay]
nickname = "MyRelay"
mode = "bridge"        # middle, exit, guard, or bridge
or_port = 9002

[bridge]
distribution = "https"

[bridge.transport]
enabled = true
type = "obfs4"
port = 9443
iat_mode = 0

[relay.bandwidth]
rate = 10485760        # 10 MB/s

[data]
directory = "/var/lib/tor"
```

See [docs/configuration.md](docs/configuration.md) for full options.

## Documentation

- [Overview](docs/overview.md) - Architecture and concepts
- [Installation](docs/installation.md) - Build instructions
- [Configuration](docs/configuration.md) - All config options
- [Deployment](docs/deployment.md) - Docker, Kubernetes, and VPS deployment
- [Architecture](docs/architecture.md) - Technical deep-dive
- [Security](docs/security.md) - Security considerations
- [Testing](docs/testing.md) - Running tests
- [API Reference](docs/api-reference.md) - Code documentation
- [Troubleshooting](docs/troubleshooting.md) - Common issues and fixes

## Project Structure

```
tor_relays/
├── include/tor/          # Header files
│   ├── core/             # Cell, circuit, channel, relay
│   ├── crypto/           # Keys, ntor, AES, hashing, TLS, key_store
│   ├── modes/            # Middle, exit, guard, bridge behaviors
│   ├── net/              # Network connections
│   ├── policy/           # Exit policy, bandwidth
│   ├── protocol/         # Link and relay protocols, cell parser
│   ├── directory/        # Descriptors, consensus
│   ├── transport/        # obfs4 listener and proxy
│   └── util/             # Config, logging, errors
├── src/                  # Implementation files
├── tests/                # Unit and integration tests
├── config/               # Example configurations
├── cmake/                # CMake modules
└── docs/                 # Documentation
```

## Dependencies

- **Compiler**: GCC 14+ (recommended), Clang 17+ (C++23 required)
- **CMake**: 3.21+
- **OpenSSL**: 3.0+
- **Boost**: 1.82+ (system, asio)
- **obfs4_cpp**: Sibling directory in monorepo (pluggable transport library)
- **Docker**: 20.10+ (optional, for containerized deployment)

## Testing

```bash
# Build with tests
cmake .. -DBUILD_TESTING=ON
cmake --build .

# Run all tests
ctest --output-on-failure

# Run specific category
ctest -L unit
ctest -L integration
ctest -L crypto
```

## Current Status

- **v0.1.79** (2026-03-13): Bridge bootstrap 100% working with obfs4 through to full Tor network connectivity
- Link protocol v4/v5 with Ed25519 certificate chain
- ntor handshake (CREATE2 htype=2) for circuit creation
- EXTEND2 circuit extension forwarding any handshake type to upstream relays
- Persistent key store with migration support for all key types
- Deployed and verified on Kubernetes with DigitalOcean

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [The Tor Project](https://www.torproject.org/)
- [Tor Protocol Specification](https://spec.torproject.org/)
