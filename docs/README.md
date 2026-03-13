# Tor Relay Documentation

A production-ready Tor relay implementation in C++23 supporting runtime mode switching between Middle, Exit, Guard, and Bridge relay modes with integrated obfs4 pluggable transport.

## Table of Contents

- [Overview](overview.md) - Architecture, relay modes, and protocol support
- [Installation](installation.md) - Build from source with obfs4_cpp dependency
- [Configuration](configuration.md) - TOML config, CLI options, environment variables
- [Deployment](deployment.md) - Docker, Kubernetes, and VPS deployment guide (includes obfs4 bridge)
- [Architecture](architecture.md) - Technical deep-dive into components, data flow, and threading
- [API Reference](api-reference.md) - Code documentation and type reference
- [Testing](testing.md) - Test framework, categories, and coverage
- [Security](security.md) - Threat model, key management, and operational security
- [Troubleshooting](troubleshooting.md) - Common issues, diagnostics, and bridge-specific fixes

## Quick Start

```bash
# Clone monorepo (needs both tor_relays/ and obfs4_cpp/)
git clone <repository>
cd monorepo/tor_relays

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=/usr/bin/g++-14
cmake --build . --parallel

# Run as bridge with obfs4
./tor_relay --mode bridge --port 9002 -f -l info --data-dir /var/lib/tor

# Run with Docker (from monorepo root)
docker build -f infrastructure/docker/Dockerfile.tor-relays -t tor-relays .
docker run -p 9002:9002 -p 9443:9443 -v tor-data:/var/lib/tor tor-relays \
    -m bridge -p 9002 -n MyBridge -f --data-dir /var/lib/tor
```

## Relay Modes

| Mode | Description | Risk Level |
|------|-------------|------------|
| **Middle** | Forward relay cells only | Low |
| **Guard** | Stable entry relay | Low |
| **Exit** | Connect to external internet | High |
| **Bridge** | Unpublished entry with obfs4 for censored users | Medium |

## Requirements

- C++23 compatible compiler (GCC 14+ recommended, GCC 11+, Clang 14+)
- OpenSSL 3.x
- Boost 1.82+
- CMake 3.21+
- obfs4_cpp library (sibling directory in monorepo)

## License

MIT License - See [LICENSE](../LICENSE) for details.
