# Tor Relay Documentation

A production-ready Tor relay implementation in C++20 supporting runtime mode switching between Middle, Exit, and Bridge relay modes.

## Table of Contents

- [Overview](overview.md)
- [Installation](installation.md)
- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [Testing](testing.md)
- [Security](security.md)
- [Troubleshooting](troubleshooting.md)

## Quick Start

```bash
# Clone and build
git clone <repository>
cd tor_relay
mkdir build && cd build
conan install .. --build=missing
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
cmake --build .

# Run as middle relay (safest default)
./tor_relay --mode middle --port 9001

# Run with Docker
docker-compose up -d
```

## Relay Modes

| Mode | Description | Risk Level |
|------|-------------|------------|
| **Middle** | Forward relay cells only | Low |
| **Exit** | Connect to external internet | High |
| **Bridge** | Unpublished entry for censored users | Medium |

## Requirements

- C++20 compatible compiler (GCC 11+, Clang 14+, MSVC 2022+)
- OpenSSL 3.x
- Boost 1.82+
- CMake 3.21+
- Conan 2.x (optional, for dependencies)

## License

MIT License - See [LICENSE](../LICENSE) for details.
