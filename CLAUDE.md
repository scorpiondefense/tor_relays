# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Production-ready Tor relay implementation in C++20 supporting Middle, Exit, and Bridge relay modes with runtime switching. Implements full Tor protocol including ntor handshake, circuit management, and relay cell processing.

## Build Commands

```bash
# Standard build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel

# Build with tests
cmake .. -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build .

# Run all tests
ctest --output-on-failure

# Run tests by category
ctest -L unit
ctest -L integration

# Run specific test suite
./tor_tests "[unit][crypto]"

# Optional: Conan dependency setup
conan install . --build=missing --output-folder=build
```

## Dependencies

- **CMake 3.21+**, **C++20 compiler** (GCC 11+, Clang 14+, MSVC 2022+)
- **OpenSSL 3.0+** - Cryptography
- **Boost 1.82+** - Asio for async I/O
- **spdlog 1.13.0** - Logging (via Conan)
- **toml11 3.8.1** - Config parsing (via Conan)
- **Catch2 3.5.2** - Testing (fetched at build)

## Architecture

**Layered design (bottom-up):**

1. **Network** (`tor::net`) - TLS connections, acceptors, DNS resolution over Boost.Asio
2. **Crypto** (`tor::crypto`) - Ed25519/Curve25519 keys, ntor handshake, AES-128-CTR, SHA-1
3. **Core** (`tor::core`) - Cells (514-byte protocol units), Circuits (encrypted paths with state machine), Channels (multiplexed TLS connections), Relay (orchestrator)
4. **Protocol** (`tor::protocol`) - Link protocol v4+, cell parsing/serialization
5. **Policy** (`tor::policy`) - Exit policies with CIDR, bandwidth limiting
6. **Directory** (`tor::directory`) - Descriptors, consensus, authority communication
7. **Modes** (`tor::modes`) - Strategy pattern: MiddleRelay, ExitRelay, BridgeRelay

**Threading Model:** Main thread for signals + async I/O thread pool via Boost.Asio. All I/O non-blocking.

## Key Types

- **Cell**: 514-byte fixed unit with CircuitId, CellCommand, 509-byte payload
- **Circuit**: State machine (Created→Extending→Open→Destroying→Closed) managing crypto state and streams
- **Channel**: TLS connection wrapper multiplexing circuits
- **Relay**: Master orchestrator with statistics and lifecycle management

## Code Conventions

- **Error handling**: `std::expected<T, Error>` for fallible operations, no exceptions in async/crypto paths
- **Memory**: `shared_ptr` for shared ownership (channels, circuits), `unique_ptr` for exclusive, secure zeroing for crypto keys
- **Naming**: Classes PascalCase, functions snake_case, constants UPPER_CASE

## Configuration

TOML config at `/etc/tor/relay.toml`. Key sections: `[relay]`, `[exit]`, `[bridge]`, `[directory]`, `[logging]`. CLI flags override config (see `--help`).

## Docker

```bash
docker-compose up -d
```

Multi-stage build, runs as non-root `tor` user. Ports: 9001 (OR), 9030 (directory), 9090 (metrics).
