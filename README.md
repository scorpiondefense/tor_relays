# Tor Relay

A production-ready Tor relay implementation in C++20 supporting runtime mode switching between **Middle**, **Exit**, and **Bridge** relay modes.

## Features

- **Multiple Relay Modes**: Middle (default), Exit, and Bridge
- **Modern C++20**: Uses `std::expected`, concepts, ranges
- **Async I/O**: Built on Boost.Asio for high performance
- **Strong Cryptography**: Ed25519, Curve25519, AES-128-CTR via OpenSSL 3.x
- **ntor Handshake**: Secure circuit key exchange
- **Exit Policies**: Flexible rule-based traffic filtering
- **Docker Support**: Easy deployment with Docker Compose
- **Comprehensive Tests**: Unit and integration tests with Catch2

## Quick Start

### Local Build

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install build-essential cmake libssl-dev libboost-all-dev

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel

# Run as middle relay
./tor_relay --mode middle --port 9001
```

### Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Remote VPS Deployment

```bash
# Deploy to your VPS
./deploy/deploy.sh user@XXX.XXX.XXX.XXX --mode middle

# Manage remotely
./deploy/remote-manage.sh user@XXX.XXX.XXX.XXX logs
./deploy/remote-manage.sh user@XXX.XXX.XXX.XXX restart
```

## Relay Modes

| Mode | Description | Risk Level | Use Case |
|------|-------------|------------|----------|
| **Middle** | Forward relay cells only | Low | Default, safest option |
| **Exit** | Connect to external internet | High | Requires careful policy |
| **Bridge** | Unlisted entry point | Medium | Help censored users |

## Configuration

Copy and edit the example configuration:

```bash
cp config/relay.toml.example config/relay.toml
```

Key settings:

```toml
[relay]
nickname = "MyRelay"
mode = "middle"        # middle, exit, or bridge
or_port = 9001

[relay.bandwidth]
rate = 10485760        # 10 MB/s

[exit]
exit_policy = """
accept *:80
accept *:443
reject *:*
"""
```

See [docs/configuration.md](docs/configuration.md) for full options.

## Documentation

- [Overview](docs/overview.md) - Architecture and concepts
- [Installation](docs/installation.md) - Build instructions
- [Configuration](docs/configuration.md) - All config options
- [Deployment](docs/deployment.md) - Docker and VPS deployment
- [Architecture](docs/architecture.md) - Technical deep-dive
- [Security](docs/security.md) - Security considerations
- [Testing](docs/testing.md) - Running tests
- [API Reference](docs/api-reference.md) - Code documentation
- [Troubleshooting](docs/troubleshooting.md) - Common issues

## Project Structure

```
tor_relay/
├── include/tor/          # Header files
│   ├── core/             # Cell, circuit, channel, relay
│   ├── crypto/           # Keys, ntor, AES, hashing
│   ├── modes/            # Middle, exit, bridge behaviors
│   ├── net/              # Network connections
│   ├── policy/           # Exit policy, bandwidth
│   ├── protocol/         # Link and relay protocols
│   ├── directory/        # Descriptors, consensus
│   └── util/             # Config, logging, errors
├── src/                  # Implementation files
├── tests/                # Unit and integration tests
├── config/               # Example configurations
├── deploy/               # Deployment scripts
├── docs/                 # Documentation
├── Dockerfile            # Docker build
└── docker-compose.yml    # Docker Compose config
```

## Requirements

- **Compiler**: GCC 11+, Clang 14+, or MSVC 2022+
- **CMake**: 3.21+
- **OpenSSL**: 3.0+
- **Boost**: 1.82+
- **Docker**: 20.10+ (optional)

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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Submit a pull request

## Security

For security issues, please email security@example.com rather than opening a public issue.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [The Tor Project](https://www.torproject.org/)
- [Tor Protocol Specification](https://spec.torproject.org/)
