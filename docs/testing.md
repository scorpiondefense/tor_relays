# Testing

## Test Framework

This project uses [Catch2 v3](https://github.com/catchorg/Catch2) for unit and integration testing.

## Running Tests

### All Tests

```bash
cd build
ctest --output-on-failure
```

### By Category

```bash
# Unit tests only
ctest -L unit

# Integration tests only
ctest -L integration

# Crypto tests
ctest -L crypto

# Exit policy tests
ctest -L exit-policy
```

### Specific Test

```bash
# Run tests matching pattern
ctest -R "Cell parsing"

# Run with verbose output
ctest -V -R "ntor"
```

### Using Catch2 Directly

```bash
# List all tests
./tor_tests --list-tests

# Run specific test
./tor_tests "Cell parsing - CREATE2 cell"

# Run tests with tag
./tor_tests [crypto]

# Verbose output
./tor_tests -s
```

## Test Organization

```
tests/
├── test_main.cpp           # Catch2 main (defines CATCH_CONFIG_MAIN)
├── unit/
│   ├── test_cell.cpp       # Cell protocol tests
│   ├── test_crypto.cpp     # Cryptographic primitives
│   ├── test_circuit.cpp    # Circuit state machine
│   ├── test_exit_policy.cpp # Exit policy matching
│   └── test_config.cpp     # Configuration parsing
├── integration/
│   ├── test_tls.cpp        # TLS handshake tests
│   ├── test_circuit_creation.cpp  # Full circuit flow
│   └── test_directory.cpp  # Descriptor building
├── mocks/
│   ├── mock_network.hpp    # Network mocking utilities
│   └── mock_crypto.hpp     # Crypto mocking utilities
└── fixtures/
    ├── cell_fixtures.hpp   # Pre-built test cells
    └── key_fixtures.hpp    # Test vectors for crypto
```

## Test Categories

### Unit Tests (`[unit]`)

Test individual components in isolation.

```cpp
TEST_CASE("Cell parsing - CREATE2 cell", "[cell][parsing][unit]") {
    SECTION("Valid CREATE2 with ntor handshake type") {
        auto cell = create_create2_cell(1234, HandshakeType::Ntor, ntor_data);

        auto result = Cell::parse(cell.serialize());
        REQUIRE(result.has_value());
        CHECK(result->command == CellCommand::CREATE2);
        CHECK(result->circuit_id == 1234);
    }

    SECTION("Reject unknown handshake type") {
        auto cell = create_create2_cell(1234, HandshakeType(99), data);

        auto result = Cell::parse(cell.serialize());
        CHECK_FALSE(result.has_value());
    }
}
```

### Integration Tests (`[integration]`)

Test component interactions.

```cpp
TEST_CASE("Circuit creation flow", "[circuit][integration]") {
    // Set up mock network
    MockNetwork network;
    auto client_socket = network.create_connected_pair();

    // Create channel
    Channel channel(client_socket);

    // Perform handshake
    auto circuit_result = channel.create_circuit(server_identity, server_onion);
    REQUIRE(circuit_result.has_value());

    // Verify circuit state
    CHECK(circuit_result->state() == CircuitState::Open);
}
```

### Crypto Tests (`[crypto]`)

Test cryptographic operations with known test vectors.

```cpp
TEST_CASE("Ed25519 signature - RFC 8032 vectors", "[crypto][ed25519][unit]") {
    // Test vector from RFC 8032
    auto secret = Ed25519SecretKey::from_bytes(rfc8032_secret);
    auto message = from_hex("...");
    auto expected_sig = from_hex("...");

    auto signature = secret.sign(message);
    CHECK(signature == expected_sig);
    CHECK(secret.public_key().verify(message, signature));
}
```

## Mocking

### Mock Network

```cpp
class MockSocket {
public:
    void inject_data(std::span<const uint8_t> data);
    std::vector<uint8_t> drain_sent_data();
    void connect_to(MockSocket& peer);  // Create connected pair
    void simulate_disconnect();
    void simulate_error(std::error_code ec);
};

// Usage
TEST_CASE("Channel handles disconnect", "[channel][unit]") {
    MockSocket socket;
    Channel channel(socket);

    socket.simulate_disconnect();

    auto result = channel.send_cell(cell);
    CHECK_FALSE(result.has_value());
    CHECK(result.error().code() == ErrorCode::ConnectionClosed);
}
```

### Mock Crypto

```cpp
class MockCryptoProvider {
public:
    void set_random_bytes(std::vector<uint8_t> bytes);
    void fail_dh_with(CryptoError error);
    void set_ed25519_verify_result(bool result);
};

// Usage
TEST_CASE("Handle DH failure", "[crypto][unit]") {
    MockCryptoProvider crypto;
    crypto.fail_dh_with(CryptoError::InvalidPublicKey);

    NtorClientHandshake handshake(crypto);
    auto result = handshake.complete(server_response);

    CHECK_FALSE(result.has_value());
    CHECK(result.error() == CryptoError::InvalidPublicKey);
}
```

## Test Fixtures

### Cell Fixtures

```cpp
namespace fixtures {

Cell create_padding_cell(CircuitId id = 0);
Cell create_versions_cell(std::vector<uint16_t> versions);
Cell create_netinfo_cell(uint32_t timestamp, IPAddress our_addr);
Cell create_create2_cell(CircuitId id, std::span<const uint8_t> handshake);
Cell create_relay_data_cell(CircuitId id, StreamId stream,
                            std::span<const uint8_t> data);

}  // namespace fixtures
```

### Key Fixtures

```cpp
namespace fixtures {

// RFC 8032 test vectors
extern const std::array<uint8_t, 32> ed25519_test_secret;
extern const std::array<uint8_t, 32> ed25519_test_public;
extern const std::array<uint8_t, 64> ed25519_test_signature;

// Curve25519 test vectors
extern const std::array<uint8_t, 32> curve25519_test_secret;
extern const std::array<uint8_t, 32> curve25519_test_public;
extern const std::array<uint8_t, 32> curve25519_test_shared;

// AES test vectors (NIST)
extern const std::array<uint8_t, 16> aes_test_key;
extern const std::array<uint8_t, 16> aes_test_iv;
extern const std::vector<uint8_t> aes_test_plaintext;
extern const std::vector<uint8_t> aes_test_ciphertext;

}  // namespace fixtures
```

## Coverage

### Generate Coverage Report

```bash
# Configure with coverage
cmake .. -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug

# Build and run tests
cmake --build .
ctest

# Generate report (requires lcov)
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage.info
genhtml coverage.info --output-directory coverage_report

# View report
open coverage_report/index.html
```

### Coverage Requirements

- Unit tests: > 80% line coverage
- Critical paths (crypto, cell parsing): > 95% coverage
- Integration tests: Cover all major flows

## Writing Tests

### Best Practices

1. **Descriptive names**: Use "Component - behavior" format
2. **Isolated tests**: Each test should be independent
3. **Test edge cases**: Invalid input, boundary conditions
4. **Use SECTION**: Group related assertions

```cpp
TEST_CASE("ExitPolicy - rule matching", "[exit-policy][unit]") {
    SECTION("Accept rule matches") {
        auto policy = ExitPolicy::parse("accept *:80");
        CHECK(policy->allows(any_ip, 80));
        CHECK_FALSE(policy->allows(any_ip, 443));
    }

    SECTION("CIDR matching") {
        auto policy = ExitPolicy::parse("accept 10.0.0.0/8:*");
        CHECK(policy->allows(0x0A000001, 80));      // 10.0.0.1
        CHECK_FALSE(policy->allows(0x0B000001, 80)); // 11.0.0.1
    }

    SECTION("Private addresses always rejected") {
        auto policy = ExitPolicy::accept_all();
        CHECK_FALSE(policy->allows(0x7F000001, 80)); // 127.0.0.1
        CHECK_FALSE(policy->allows(0xC0A80001, 80)); // 192.168.0.1
    }
}
```

### Test Helpers

```cpp
// Assertion helpers
#define CHECK_RESULT(expr) \
    do { \
        auto _result = (expr); \
        INFO("Error: " << (_result ? "" : _result.error().message())); \
        CHECK(_result.has_value()); \
    } while(0)

// Hex conversion
std::vector<uint8_t> from_hex(std::string_view hex);
std::string to_hex(std::span<const uint8_t> bytes);

// Random data generation
std::vector<uint8_t> random_bytes(size_t count);
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libssl-dev libboost-all-dev

      - name: Configure
        run: cmake -B build -DCMAKE_BUILD_TYPE=Debug

      - name: Build
        run: cmake --build build --parallel

      - name: Test
        run: ctest --test-dir build --output-on-failure
```
