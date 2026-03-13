# API Reference

## Core Types

### Cell Types

```cpp
namespace tor::core {

// Cell size constants
constexpr size_t CELL_LEN = 514;
constexpr size_t PAYLOAD_LEN = 509;
constexpr size_t MAX_CELL_PAYLOAD = 509;

// Type aliases
using CircuitId = uint32_t;
using StreamId = uint16_t;

// Cell command enumeration
enum class CellCommand : uint8_t {
    PADDING = 0,
    CREATE = 1,
    CREATED = 2,
    RELAY = 3,
    DESTROY = 4,
    CREATE_FAST = 5,
    CREATED_FAST = 6,
    VERSIONS = 7,
    NETINFO = 8,
    RELAY_EARLY = 9,
    CREATE2 = 10,
    CREATED2 = 11,
    PADDING_NEGOTIATE = 12,
    VPADDING = 128,
    CERTS = 129,
    AUTH_CHALLENGE = 130,
    AUTHENTICATE = 131
};

// Fixed-length cell (514 bytes)
struct Cell {
    CircuitId circuit_id;
    CellCommand command;
    std::array<uint8_t, PAYLOAD_LEN> payload;

    static Result<Cell> parse(std::span<const uint8_t> data);
    std::array<uint8_t, CELL_LEN> serialize() const;
    bool is_valid() const;
};

// Variable-length cell
struct VariableCell {
    CircuitId circuit_id;
    CellCommand command;
    std::vector<uint8_t> payload;

    static Result<VariableCell> parse(std::span<const uint8_t> data);
    std::vector<uint8_t> serialize() const;
};

}  // namespace tor::core
```

### Relay Commands

```cpp
namespace tor::core {

enum class RelayCommand : uint8_t {
    BEGIN = 1,
    DATA = 2,
    END = 3,
    CONNECTED = 4,
    SENDME = 5,
    EXTEND = 6,
    EXTENDED = 7,
    TRUNCATE = 8,
    TRUNCATED = 9,
    DROP = 10,
    RESOLVE = 11,
    RESOLVED = 12,
    BEGIN_DIR = 13,
    EXTEND2 = 14,
    EXTENDED2 = 15
};

struct RelayCell {
    RelayCommand command;
    uint16_t recognized;
    StreamId stream_id;
    uint32_t digest;
    uint16_t length;
    std::array<uint8_t, RELAY_PAYLOAD_LEN> data;

    static Result<RelayCell> parse(std::span<const uint8_t> payload);
    std::array<uint8_t, PAYLOAD_LEN> serialize() const;
};

}  // namespace tor::core
```

## Cryptography

### Key Types

```cpp
namespace tor::crypto {

// Ed25519 secret key (64 bytes: 32 seed + 32 public)
class Ed25519SecretKey {
public:
    static Result<Ed25519SecretKey> generate();
    static Result<Ed25519SecretKey> from_bytes(std::span<const uint8_t, 64> bytes);

    Ed25519PublicKey public_key() const;
    std::array<uint8_t, 64> sign(std::span<const uint8_t> message) const;
    std::span<const uint8_t, 64> as_bytes() const;
};

// Ed25519 public key (32 bytes)
class Ed25519PublicKey {
public:
    static Result<Ed25519PublicKey> from_bytes(std::span<const uint8_t, 32> bytes);

    bool verify(std::span<const uint8_t> message,
                std::span<const uint8_t, 64> signature) const;
    std::span<const uint8_t, 32> as_bytes() const;
    bool is_valid() const;
};

// Curve25519 secret key (32 bytes)
class Curve25519SecretKey {
public:
    static Result<Curve25519SecretKey> generate();
    static Result<Curve25519SecretKey> from_bytes(std::span<const uint8_t, 32> bytes);

    Curve25519PublicKey public_key() const;
    Result<std::array<uint8_t, 32>> diffie_hellman(const Curve25519PublicKey& peer) const;
    std::span<const uint8_t, 32> as_bytes() const;
};

// Curve25519 public key (32 bytes)
class Curve25519PublicKey {
public:
    static Result<Curve25519PublicKey> from_bytes(std::span<const uint8_t, 32> bytes);

    std::span<const uint8_t, 32> as_bytes() const;
    bool is_valid() const;
    bool is_low_order() const;
};

// RSA 1024-bit identity key (legacy, required for Tor link protocol CERTS cell)
class Rsa1024Identity {
public:
    static Result<Rsa1024Identity> generate();
    static Result<Rsa1024Identity> from_der_private(std::span<const uint8_t> der);

    std::vector<uint8_t> private_key_der() const;
    std::vector<uint8_t> public_key_der() const;
    std::vector<uint8_t> rsa_public_key_der() const;  // PKCS#1 RSAPublicKey for fingerprint

    Result<std::vector<uint8_t>> sign_sha256(std::span<const uint8_t> data) const;
    Result<std::vector<uint8_t>> sign_raw(std::span<const uint8_t> data) const;

    // Certificate generation for CERTS cell
    Result<std::vector<uint8_t>> create_identity_cert() const;     // Type 2
    Result<std::vector<uint8_t>> create_link_cert(EVP_PKEY* tls_pkey) const;  // Type 1
    Result<std::vector<uint8_t>> create_ed25519_cross_cert(const Ed25519PublicKey& ed_pub) const;  // Type 7

    bool is_valid() const;
};

// Relay key bundle (all four key types)
struct RelayKeyPair {
    Ed25519SecretKey identity_key;      // ed25519_identity
    Curve25519SecretKey onion_key;      // curve25519_onion (determines obfs4 cert!)
    Rsa1024Identity rsa_identity;       // rsa1024_identity
    Ed25519SecretKey onion_ed_key;      // derived from onion_key seed
    uint8_t onion_ed_sign_bit = 0;

    static Result<RelayKeyPair> generate();
};

// Node identifier (20-byte SHA-1 of RSA public key DER)
class NodeId {
public:
    NodeId();
    explicit NodeId(const Ed25519PublicKey& identity);
    explicit NodeId(std::span<const uint8_t> rsa_public_key_der);
    static Result<NodeId> from_bytes(std::span<const uint8_t, 20> bytes);
    static Result<NodeId> from_hex(const std::string& hex);
    static Result<NodeId> from_base64(const std::string& b64);

    std::span<const uint8_t, 20> as_bytes() const;
    std::string to_hex() const;
    std::string to_base64() const;
};

}  // namespace tor::crypto
```

### ntor Handshake

```cpp
namespace tor::crypto {

struct NtorKeyMaterial {
    std::array<uint8_t, 20> forward_digest_seed;
    std::array<uint8_t, 20> backward_digest_seed;
    std::array<uint8_t, 16> forward_key;
    std::array<uint8_t, 16> backward_key;
};

class NtorClientHandshake {
public:
    Result<std::vector<uint8_t>> create_request(
        const NodeId& server_identity,
        const Curve25519PublicKey& server_onion_key);

    Result<NtorKeyMaterial> complete_handshake(
        std::span<const uint8_t> server_response);
};

class NtorServerHandshake {
public:
    Result<std::pair<std::vector<uint8_t>, NtorKeyMaterial>> process_request(
        std::span<const uint8_t> client_request,
        const NodeId& our_identity,
        const Curve25519SecretKey& our_onion_key);
};

}  // namespace tor::crypto
```

### Hash Functions

```cpp
namespace tor::crypto {

class Sha1 {
public:
    void update(std::span<const uint8_t> data);
    std::array<uint8_t, 20> finalize();
    static std::array<uint8_t, 20> hash(std::span<const uint8_t> data);
};

class Sha256 {
public:
    void update(std::span<const uint8_t> data);
    std::array<uint8_t, 32> finalize();
    static std::array<uint8_t, 32> hash(std::span<const uint8_t> data);
};

class HmacSha256 {
public:
    explicit HmacSha256(std::span<const uint8_t> key);
    void update(std::span<const uint8_t> data);
    std::array<uint8_t, 32> finalize();
    static std::array<uint8_t, 32> mac(std::span<const uint8_t> key,
                                        std::span<const uint8_t> data);
};

// HKDF (RFC 5869)
std::vector<uint8_t> hkdf_sha256(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info,
    size_t output_length);

}  // namespace tor::crypto
```

### AES-CTR

```cpp
namespace tor::crypto {

class AesCtr128 {
public:
    AesCtr128(std::span<const uint8_t, 16> key,
              std::span<const uint8_t, 16> iv);

    void crypt(std::span<uint8_t> data);  // In-place encrypt/decrypt
    void crypt(std::span<const uint8_t> input, std::span<uint8_t> output);
    void reset(std::span<const uint8_t, 16> iv);
};

}  // namespace tor::crypto
```

## Key Persistence

```cpp
namespace tor::crypto {

class KeyStore {
public:
    explicit KeyStore(std::filesystem::path data_dir);

    // Load existing keys or generate and save new ones
    Result<RelayKeyPair> load_or_generate();

    // Write fingerprint file: "{data_dir}/fingerprint"
    Result<void> write_fingerprint(const std::string& nickname, const NodeId& node_id);
};

}  // namespace tor::crypto
```

## obfs4 Transport

```cpp
namespace tor::transport {

// obfs4 server identity: node_id + curve25519 onion key
struct Obfs4Identity {
    crypto::NodeId node_id;
    crypto::Curve25519PublicKey ntor_public_key;

    // Generate cert string: base64url_nopad(node_id[20] || pubkey[32])
    std::string to_cert() const;
    static Result<Obfs4Identity> from_cert(const std::string& cert);
};

// IAT modes
enum class IatMode : uint8_t {
    Off = 0,      // No IAT obfuscation
    Enabled = 1,  // Add random padding
    Paranoid = 2, // Padding + delay
};

// Server handshake state machine
class Obfs4ServerHandshake {
public:
    enum class State { WaitingForMark, WaitingForMac, Completed, Failed };

    Obfs4ServerHandshake(const crypto::NodeId& node_id,
                         const crypto::Curve25519SecretKey& identity_key);

    Result<size_t> consume(std::span<const uint8_t> data);
    Result<std::vector<uint8_t>> generate_server_hello();
    State state() const;

    struct SessionKeys {
        std::array<uint8_t, 32> send_key, recv_key;
        std::array<uint8_t, 24> send_nonce, recv_nonce;
        std::array<uint8_t, 24> send_drbg_seed, recv_drbg_seed;
    };
    const SessionKeys& session_keys() const;
};

// Frame encode/decode
class Obfs4Framing {
public:
    void init_send(std::span<const uint8_t, 32> key,
                   std::span<const uint8_t, 24> initial_nonce,
                   std::span<const uint8_t, 24> drbg_seed);
    void init_recv(/* same params */);

    std::vector<uint8_t> encode(std::span<const uint8_t> payload);

    struct DecodeResult {
        std::vector<std::vector<uint8_t>> frames;
        size_t consumed;
    };
    Result<DecodeResult> decode(std::span<const uint8_t> data);
};

// TCP listener that performs obfs4 handshake, then proxies to local OR port
class Obfs4Listener {
public:
    Obfs4Listener(boost::asio::io_context& io_context,
                  const crypto::NodeId& node_id,
                  const crypto::Curve25519SecretKey& identity_key,
                  IatMode iat_mode = IatMode::Off);

    Result<void> start(const std::string& address, uint16_t port);
    void stop();

    const std::string& cert() const;  // For bridge line generation
    void set_or_port(uint16_t port);  // Default: 9001

    // Statistics
    uint64_t connections_accepted() const;
    uint64_t handshakes_completed() const;
    uint64_t handshakes_failed() const;
    bool is_listening() const;
};

}  // namespace tor::transport
```

## Circuit Management

```cpp
namespace tor::core {

enum class CircuitState {
    Created,
    Extending,
    Open,
    Destroying,
    Closed
};

class Circuit {
public:
    Circuit(CircuitId id, std::shared_ptr<Channel> channel);

    CircuitId id() const;
    CircuitState state() const;
    void set_state(CircuitState state);

    Result<void> init_crypto(const crypto::NtorKeyMaterial& keys);
    Result<RelayCell> decrypt_relay(const Cell& cell);
    Result<Cell> encrypt_relay(const RelayCell& relay);

    Result<std::shared_ptr<Stream>> create_stream(StreamId id);
    std::shared_ptr<Stream> get_stream(StreamId id);
    void remove_stream(StreamId id);
    size_t stream_count() const;
};

class CircuitTable {
public:
    Result<std::shared_ptr<Circuit>> create_circuit(std::shared_ptr<Channel> channel);
    std::shared_ptr<Circuit> get(CircuitId id);
    void remove(CircuitId id);
    size_t count() const;
    size_t cleanup_stale(std::chrono::seconds max_age);
};

}  // namespace tor::core
```

## Exit Policy

```cpp
namespace tor::policy {

struct PortRange {
    uint16_t low;
    uint16_t high;

    static Result<PortRange> parse(std::string_view str);
    static PortRange single(uint16_t port);
    static PortRange range(uint16_t low, uint16_t high);
    static PortRange all();

    bool contains(uint16_t port) const;
    bool is_single() const;
    bool is_all() const;
};

struct IPv4Address {
    uint32_t address;
    uint8_t prefix_len;

    static Result<IPv4Address> parse(std::string_view str);
    static IPv4Address from_octets(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
    static IPv4Address any();

    bool matches(uint32_t ip) const;
    bool is_any() const;
};

struct ExitPolicyRule {
    enum class Action { Accept, Reject };

    Action action;
    AddressPattern address;
    PortRange ports;

    static Result<ExitPolicyRule> parse(std::string_view str);
    bool matches(uint32_t ip, uint16_t port) const;
    bool matches(std::string_view hostname, uint16_t port) const;
    std::string to_string() const;
};

class ExitPolicy {
public:
    ExitPolicy();

    static Result<ExitPolicy> parse(std::string_view policy_text);
    static ExitPolicy reject_all();
    static ExitPolicy accept_all();
    static ExitPolicy reduced();

    void add_rule(ExitPolicyRule rule);
    bool allows(uint32_t ip, uint16_t port) const;
    bool allows(std::string_view hostname, uint16_t port) const;
    bool is_empty() const;
    size_t rule_count() const;
    std::string to_string() const;
};

}  // namespace tor::policy
```

## Relay Modes

```cpp
namespace tor::modes {

enum class RelayMode { Middle, Exit, Bridge, Guard };
enum class RelayOperation {
    ForwardRelay,
    ExtendCircuit,
    ExitToInternet,
    PublishDescriptor,
    DirectoryCache
};

class RelayBehavior {
public:
    virtual ~RelayBehavior() = default;

    virtual RelayMode mode() const = 0;
    virtual std::string mode_name() const = 0;
    virtual Result<void> handle_relay_cell(std::shared_ptr<core::Circuit> circuit,
                                           core::RelayCell& cell) = 0;
    virtual Result<void> handle_begin(std::shared_ptr<core::Circuit> circuit,
                                      const core::RelayCell& begin) = 0;
    virtual Result<void> handle_extend(std::shared_ptr<core::Circuit> circuit,
                                       const core::RelayCell& extend) = 0;
    virtual bool allows_operation(RelayOperation op) const = 0;
    virtual std::string descriptor_additions() const = 0;
    virtual Result<void> validate_config() const = 0;
};

// Factory function
std::unique_ptr<RelayBehavior> create_behavior(RelayMode mode, const util::Config& config);

// Mode helpers
const char* relay_mode_name(RelayMode mode);
const char* relay_operation_name(RelayOperation op);

}  // namespace tor::modes
```

## Configuration

```cpp
namespace tor::util {

struct RelayConfig {
    std::string nickname;
    modes::RelayMode mode{modes::RelayMode::Middle};
    uint16_t or_port{9002};
    uint16_t dir_port{0};
    std::string address;
    std::string contact;
    std::filesystem::path data_dir{"/var/lib/tor"};

    struct Bandwidth {
        size_t rate{0};
        size_t burst{0};
        size_t advertised{0};
    } bandwidth;
};

struct BridgeConfig {
    std::string transport;         // "obfs4" or empty
    uint16_t transport_port{9443}; // obfs4 listener port
    uint8_t iat_mode{0};          // IAT obfuscation mode
    std::string distribution{"https"};
};

struct ExitConfig {
    std::string exit_policy;
    bool reduced_exit_policy{false};
    bool reject_private{true};
};

struct Config {
    RelayConfig relay;
    BridgeConfig bridge;
    ExitConfig exit;
    DirectoryConfig directory;
    LoggingConfig logging;

    static Result<Config> load_from_file(const std::string& path);
    static Config default_config();

    bool is_exit() const;
    bool is_bridge() const;
    policy::ExitPolicy effective_exit_policy() const;
};

}  // namespace tor::util
```

## Relay

```cpp
namespace tor::core {

class Relay {
public:
    Result<void> start();
    Result<void> stop();

    bool is_running() const;

    // Runtime mode switching
    Result<void> switch_mode(modes::RelayMode new_mode);
    modes::RelayMode mode() const;

    // Access internals
    std::shared_ptr<ChannelManager> channel_manager() const;
    modes::RelayBehavior* behavior() const;
    const crypto::RelayKeyPair* keys() const;
    const crypto::NodeId& fingerprint() const;
};

class RelayBuilder {
public:
    RelayBuilder& config(util::Config& cfg);
    Result<std::unique_ptr<Relay>> build();
};

}  // namespace tor::core
```

## Error Handling

```cpp
namespace tor::util {

enum class ErrorCode {
    Success = 0,
    InvalidCell,
    InvalidCrypto,
    ConnectionFailed,
    Timeout,
    PolicyRejected,
    CircuitNotFound,
    StreamNotFound,
    ConfigError,
    IoError
};

class Error {
public:
    Error(ErrorCode code, std::string message);

    ErrorCode code() const;
    const std::string& message() const;
    std::string to_string() const;
};

template<typename T>
using Result = std::expected<T, Error>;

}  // namespace tor::util
```
