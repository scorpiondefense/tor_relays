# Security

## Security Model

### Threat Model

This Tor relay implementation protects against:

1. **Passive network observers** - All traffic is TLS encrypted
2. **Active network attackers** - TLS with certificate pinning
3. **Compromised relays** - Onion encryption (multiple layers)
4. **Key theft** - Secure memory for cryptographic keys

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                            │
│  - Internet traffic                                          │
│  - Other Tor relays (potentially malicious)                  │
│  - DNS responses                                             │
└─────────────────────────────────────────────────────────────┘
                            │
                    TLS + Onion Encryption
                            │
┌─────────────────────────────────────────────────────────────┐
│                    RELAY BOUNDARY                            │
│  - Cell processing                                           │
│  - Circuit management                                        │
│  - Exit policy enforcement                                   │
└─────────────────────────────────────────────────────────────┘
                            │
                    Memory Protection
                            │
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                              │
│  - Identity keys                                             │
│  - Configuration                                             │
│  - Local state                                               │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Security

### Key Management

| Key Type | Algorithm | Size | Lifetime | Storage |
|----------|-----------|------|----------|---------|
| Identity | Ed25519 | 256-bit | Permanent | Secure file |
| Onion | Curve25519 | 256-bit | ~28 days | Secure file |
| Circuit | AES-128 | 128-bit | Circuit lifetime | Memory only |

### Key Generation

```cpp
// Keys generated using OpenSSL's secure RNG
auto identity = Ed25519SecretKey::generate();
auto onion = Curve25519SecretKey::generate();

// Keys are validated before use
if (!identity->public_key().is_valid()) {
    return Error("Invalid key generated");
}
```

### Secure Memory

```cpp
// Keys use secure memory that is:
// - Locked in RAM (mlock)
// - Zeroed on destruction
// - Protected from core dumps

class SecureBytes {
    ~SecureBytes() {
        OPENSSL_cleanse(data_.data(), data_.size());
    }
};
```

### TLS Configuration

```cpp
// TLS 1.2 minimum (TLS 1.3 preferred)
ctx.set_min_version(TlsVersion::TLS_1_2);

// Strong cipher suites only
ctx.set_cipher_list(
    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
);

// Certificate verification for directory authorities
ctx.set_verify_mode(SSL_VERIFY_PEER);
```

## Input Validation

### Cell Validation

```cpp
Result<Cell> parse_cell(std::span<const uint8_t> data) {
    // Length check
    if (data.size() < CELL_LEN) {
        return Error(ErrorCode::InvalidCell, "Cell too short");
    }

    // Command validation
    if (!is_valid_command(data[4])) {
        return Error(ErrorCode::InvalidCell, "Unknown command");
    }

    // Circuit ID validation
    auto circuit_id = parse_circuit_id(data);
    if (circuit_id == 0 && requires_circuit(data[4])) {
        return Error(ErrorCode::InvalidCell, "Missing circuit ID");
    }

    return Cell{...};
}
```

### Exit Policy Validation

```cpp
bool ExitPolicy::allows(uint32_t ip, uint16_t port) const {
    // Always reject private addresses
    if (is_private_address(ip)) {
        return false;
    }

    // Always reject localhost
    if (is_loopback(ip)) {
        return false;
    }

    // Check policy rules
    for (const auto& rule : rules_) {
        if (rule.matches(ip, port)) {
            return rule.action == Action::Accept;
        }
    }

    return false;  // Default deny
}
```

### Address Validation

```cpp
bool is_private_address(uint32_t ip) {
    // RFC 1918 private ranges
    if ((ip & 0xFF000000) == 0x0A000000) return true;  // 10.0.0.0/8
    if ((ip & 0xFFF00000) == 0xAC100000) return true;  // 172.16.0.0/12
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;  // 192.168.0.0/16

    // Loopback
    if ((ip & 0xFF000000) == 0x7F000000) return true;  // 127.0.0.0/8

    // Link-local
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return true;  // 169.254.0.0/16

    return false;
}
```

## Rate Limiting

### Connection Rate Limiting

```cpp
class ConnectionLimiter {
    std::unordered_map<IPAddress, ConnectionInfo> connections_;

    bool allow_connection(const IPAddress& addr) {
        auto& info = connections_[addr];
        auto now = std::chrono::steady_clock::now();

        // Max 10 connections per second per IP
        if (info.recent_count > 10 &&
            now - info.window_start < std::chrono::seconds(1)) {
            return false;
        }

        return true;
    }
};
```

### Bandwidth Limiting

```cpp
class TokenBucket {
    size_t tokens_;
    size_t capacity_;
    size_t refill_rate_;  // tokens per second

    bool consume(size_t amount) {
        refill();
        if (tokens_ >= amount) {
            tokens_ -= amount;
            return true;
        }
        return false;
    }
};
```

## Denial of Service Protection

### Circuit Limits

```cpp
// Per-channel circuit limit
constexpr size_t MAX_CIRCUITS_PER_CHANNEL = 1000;

// Global circuit limit
constexpr size_t MAX_TOTAL_CIRCUITS = 65535;

// Circuit creation rate limit
constexpr size_t MAX_CIRCUIT_CREATES_PER_SECOND = 100;
```

### Memory Limits

```cpp
// Maximum pending data per circuit
constexpr size_t MAX_CIRCUIT_QUEUE_SIZE = 1024 * 1024;  // 1 MB

// Maximum streams per circuit
constexpr size_t MAX_STREAMS_PER_CIRCUIT = 500;
```

## Logging Security

### Sensitive Data Handling

```cpp
// Never log:
// - Full IP addresses of clients
// - Circuit contents
// - Cryptographic keys
// - Destination hostnames (for exit relays)

// Safe to log:
// - Anonymized metrics
// - Error conditions
// - Circuit IDs (not contents)
// - Relay-to-relay connections
```

### Log Sanitization

```cpp
std::string sanitize_address(const IPAddress& addr) {
    // Log only /16 for IPv4
    return fmt::format("{}.{}.x.x",
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF);
}
```

## Operational Security

### File Permissions

```bash
# Key files: owner read only
chmod 600 /var/lib/tor/keys/*

# Config files: owner read only
chmod 600 /etc/tor/relay.toml

# Data directory
chmod 700 /var/lib/tor
```

### Process Isolation

```toml
[security]
# Run as unprivileged user
user = "tor"
group = "tor"

# Chroot (Linux)
chroot = "/var/lib/tor"

# Seccomp sandbox (Linux)
sandbox = true
```

### Docker Security

```yaml
# docker-compose.yml security settings
services:
  tor-relay:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if using port < 1024
    read_only: true
    tmpfs:
      - /tmp
```

## Security Checklist

### Deployment

- [ ] Run as non-root user
- [ ] Restrict file permissions on keys
- [ ] Enable firewall, allow only necessary ports
- [ ] Use secure DNS resolver
- [ ] Keep system and dependencies updated
- [ ] Monitor logs for anomalies

### Configuration

- [ ] Set appropriate bandwidth limits
- [ ] Configure exit policy carefully (if exit relay)
- [ ] Enable secure memory
- [ ] Set reasonable connection limits
- [ ] Configure log rotation

### Monitoring

- [ ] Monitor for unusual traffic patterns
- [ ] Alert on authentication failures
- [ ] Track circuit creation rates
- [ ] Monitor resource usage

## Vulnerability Reporting

Report security vulnerabilities to: security@example.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We follow responsible disclosure practices.
