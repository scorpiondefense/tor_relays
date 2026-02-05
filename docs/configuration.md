# Configuration

## Configuration File

The relay uses TOML format for configuration. Default location: `/etc/tor/relay.toml`

### Complete Example

```toml
# Tor Relay Configuration

[relay]
# Relay nickname (1-19 alphanumeric characters)
nickname = "MyTorRelay"

# Operating mode: "middle", "exit", or "bridge"
mode = "middle"

# OR (Onion Router) port - main relay port
or_port = 9001

# Directory port (0 to disable)
dir_port = 9030

# Contact information (optional but recommended)
contact = "admin@example.com"

# Address to advertise (auto-detected if empty)
address = ""

# Address to bind to (0.0.0.0 for all interfaces)
bind_address = "0.0.0.0"

[relay.bandwidth]
# Rate limit in bytes per second (0 = unlimited)
rate = 10485760  # 10 MB/s

# Burst limit in bytes (0 = unlimited)
burst = 20971520  # 20 MB

# Advertised bandwidth (for directory)
advertised = 10485760

[exit]
# Exit policy (only used when mode = "exit")
# Rules are evaluated in order, first match wins
exit_policy = """
# Allow common web ports
accept *:80
accept *:443

# Allow SSH
accept *:22

# Allow email
accept *:587
accept *:993
accept *:995

# Reject everything else
reject *:*
"""

# Use reduced exit policy (common safe ports only)
# If true, overrides exit_policy above
reduced_exit_policy = false

# Reject connections to private addresses (always recommended)
reject_private = true

[bridge]
# Bridge distribution method
# Options: "https", "email", "moat", "none"
distribution = "https"

# Pluggable transport settings (optional)
[bridge.transport]
enabled = false
type = "obfs4"
bind_address = "0.0.0.0:9002"

[directory]
# Publish server descriptor to directory authorities
publish_server_descriptor = true

# Fetch directory updates
fetch_directory = true

# Directory cache (for serving directory info to others)
directory_cache = false

# How often to fetch new consensus (seconds)
fetch_interval = 3600

[logging]
# Log level: "trace", "debug", "info", "warn", "error"
level = "info"

# Log to file (empty = stdout only)
file = "/var/log/tor/relay.log"

# Log rotation
max_size_mb = 100
max_files = 5

[data]
# Data directory for keys, state, cached data
directory = "/var/lib/tor"

# Key file paths (relative to data directory)
identity_key = "keys/ed25519_identity"
onion_key = "keys/curve25519_onion"

[network]
# Connection timeout (seconds)
connect_timeout = 30

# Idle connection timeout (seconds)
idle_timeout = 600

# Maximum concurrent connections
max_connections = 8192

# TCP keepalive interval (seconds)
keepalive_interval = 30

[security]
# Require secure memory for keys
secure_memory = true

# Sandbox mode (Linux only, uses seccomp)
sandbox = false
```

## Command Line Options

Command line options override configuration file settings.

```
Usage: tor_relay [OPTIONS]

Options:
  -c, --config FILE     Configuration file path
  -m, --mode MODE       Relay mode: middle, exit, bridge
  -p, --port PORT       OR port to listen on
  -d, --dir-port PORT   Directory port (0 to disable)
  -n, --nickname NAME   Relay nickname
  --data-dir DIR        Data directory
  -f, --foreground      Run in foreground
  -l, --log-level LEVEL Log level: trace, debug, info, warn, error
  -h, --help            Show help
  -v, --version         Show version
```

### Examples

```bash
# Middle relay with custom port
./tor_relay --mode middle --port 443

# Exit relay with config file
./tor_relay --mode exit --config /etc/tor/exit.toml

# Bridge relay in foreground with debug logging
./tor_relay --mode bridge --port 9001 -f -l debug

# Override config file settings
./tor_relay -c /etc/tor/relay.toml --port 9002 --nickname "OverrideNick"
```

## Exit Policy Syntax

Exit policies control which destinations exit relays can connect to.

### Rule Format

```
action address:port
```

- **action**: `accept` or `reject`
- **address**: IP, CIDR notation, hostname, or `*` for any
- **port**: single port, range (80-443), or `*` for any

### Examples

```toml
exit_policy = """
# Allow HTTP/HTTPS to any address
accept *:80
accept *:443

# Allow SSH to specific network
accept 192.168.0.0/16:22

# Block specific IP
reject 10.0.0.1:*

# Block port range
reject *:25-26

# Default deny
reject *:*
"""
```

### Predefined Policies

```toml
# Use built-in reduced policy (recommended for new exit operators)
reduced_exit_policy = true
```

The reduced policy allows: 20-23, 43, 53, 79-81, 88, 110, 143, 194, 220, 389, 443, 464-465, 531, 543-544, 554, 563, 587, 636, 706, 749, 853, 873, 902-904, 981, 989-995, 1194, 1220, 1293, 1500, 1533, 1677, 1723, 1755, 1863, 2082-2083, 2086-2087, 2095-2096, 2102-2104, 3128, 3389, 3690, 4321, 4643, 5050, 5190, 5222-5223, 5228, 5900, 6660-6669, 6679, 6697, 8000, 8008, 8074, 8080, 8082, 8087-8088, 8232-8233, 8332-8333, 8443, 8888, 9418, 9999-10000, 11371, 19294, 19638, 50002, 64738

## Environment Variables

Environment variables can also be used for configuration:

```bash
export TOR_RELAY_MODE=middle
export TOR_RELAY_PORT=9001
export TOR_RELAY_NICKNAME=MyRelay
export TOR_RELAY_DATA_DIR=/var/lib/tor
export TOR_RELAY_LOG_LEVEL=info

./tor_relay
```

Priority order (highest to lowest):
1. Command line arguments
2. Environment variables
3. Configuration file
4. Built-in defaults

## Configuration Reload

Send SIGHUP to reload configuration without restart:

```bash
kill -HUP $(pidof tor_relay)
```

Reloadable settings:
- Bandwidth limits
- Exit policy
- Log level
- Contact information

Non-reloadable settings (require restart):
- Mode
- Port numbers
- Identity keys
