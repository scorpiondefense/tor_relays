# Troubleshooting

## Common Issues

### Build Issues

#### OpenSSL Not Found

**Error:**
```
CMake Error: Could not find OpenSSL
```

**Solution:**
```bash
# Install OpenSSL development files
# Ubuntu/Debian
sudo apt install libssl-dev

# macOS
brew install openssl@3
cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

# Or set environment variable
export OPENSSL_ROOT_DIR=/path/to/openssl
```

#### Boost Not Found

**Error:**
```
CMake Error: Could not find Boost
```

**Solution:**
```bash
# Install Boost
# Ubuntu/Debian
sudo apt install libboost-all-dev

# macOS
brew install boost

# Set path if needed
cmake .. -DBOOST_ROOT=/path/to/boost
```

#### C++23 `std::expected` Not Available

**Error:**
```
error: 'expected' is not a member of 'std'
```

**Solution:**
The project uses C++23 `std::expected`. Update your compiler:
```bash
# Check version
g++ --version  # Need 14+ (production) or 12+ (minimum)
clang++ --version  # Need 16+

# Use specific compiler
cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++-14
```

#### obfs4_cpp Not Found

**Error:**
```
CMake Error: obfs4_cpp not found at .../obfs4_cpp or .../../obfs4_cpp
```

**Solution:**
Ensure `obfs4_cpp` exists as a sibling directory. In the monorepo:
```bash
ls ../obfs4_cpp/CMakeLists.txt  # Should exist
```

For standalone builds, symlink it:
```bash
ln -s /path/to/obfs4_cpp ../obfs4_cpp
```

### Runtime Issues

#### Cannot Bind to Port

**Error:**
```
Failed to bind to port 9002: Permission denied
```

**Solution:**
```bash
# Option 1: Use ports > 1024 (default: 9002 OR, 9443 obfs4)
./tor_relay --port 9002

# Option 2: Give capability (Linux)
sudo setcap 'cap_net_bind_service=+ep' ./tor_relay

# Option 3: Use Docker with port mapping
docker run -p 9002:9002 -p 9443:9443 tor-relay --mode bridge
```

#### Key Generation Fails

**Error:**
```
Failed to generate identity key: Random number generator not available
```

**Solution:**
```bash
# Check /dev/urandom exists
ls -la /dev/urandom

# In Docker, ensure it's mounted
docker run -v /dev/urandom:/dev/urandom tor-relay
```

#### TLS Handshake Fails

**Error:**
```
TLS handshake failed: certificate verify failed
```

**Solution:**
1. Check system time is correct
2. Verify certificate chain
3. Check TLS version compatibility

```bash
# Test TLS manually
openssl s_client -connect localhost:9001 -tls1_2

# Check system time
date

# Sync time
sudo ntpdate pool.ntp.org
```

#### obfs4 Handshake Fails

**Error:**
```
obfs4 handshake failed: MarkNotFound
obfs4 handshake failed: MacVerificationFailed
obfs4 handshake failed: EpochHourMismatch
```

**Solutions:**

1. **MarkNotFound** -- Client is not sending a valid obfs4 handshake. Check that the client has the correct `cert=` from the bridge line.

2. **MacVerificationFailed** -- The epoch-hour MAC doesn't match. This can happen if:
   - The client has the wrong cert (wrong bridge line)
   - Clock skew between client and bridge (> 1 hour)

3. **EpochHourMismatch** -- System clock is wrong:
```bash
# Check system time
date
# Sync time
sudo ntpdate pool.ntp.org
```

4. **Client has stale bridge line** -- If the `curve25519_onion` key was regenerated (e.g., PVC lost), all existing bridge lines are invalid. Distribute the new bridge line.

#### SIGSEGV in EXTEND2 Handler

**Error:**
```
Segmentation fault (core dumped)
```
in the EXTEND2 / circuit extension path.

**Cause:** Use-after-free of `ext_io`/`ext_tls` objects when the reader thread outlives their scope.

**Solution:** Update to v0.1.80 or later, which moves these objects into the reader thread closure to ensure correct lifetime.

#### v3 Link Handshake Fails (CERTS Cell)

**Error:**
```
CERTS cell rejected by peer
Ed25519 cert ext_length mismatch
```

**Cause:** The Ed25519 certificate extension length field was incorrectly set to 34 instead of 32 (the extension data is 32 bytes of Ed25519 public key, not 32 + 2 bytes of extension type/flags).

**Solution:** Update to v0.1.75 or later.

#### Cannot Connect to Directory Authorities

**Error:**
```
Failed to fetch consensus: Connection refused
```

**Solution:**
1. Check network connectivity
2. Verify firewall allows outbound connections
3. Check DNS resolution

```bash
# Test connectivity
nc -zv 128.31.0.39 9131  # moria1

# Check DNS
dig moria1.mit.edu

# Check firewall
sudo iptables -L OUTPUT
```

### Docker Issues

#### Container Exits Immediately

**Diagnosis:**
```bash
docker logs tor-bridge
docker inspect tor-bridge --format='{{.State.ExitCode}}'
```

**Common causes:**
1. Invalid configuration
2. Permission issues with mounted volumes (`/var/lib/tor` must be writable by `tor` user)
3. Missing `obfs4_cpp` at build time (build fails, no binary)

**Solution:**
```bash
# Run interactively to see errors
docker run -it --rm tor-relay --mode bridge --foreground

# Check volume permissions
docker run -it --rm -v tor-data:/var/lib/tor alpine ls -la /var/lib/tor

# Rebuild from monorepo root (ensures obfs4_cpp is included)
docker build -f tor_relays/Dockerfile .
```

#### Cannot Access Port

**Diagnosis:**
```bash
docker port tor-bridge
docker inspect tor-bridge --format='{{.NetworkSettings.Ports}}'
```

**Solution:**
```bash
# Ensure both ports are exposed (OR + obfs4)
docker run -p 9002:9002 -p 9443:9443 tor-relay --mode bridge

# Check if something else is using the ports
sudo lsof -i :9002
sudo lsof -i :9443
```

#### Keys Lost After Pod Restart (Kubernetes)

**Cause:** The PVC for `/var/lib/tor` was not configured, so keys existed only in the ephemeral container filesystem.

**Solution:**
```yaml
# In the Kubernetes deployment spec:
volumes:
  - name: tor-data
    persistentVolumeClaim:
      claimName: tor-bridge-data
volumeMounts:
  - name: tor-data
    mountPath: /var/lib/tor
```

After losing keys, the bridge line changes. Distribute the new bridge line to clients.

### Performance Issues

#### High CPU Usage

**Diagnosis:**
```bash
top -p $(pidof tor_relay)
perf top -p $(pidof tor_relay)
```

**Common causes:**
1. Too many connections
2. Bandwidth limit causing queuing
3. Debug logging enabled

**Solution:**
```toml
# Limit connections
[network]
max_connections = 4096

# Increase bandwidth if possible
[relay.bandwidth]
rate = 52428800  # 50 MB/s

# Reduce log level
[logging]
level = "warn"
```

#### High Memory Usage

**Diagnosis:**
```bash
# Check memory usage
ps aux | grep tor_relay
cat /proc/$(pidof tor_relay)/status | grep VmRSS

# Check for memory leaks (requires debug build)
valgrind --leak-check=full ./tor_relay
```

**Solution:**
```toml
# Limit circuits
[network]
max_circuits = 10000

# Limit queue sizes
max_circuit_queue_size = 524288  # 512 KB
```

#### Slow Circuit Creation

**Diagnosis:**
Check logs for timing:
```bash
grep "circuit created" relay.log | head -20
```

**Common causes:**
1. Slow crypto operations
2. Network latency
3. Overloaded relay

**Solution:**
```bash
# Check CPU has AES-NI support
grep aes /proc/cpuinfo

# Ensure OpenSSL uses hardware acceleration
openssl speed aes-128-cbc
```

### Configuration Issues

#### Config File Not Loaded

**Diagnosis:**
```bash
./tor_relay --config /path/to/config.toml -l debug 2>&1 | head -50
```

**Common causes:**
1. File not found
2. Permission denied
3. Syntax error in TOML

**Solution:**
```bash
# Check file exists and is readable
ls -la /path/to/config.toml
cat /path/to/config.toml

# Validate TOML syntax (requires toml-cli)
toml /path/to/config.toml
```

#### Exit Policy Not Working

**Diagnosis:**
```bash
# Check policy in descriptor
curl http://localhost:9030/tor/server/authority | grep -A 20 "exit-policy"
```

**Common causes:**
1. Mode is not "exit"
2. Policy syntax error
3. Policy rejects all

**Solution:**
```toml
[relay]
mode = "exit"  # Must be exit mode

[exit]
exit_policy = """
accept *:80
accept *:443
reject *:*
"""
```

## Diagnostic Commands

### Check Relay Status

```bash
# Process status
ps aux | grep tor_relay

# Port listening (should see 9002 and 9443)
ss -tlnp | grep tor_relay

# Connection count
ss -tnp | grep tor_relay | wc -l

# Resource usage
top -p $(pidof tor_relay) -b -n 1

# Thread count (detached threads per connection)
ls /proc/$(pidof tor_relay)/task | wc -l
```

### Check Logs

```bash
# Recent errors
grep -i error /var/log/tor/relay.log | tail -20

# obfs4 handshake results
grep -i "obfs4" /var/log/tor/relay.log | tail -20

# Link protocol handshake (CERTS cell issues)
grep -i "CERTS\|handshake\|link" /var/log/tor/relay.log | tail -20

# EXTEND2 / circuit extension
grep -i "EXTEND\|extend" /var/log/tor/relay.log | tail -20
```

### Network Diagnostics

```bash
# Check OR port TLS
openssl s_client -connect localhost:9002 -brief

# Check obfs4 port is listening
nc -zv YOUR_IP 9443

# Check from outside
nc -zv YOUR_IP 9002

# Verify bridge line (logged at startup)
grep "Bridge obfs4" /var/log/tor/relay.log
```

### Debug Mode

Run with maximum verbosity:
```bash
./tor_relay --foreground --log-level trace 2>&1 | tee debug.log
```

## Version History of Notable Fixes

| Version | Fix |
|---------|-----|
| v0.1.80 | SIGSEGV from use-after-free in EXTEND2 handler (ext_io/ext_tls lifetime) |
| v0.1.75 | Ed25519 cert ext_length (32 not 34) -- v3 link handshake now works |
| v0.1.74 | RSA-1024 identity key fix, SHA1 EVP migration for GCC 14 |
| v0.1.69 | Ed25519 cert extension fix, bridge liveness probe fix |

## Getting Help

When reporting issues, include:
- Operating system and version
- Compiler version (`g++ --version`, need GCC 14+ for production)
- OpenSSL version (`openssl version`, need 3.x)
- Relevant log output (especially CERTS, obfs4, EXTEND2 lines)
- Configuration (with keys and IPs removed)
- Steps to reproduce
- Version tag (e.g., `v0.1.80`)
