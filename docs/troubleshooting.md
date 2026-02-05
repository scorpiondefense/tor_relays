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

#### C++20 Features Not Available

**Error:**
```
error: 'expected' is not a member of 'std'
```

**Solution:**
Update your compiler:
```bash
# Check version
g++ --version  # Need 11+
clang++ --version  # Need 14+

# Use specific compiler
cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++-12
```

### Runtime Issues

#### Cannot Bind to Port

**Error:**
```
Failed to bind to port 9001: Permission denied
```

**Solution:**
```bash
# Option 1: Use port > 1024
./tor_relay --port 9001

# Option 2: Give capability (Linux)
sudo setcap 'cap_net_bind_service=+ep' ./tor_relay

# Option 3: Use Docker with port mapping
docker run -p 443:9001 tor-relay
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
docker logs tor-relay
docker inspect tor-relay --format='{{.State.ExitCode}}'
```

**Common causes:**
1. Invalid configuration
2. Permission issues with mounted volumes
3. Missing required files

**Solution:**
```bash
# Run interactively to see errors
docker run -it --rm tor-relay --foreground

# Check volume permissions
ls -la /path/to/data
docker run -it --rm -v /path/to/data:/var/lib/tor alpine ls -la /var/lib/tor
```

#### Cannot Access Port

**Diagnosis:**
```bash
docker port tor-relay
docker inspect tor-relay --format='{{.NetworkSettings.Ports}}'
```

**Solution:**
```bash
# Ensure port is exposed
docker run -p 9001:9001 tor-relay

# Check if something else is using the port
sudo lsof -i :9001
```

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

# Port listening
ss -tlnp | grep tor_relay

# Connection count
ss -tnp | grep tor_relay | wc -l

# Resource usage
top -p $(pidof tor_relay) -b -n 1
```

### Check Logs

```bash
# Recent errors
grep -i error /var/log/tor/relay.log | tail -20

# Warning messages
grep -i warn /var/log/tor/relay.log | tail -20

# Circuit statistics
grep "circuit" /var/log/tor/relay.log | tail -50
```

### Network Diagnostics

```bash
# Check TLS
openssl s_client -connect localhost:9001 -brief

# Check from outside
nc -zv YOUR_IP 9001

# Check descriptor
curl -s http://localhost:9030/tor/server/authority
```

### Debug Mode

Run with maximum verbosity:
```bash
./tor_relay --foreground --log-level trace 2>&1 | tee debug.log
```

## Getting Help

1. Check the [documentation](README.md)
2. Search existing [issues](https://github.com/your-repo/issues)
3. Ask on the [mailing list](mailto:tor-relays@lists.torproject.org)
4. File a [bug report](https://github.com/your-repo/issues/new)

When reporting issues, include:
- Operating system and version
- Compiler version
- OpenSSL version (`openssl version`)
- Relevant log output
- Configuration (with sensitive data removed)
- Steps to reproduce
