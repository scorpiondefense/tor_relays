# Deployment Guide

## Docker Deployment

### Local Docker

```bash
# Build image
docker build -t tor-relay .

# Run middle relay
docker run -d \
    --name tor-middle \
    --restart unless-stopped \
    -p 9001:9001 \
    -v tor-data:/var/lib/tor \
    tor-relay --mode middle

# Run exit relay with custom config
docker run -d \
    --name tor-exit \
    --restart unless-stopped \
    -p 9001:9001 \
    -v $(pwd)/config:/etc/tor:ro \
    -v tor-data:/var/lib/tor \
    tor-relay --mode exit --config /etc/tor/relay.toml

# View logs
docker logs -f tor-middle
```

### Docker Compose

See `docker-compose.yml` in the repository root for complete setup.

```bash
# Start relay
docker-compose up -d

# View logs
docker-compose logs -f

# Stop relay
docker-compose down

# Update and restart
docker-compose pull
docker-compose up -d
```

## Remote VPS Deployment

### Prerequisites

- VPS with public IPv4 address
- SSH access
- Docker and Docker Compose installed
- Ports 9001 (and optionally 9030) open in firewall

### Automated Deployment Script

```bash
# Deploy to remote server
./deploy/deploy.sh user@XXX.XXX.XXX.XXX
```

### Manual Deployment

1. **Prepare the server:**

```bash
# SSH to server
ssh user@XXX.XXX.XXX.XXX

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout and login again for group changes
exit
```

2. **Configure firewall:**

```bash
# UFW (Ubuntu)
sudo ufw allow 9001/tcp
sudo ufw allow 9030/tcp  # Optional: directory port
sudo ufw enable

# firewalld (CentOS/Fedora)
sudo firewall-cmd --permanent --add-port=9001/tcp
sudo firewall-cmd --permanent --add-port=9030/tcp
sudo firewall-cmd --reload
```

3. **Deploy the relay:**

```bash
# Create directory
mkdir -p ~/tor-relay
cd ~/tor-relay

# Copy files (from local machine)
scp -r docker-compose.yml config/ Dockerfile user@XXX.XXX.XXX.XXX:~/tor-relay/

# Or clone repository
git clone <repository> ~/tor-relay

# Start relay
docker-compose up -d
```

4. **Verify deployment:**

```bash
# Check status
docker-compose ps

# Check logs
docker-compose logs -f

# Test connectivity
nc -zv localhost 9001
```

## Production Configuration

### Recommended Settings

```toml
[relay]
nickname = "MyProductionRelay"
mode = "middle"
or_port = 9001
contact = "admin@example.com <0xFINGERPRINT>"

[relay.bandwidth]
rate = 104857600     # 100 MB/s
burst = 209715200    # 200 MB

[logging]
level = "info"
file = "/var/log/tor/relay.log"
max_size_mb = 100
max_files = 10

[network]
max_connections = 8192

[security]
secure_memory = true
```

### System Tuning

```bash
# /etc/sysctl.d/99-tor-relay.conf
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Apply
sudo sysctl -p /etc/sysctl.d/99-tor-relay.conf
```

### File Descriptor Limits

```bash
# /etc/security/limits.d/tor-relay.conf
* soft nofile 65535
* hard nofile 65535

# For systemd services
# /etc/systemd/system/docker.service.d/limits.conf
[Service]
LimitNOFILE=65535
```

## Monitoring

### Health Checks

```bash
# Docker health check (built into image)
docker inspect --format='{{.State.Health.Status}}' tor-relay

# Manual check
curl -s http://localhost:9030/tor/server/authority | head
```

### Prometheus Metrics

Metrics endpoint available at `:9090/metrics` when enabled:

```toml
[metrics]
enabled = true
port = 9090
```

### Log Monitoring

```bash
# Real-time logs
docker-compose logs -f --tail=100

# Search for errors
docker-compose logs | grep -i error

# Export logs
docker-compose logs > relay.log
```

## Backup and Recovery

### Backup Keys

```bash
# Backup identity keys (critical!)
docker cp tor-relay:/var/lib/tor/keys ./backup-keys-$(date +%Y%m%d)

# Or with volume
docker run --rm -v tor-data:/data -v $(pwd):/backup alpine \
    tar czf /backup/tor-keys-backup.tar.gz /data/keys
```

### Restore Keys

```bash
# Restore from backup
docker cp ./backup-keys/ tor-relay:/var/lib/tor/keys

# Restart relay
docker-compose restart
```

## Updating

```bash
# Pull latest image
docker-compose pull

# Recreate container with new image
docker-compose up -d

# Verify
docker-compose logs -f
```

## Troubleshooting Deployment

### Container won't start

```bash
# Check logs
docker-compose logs

# Check config syntax
docker run --rm -v $(pwd)/config:/etc/tor tor-relay --config /etc/tor/relay.toml --help
```

### Can't connect to relay

```bash
# Check if port is listening
ss -tlnp | grep 9001

# Check firewall
sudo iptables -L -n | grep 9001

# Test from outside
nc -zv XXX.XXX.XXX.XXX 9001
```

### High CPU/Memory usage

```bash
# Check resource usage
docker stats tor-relay

# Limit resources in docker-compose.yml
services:
  tor-relay:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```
