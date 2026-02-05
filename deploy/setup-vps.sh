#!/bin/bash
# Initial VPS setup script for Tor Relay
# Run this on a fresh VPS before deploying
# Usage: curl -sSL <url>/setup-vps.sh | bash

set -euo pipefail

echo "═══════════════════════════════════════════════════════════"
echo "  Tor Relay VPS Setup"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "[1/7] Updating system packages..."
case $OS in
    ubuntu|debian)
        apt-get update
        apt-get upgrade -y
        ;;
    centos|rhel|fedora)
        dnf update -y || yum update -y
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "[2/7] Installing essential packages..."
case $OS in
    ubuntu|debian)
        apt-get install -y \
            curl \
            wget \
            git \
            htop \
            iotop \
            net-tools \
            netcat-openbsd \
            fail2ban \
            unattended-upgrades
        ;;
    centos|rhel|fedora)
        dnf install -y \
            curl \
            wget \
            git \
            htop \
            iotop \
            net-tools \
            nc \
            fail2ban
        ;;
esac

echo "[3/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "Docker already installed"
fi

echo "[4/7] Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
else
    echo "Docker Compose already installed"
fi

echo "[5/7] Configuring firewall..."
case $OS in
    ubuntu|debian)
        if command -v ufw &> /dev/null; then
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow 9001/tcp comment "Tor OR port"
            ufw allow 9030/tcp comment "Tor Directory port"
            ufw --force enable
        fi
        ;;
    centos|rhel|fedora)
        if command -v firewall-cmd &> /dev/null; then
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-port=9001/tcp
            firewall-cmd --permanent --add-port=9030/tcp
            firewall-cmd --reload
        fi
        ;;
esac

echo "[6/7] Configuring system limits..."
cat > /etc/sysctl.d/99-tor-relay.conf << 'EOF'
# Network tuning for Tor relay
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
EOF
sysctl -p /etc/sysctl.d/99-tor-relay.conf

# File descriptor limits
cat > /etc/security/limits.d/tor-relay.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

# Systemd limits for Docker
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=65535
LimitNPROC=65535
EOF
systemctl daemon-reload
systemctl restart docker

echo "[7/7] Setting up automatic security updates..."
case $OS in
    ubuntu|debian)
        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        ;;
esac

# Enable fail2ban
systemctl enable fail2ban
systemctl start fail2ban

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  VPS Setup Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "System information:"
echo "  OS: $OS"
echo "  Docker: $(docker --version)"
echo "  Compose: $(docker-compose --version 2>/dev/null || docker compose version)"
echo ""
echo "Next steps:"
echo "  1. Create a non-root user for deployment"
echo "  2. Copy your SSH key to the new user"
echo "  3. Run the deploy script from your local machine"
echo ""
echo "  sudo adduser toroperator"
echo "  sudo usermod -aG docker toroperator"
echo ""
