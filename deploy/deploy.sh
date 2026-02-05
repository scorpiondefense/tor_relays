#!/bin/bash
# Deploy Tor Relay to remote VPS
# Usage: ./deploy/deploy.sh [user@host] [--mode middle|exit|bridge]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
REMOTE_HOST="${1:-${REMOTE_HOST:-}}"
RELAY_MODE="${RELAY_MODE:-middle}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse arguments
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            RELAY_MODE="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate
if [[ -z "$REMOTE_HOST" ]]; then
    echo -e "${RED}Error: Remote host not specified${NC}"
    echo "Usage: $0 user@host [--mode middle|exit|bridge]"
    echo "Or set REMOTE_HOST environment variable"
    exit 1
fi

if [[ ! "$RELAY_MODE" =~ ^(middle|exit|bridge)$ ]]; then
    echo -e "${RED}Error: Invalid mode '$RELAY_MODE'. Use: middle, exit, or bridge${NC}"
    exit 1
fi

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Tor Relay Deployment${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Target:  ${YELLOW}$REMOTE_HOST${NC}"
echo -e "  Mode:    ${YELLOW}$RELAY_MODE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Step 1: Check SSH connectivity
echo -e "${YELLOW}[1/6] Checking SSH connectivity...${NC}"
if ! ssh -o ConnectTimeout=10 "$REMOTE_HOST" "echo 'SSH OK'" >/dev/null 2>&1; then
    echo -e "${RED}Error: Cannot connect to $REMOTE_HOST${NC}"
    exit 1
fi
echo -e "${GREEN}✓ SSH connection successful${NC}"

# Step 2: Install Docker on remote if needed
echo -e "${YELLOW}[2/6] Ensuring Docker is installed...${NC}"
ssh "$REMOTE_HOST" << 'DOCKER_INSTALL'
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Installing Docker Compose..."
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

docker --version
docker-compose --version || docker compose version
DOCKER_INSTALL
echo -e "${GREEN}✓ Docker ready${NC}"

# Step 3: Create remote directory structure
echo -e "${YELLOW}[3/6] Creating directory structure...${NC}"
ssh "$REMOTE_HOST" << 'MKDIR'
mkdir -p ~/tor-relay/config ~/tor-relay/logs
chmod 700 ~/tor-relay
MKDIR
echo -e "${GREEN}✓ Directories created${NC}"

# Step 4: Copy files to remote
echo -e "${YELLOW}[4/6] Copying files to remote...${NC}"
rsync -avz --progress \
    "$PROJECT_DIR/Dockerfile" \
    "$PROJECT_DIR/docker-compose.yml" \
    "$PROJECT_DIR/config/relay.toml.example" \
    "$REMOTE_HOST:~/tor-relay/"

# Copy and customize config
ssh "$REMOTE_HOST" << CUSTOMIZE
cd ~/tor-relay
if [[ ! -f config/relay.toml ]]; then
    cp relay.toml.example config/relay.toml
    # Customize based on mode
    sed -i 's/mode = "middle"/mode = "$RELAY_MODE"/' config/relay.toml
    # Generate random nickname suffix
    NICK_SUFFIX=\$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
    sed -i "s/nickname = \"MyTorRelay\"/nickname = \"Relay\$NICK_SUFFIX\"/" config/relay.toml
fi
CUSTOMIZE
echo -e "${GREEN}✓ Files copied${NC}"

# Step 5: Configure firewall
echo -e "${YELLOW}[5/6] Configuring firewall...${NC}"
ssh "$REMOTE_HOST" << 'FIREWALL'
# UFW
if command -v ufw &> /dev/null; then
    ufw allow 9001/tcp comment "Tor OR port"
    ufw allow 9030/tcp comment "Tor Directory port"
    ufw --force enable || true
fi

# firewalld
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=9001/tcp || true
    firewall-cmd --permanent --add-port=9030/tcp || true
    firewall-cmd --reload || true
fi

# iptables (fallback)
if ! command -v ufw &> /dev/null && ! command -v firewall-cmd &> /dev/null; then
    iptables -A INPUT -p tcp --dport 9001 -j ACCEPT || true
    iptables -A INPUT -p tcp --dport 9030 -j ACCEPT || true
fi
FIREWALL
echo -e "${GREEN}✓ Firewall configured${NC}"

# Step 6: Build and start
echo -e "${YELLOW}[6/6] Building and starting relay...${NC}"
ssh "$REMOTE_HOST" << 'START'
cd ~/tor-relay

# Stop existing if running
docker-compose down 2>/dev/null || docker compose down 2>/dev/null || true

# Build and start
docker-compose up -d --build || docker compose up -d --build

# Show status
echo ""
echo "Container status:"
docker-compose ps || docker compose ps

echo ""
echo "Recent logs:"
docker-compose logs --tail=20 || docker compose logs --tail=20
START

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Your Tor relay is now running on ${YELLOW}$REMOTE_HOST${NC}"
echo ""
echo -e "  Useful commands:"
echo -e "    View logs:    ${YELLOW}ssh $REMOTE_HOST 'cd ~/tor-relay && docker-compose logs -f'${NC}"
echo -e "    Stop relay:   ${YELLOW}ssh $REMOTE_HOST 'cd ~/tor-relay && docker-compose down'${NC}"
echo -e "    Restart:      ${YELLOW}ssh $REMOTE_HOST 'cd ~/tor-relay && docker-compose restart'${NC}"
echo ""
echo -e "  The relay will appear on Tor Metrics after ~3 hours:"
echo -e "    ${YELLOW}https://metrics.torproject.org/rs.html${NC}"
echo ""
