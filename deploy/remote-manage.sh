#!/bin/bash
# Remote management script for Tor Relay
# Usage: ./deploy/remote-manage.sh [user@host] [command]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

REMOTE_HOST="${1:-${REMOTE_HOST:-}}"
COMMAND="${2:-status}"

if [[ -z "$REMOTE_HOST" ]]; then
    echo -e "${RED}Error: Remote host not specified${NC}"
    echo "Usage: $0 user@host [command]"
    echo ""
    echo "Commands:"
    echo "  status    - Show relay status (default)"
    echo "  logs      - Show recent logs"
    echo "  follow    - Follow logs in real-time"
    echo "  restart   - Restart the relay"
    echo "  stop      - Stop the relay"
    echo "  start     - Start the relay"
    echo "  update    - Pull latest and restart"
    echo "  stats     - Show resource usage"
    echo "  shell     - Open shell in container"
    echo "  backup    - Backup keys to local machine"
    exit 1
fi

case "$COMMAND" in
    status)
        echo -e "${YELLOW}Relay Status:${NC}"
        ssh "$REMOTE_HOST" 'cd ~/tor-relay && docker-compose ps'
        echo ""
        echo -e "${YELLOW}Health:${NC}"
        ssh "$REMOTE_HOST" 'docker inspect tor-relay --format="{{.State.Health.Status}}" 2>/dev/null || echo "No health check"'
        ;;

    logs)
        ssh "$REMOTE_HOST" 'cd ~/tor-relay && docker-compose logs --tail=100'
        ;;

    follow)
        ssh "$REMOTE_HOST" 'cd ~/tor-relay && docker-compose logs -f'
        ;;

    restart)
        echo -e "${YELLOW}Restarting relay...${NC}"
        ssh "$REMOTE_HOST" 'cd ~/tor-relay && docker-compose restart'
        echo -e "${GREEN}✓ Relay restarted${NC}"
        ;;

    stop)
        echo -e "${YELLOW}Stopping relay...${NC}"
        ssh "$REMOTE_HOST" 'cd ~/tor-relay && docker-compose down'
        echo -e "${GREEN}✓ Relay stopped${NC}"
        ;;

    start)
        echo -e "${YELLOW}Starting relay...${NC}"
        ssh "$REMOTE_HOST" 'cd ~/tor-relay && docker-compose up -d'
        echo -e "${GREEN}✓ Relay started${NC}"
        ;;

    update)
        echo -e "${YELLOW}Updating relay...${NC}"
        ssh "$REMOTE_HOST" << 'UPDATE'
cd ~/tor-relay
docker-compose pull || docker compose pull
docker-compose up -d --build || docker compose up -d --build
UPDATE
        echo -e "${GREEN}✓ Relay updated${NC}"
        ;;

    stats)
        echo -e "${YELLOW}Resource Usage:${NC}"
        ssh "$REMOTE_HOST" 'docker stats tor-relay --no-stream'
        echo ""
        echo -e "${YELLOW}Connection Count:${NC}"
        ssh "$REMOTE_HOST" 'ss -tnp | grep -c ":9001" || echo "0"'
        ;;

    shell)
        echo -e "${YELLOW}Opening shell in container...${NC}"
        ssh -t "$REMOTE_HOST" 'docker exec -it tor-relay /bin/sh'
        ;;

    backup)
        echo -e "${YELLOW}Backing up keys...${NC}"
        BACKUP_DIR="backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP_DIR"

        ssh "$REMOTE_HOST" 'docker cp tor-relay:/var/lib/tor/keys - | tar -xf -' > "$BACKUP_DIR/keys.tar"
        tar -xf "$BACKUP_DIR/keys.tar" -C "$BACKUP_DIR"
        rm "$BACKUP_DIR/keys.tar"

        echo -e "${GREEN}✓ Keys backed up to $BACKUP_DIR/${NC}"
        echo -e "${RED}WARNING: Keep these keys secure! They are your relay's identity.${NC}"
        ;;

    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        exit 1
        ;;
esac
