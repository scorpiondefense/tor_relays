# Deployment Guide

## Bridge Deployment with obfs4 (Kubernetes)

This is the recommended production deployment for a Tor bridge relay with obfs4 pluggable transport.

### Prerequisites

- Kubernetes cluster with a worker node that has a **public IP** accessible from the internet
- The worker node must expose ports **9002** (OR) and **9443** (obfs4) via `hostPort`
- DigitalOcean Container Registry (or any Docker registry) with the `tor-relays` image
- PersistentVolumeClaim for key persistence across pod restarts

### Architecture

```
Internet
    │
    ▼ (port 9443, obfs4)
┌────────────────────────────────┐
│  K8s Worker Node (public IP)   │
│  ┌──────────────────────────┐  │
│  │  tor-bridge Pod          │  │
│  │  ┌────────────────────┐  │  │
│  │  │ obfs4 listener     │──┼──┼── hostPort 9443
│  │  │   ↕ proxy           │  │  │
│  │  │ OR port (TLS)      │──┼──┼── hostPort 9002
│  │  │   ↕                 │  │  │
│  │  │ Circuit handler     │  │  │
│  │  │   ↕ EXTEND2         │  │  │
│  │  │ Upstream Tor relays │  │  │
│  │  └────────────────────┘  │  │
│  │  /var/lib/tor/keys/ (PVC)│  │
│  └──────────────────────────┘  │
└────────────────────────────────┘
```

### Step 1: Build and Push Docker Image

The Docker build requires both `tor_relays/` and `obfs4_cpp/` from the monorepo root.

```bash
# From monorepo root
docker build -f infrastructure/docker/Dockerfile.tor-relays \
    -t registry.digitalocean.com/scorpion-intelligence/tor-relays:v0.1.79 \
    -t registry.digitalocean.com/scorpion-intelligence/tor-relays:latest .

docker push registry.digitalocean.com/scorpion-intelligence/tor-relays:v0.1.79
docker push registry.digitalocean.com/scorpion-intelligence/tor-relays:latest
```

Or trigger via Jenkins:
```bash
# Get crumb for CSRF protection
CRUMB=$(curl -sk --cookie-jar /tmp/jenkins_cookies -u 'admin:PASSWORD' \
  "https://builder.mylobster.ai/crumbIssuer/api/json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crumbRequestField']+':'+d['crumb'])")

# Trigger build
curl -sk --cookie /tmp/jenkins_cookies -u 'admin:PASSWORD' -X POST \
  "https://builder.mylobster.ai/job/scorpion-release/buildWithParameters" \
  -H "${CRUMB}" --data-urlencode "TAG_NAME=v0.1.79"
```

### Step 2: Create Kubernetes Resources

**ConfigMap** (`infrastructure/k8s/tor/configmap.yaml`):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tor-bridge-config
  namespace: scorpion-intelligence
data:
  relay.toml: |
    [relay]
    nickname = "TorBridge"
    mode = "bridge"
    or_port = 9002
    dir_port = 0
    contact = "admin@example.com"

    [bridge]
    distribution = "https"

    [bridge.transport]
    enabled = true
    type = "obfs4"
    port = 9443
    iat_mode = 0

    [directory]
    publish_server_descriptor = false
    fetch_directory = true
    directory_cache = false

    [logging]
    level = "info"
    file = ""

    [data]
    directory = "/var/lib/tor"

    [security]
    secure_memory = true
```

**PersistentVolumeClaim** (critical for key persistence):

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: tor-bridge-data-pvc
  namespace: scorpion-intelligence
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
```

**Deployment** (`infrastructure/k8s/tor/deployments.yaml`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scorpion-tor-bridge
  namespace: scorpion-intelligence
spec:
  replicas: 1
  strategy:
    type: Recreate  # Required: only one pod can hold the PVC
  selector:
    matchLabels:
      app: scorpion-tor-bridge
  template:
    metadata:
      labels:
        app: scorpion-tor-bridge
    spec:
      imagePullSecrets:
        - name: docr-registry
      containers:
        - name: tor-relay
          image: registry.digitalocean.com/scorpion-intelligence/tor-relays:latest
          args:
            - "-c"
            - "/etc/tor/relay.toml"
            - "-m"
            - "bridge"
            - "-p"
            - "9002"
            - "-n"
            - "TorBridge"
            - "-f"
            - "-l"
            - "info"
            - "--data-dir"
            - "/var/lib/tor"
          ports:
            - containerPort: 9443
              hostPort: 9443      # obfs4 — must be reachable from internet
              protocol: TCP
            - containerPort: 9002
              hostPort: 9002      # OR port
              protocol: TCP
          volumeMounts:
            - name: tor-data
              mountPath: /var/lib/tor
            - name: tor-config
              mountPath: /etc/tor
              readOnly: true
          resources:
            requests:
              cpu: 50m
              memory: 256Mi
            limits:
              cpu: "2"
              memory: 2Gi
          livenessProbe:
            tcpSocket:
              port: 9443
            initialDelaySeconds: 60
            periodSeconds: 30
      volumes:
        - name: tor-data
          persistentVolumeClaim:
            claimName: tor-bridge-data-pvc
        - name: tor-config
          configMap:
            name: tor-bridge-config
```

### Step 3: Apply and Verify

```bash
# Apply all manifests
kubectl apply -f infrastructure/k8s/tor/

# Wait for pod to be ready
kubectl -n scorpion-intelligence rollout status deployment/scorpion-tor-bridge

# Get the bridge line from logs
kubectl -n scorpion-intelligence logs -l app=scorpion-tor-bridge | grep "Bridge line:"
```

The bridge line will look like:
```
Bridge obfs4 <WORKER_IP>:9443 <FINGERPRINT> cert=<OBFS4_CERT> iat-mode=0
```

**Important**: Use the worker node's **public IP** (not the pod IP or reserved IP).

### Step 4: Verify Keys Are Persisted

```bash
# Check key files exist
kubectl -n scorpion-intelligence exec -it deploy/scorpion-tor-bridge -- ls -la /var/lib/tor/keys/
```

Expected files:
```
-rw------- tor tor  32 ed25519_identity_secret_key
-rw------- tor tor  32 ed25519_onion_secret_key
-rw------- tor tor  32 curve25519_onion_secret_key
-rw------- tor tor 607 rsa1024_identity_secret_key
```

All four key files must exist. The `ed25519_onion_secret_key` is especially critical — it determines the obfs4 certificate. If this file is missing, the bridge generates a new one on each restart, changing the obfs4 cert and breaking client connections.

### Step 5: Configure Tor Browser

1. Open Tor Browser
2. Go to Settings > Connection > Bridges
3. Select "Provide a bridge" and enter:
   ```
   obfs4 <WORKER_IP>:9443 <FINGERPRINT> cert=<CERT> iat-mode=0
   ```
4. Connect

### Step 6: Verify End-to-End

Monitor server logs while a client connects:
```bash
kubectl -n scorpion-intelligence logs -f -l app=scorpion-tor-bridge
```

Expected log sequence for a successful connection:
```
obfs4: accepted connection #N
obfs4 handshake completed successfully
OR: negotiated link protocol v5
CERTS: Type4 self-verify=PASS
CERTS: Type5 self-verify=PASS
CERTS: TLS SHA256 match=PASS
OR: link protocol handshake complete
OR: circuit NNNNN created (CREATE_FAST)       # Directory circuit
OR: proxying dir request: /tor/status-vote/... # Consensus download
OR: circuit NNNNN created (CREATE2/ntor)       # User circuit
OR: EXTEND2 success on circuit NNNNN           # Extending to Tor network
```

### Updating the Bridge

```bash
# Update image tag
kubectl -n scorpion-intelligence set image \
    deployment/scorpion-tor-bridge \
    tor-relay=registry.digitalocean.com/scorpion-intelligence/tor-relays:v0.1.79

# Restart to pick up new image
kubectl -n scorpion-intelligence rollout restart deployment/scorpion-tor-bridge

# Watch rollout
kubectl -n scorpion-intelligence rollout status deployment/scorpion-tor-bridge
```

After updating, verify the obfs4 cert is the same (if keys are persisted):
```bash
kubectl -n scorpion-intelligence logs -l app=scorpion-tor-bridge | grep "obfs4 cert:"
```

---

## Docker Deployment (Standalone)

### Build

```bash
# From monorepo root (needs both tor_relays/ and obfs4_cpp/)
docker build -f infrastructure/docker/Dockerfile.tor-relays -t tor-relays .
```

### Run as Bridge with obfs4

```bash
docker run -d \
    --name tor-bridge \
    --restart unless-stopped \
    -p 9002:9002 \
    -p 9443:9443 \
    -v tor-bridge-data:/var/lib/tor \
    tor-relays \
    -m bridge -p 9002 -n MyBridge -f -l info --data-dir /var/lib/tor
```

### Run as Middle Relay

```bash
docker run -d \
    --name tor-middle \
    --restart unless-stopped \
    -p 9001:9001 \
    -v tor-middle-data:/var/lib/tor \
    tor-relays \
    --mode middle --port 9001
```

### Run as Exit Relay

```bash
docker run -d \
    --name tor-exit \
    --restart unless-stopped \
    -p 9001:9001 \
    -v tor-exit-data:/var/lib/tor \
    -v $(pwd)/config:/etc/tor:ro \
    tor-relays \
    --mode exit --config /etc/tor/relay.toml
```

### Docker Compose

```yaml
version: '3.8'
services:
  tor-bridge:
    image: tor-relays:latest
    command: ["-m", "bridge", "-p", "9002", "-n", "MyBridge", "-f", "-l", "info", "--data-dir", "/var/lib/tor"]
    ports:
      - "9002:9002"
      - "9443:9443"
    volumes:
      - tor-data:/var/lib/tor
    restart: unless-stopped

volumes:
  tor-data:
```

```bash
docker-compose up -d
docker-compose logs -f
```

---

## Remote VPS Deployment

### Prerequisites

- VPS with public IPv4 address
- SSH access
- Docker installed
- Ports 9002 and 9443 open in firewall (for bridge mode)

### Firewall Setup

```bash
# UFW (Ubuntu)
sudo ufw allow 9002/tcp   # OR port
sudo ufw allow 9443/tcp   # obfs4 port
sudo ufw enable

# firewalld (CentOS/Fedora)
sudo firewall-cmd --permanent --add-port=9002/tcp
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --reload
```

### Deploy

```bash
ssh user@YOUR_VPS_IP

# Pull and run
docker pull registry.digitalocean.com/scorpion-intelligence/tor-relays:latest
docker run -d \
    --name tor-bridge \
    --restart unless-stopped \
    -p 9002:9002 \
    -p 9443:9443 \
    -v tor-bridge-data:/var/lib/tor \
    registry.digitalocean.com/scorpion-intelligence/tor-relays:latest \
    -m bridge -p 9002 -n MyBridge -f -l info --data-dir /var/lib/tor

# Get bridge line
docker logs tor-bridge 2>&1 | grep "Bridge line:"
```

---

## Production Configuration

### Recommended Settings

```toml
[relay]
nickname = "MyProductionRelay"
mode = "bridge"
or_port = 9002
contact = "admin@example.com"

[bridge.transport]
enabled = true
type = "obfs4"
port = 9443
iat_mode = 0

[relay.bandwidth]
rate = 104857600     # 100 MB/s
burst = 209715200    # 200 MB

[logging]
level = "info"
file = ""            # stdout for Docker/K8s

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

---

## Backup and Recovery

### Backup Keys

```bash
# Docker
docker cp tor-bridge:/var/lib/tor/keys ./backup-keys-$(date +%Y%m%d)

# Kubernetes
kubectl -n scorpion-intelligence cp scorpion-tor-bridge-POD:/var/lib/tor/keys ./backup-keys
```

### Restore Keys

```bash
# Docker
docker cp ./backup-keys/ tor-bridge:/var/lib/tor/keys
docker restart tor-bridge

# Kubernetes
kubectl -n scorpion-intelligence cp ./backup-keys scorpion-tor-bridge-POD:/var/lib/tor/keys
kubectl -n scorpion-intelligence rollout restart deployment/scorpion-tor-bridge
```

---

## Monitoring

```bash
# Real-time logs
kubectl -n scorpion-intelligence logs -f -l app=scorpion-tor-bridge

# Check for errors
kubectl -n scorpion-intelligence logs -l app=scorpion-tor-bridge | grep -i "error\|warn"

# Connectivity test
nc -zv WORKER_IP 9443
```
