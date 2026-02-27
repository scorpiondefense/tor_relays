# Multi-stage build for Tor Relay
# Build context: monorepo root (parent of tor_relays/)
# Usage: docker build -f tor_relays/Dockerfile .
# Or:    docker build -f infrastructure/docker/Dockerfile.tor-relays .

# Stage 1: Build
FROM ubuntu:24.04 AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libboost-all-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Conan
RUN pip3 install --break-system-packages conan

# Create build directory
WORKDIR /build

# Copy obfs4_cpp library (dependency)
COPY obfs4_cpp/ obfs4_cpp/

# Copy tor_relays source files
COPY tor_relays/CMakeLists.txt tor_relays/
COPY tor_relays/conanfile.txt tor_relays/
COPY tor_relays/include/ tor_relays/include/
COPY tor_relays/src/ tor_relays/src/
COPY tor_relays/tests/ tor_relays/tests/
COPY tor_relays/cmake/ tor_relays/cmake/

# Setup Conan profile
RUN conan profile detect

# Install dependencies
WORKDIR /build/tor_relays
RUN conan install . --build=missing --output-folder=build

# Build the project
WORKDIR /build/tor_relays/build
RUN cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF

RUN cmake --build . --parallel $(nproc)

# Stage 2: Runtime
FROM ubuntu:24.04 AS runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libboost-system1.83.0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false tor

# Copy binary from builder
COPY --from=builder /build/tor_relays/build/tor_relay /usr/local/bin/

# Create data directories
RUN mkdir -p /var/lib/tor/keys /var/log/tor /etc/tor \
    && chown -R tor:tor /var/lib/tor /var/log/tor

# Copy default configuration
COPY tor_relays/config/relay.toml.example /etc/tor/relay.toml

# Set permissions
RUN chmod 700 /var/lib/tor \
    && chmod 755 /usr/local/bin/tor_relay

# Switch to non-root user
USER tor

# Expose ports
# 9001 - OR port (main relay port)
# 9030 - Directory port (optional)
# 9090 - Metrics port (optional)
EXPOSE 443 9001 9030 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD nc -z localhost 9001 || exit 1

# Data volume
VOLUME ["/var/lib/tor"]

# Default command
ENTRYPOINT ["/usr/local/bin/tor_relay"]
CMD ["--config", "/etc/tor/relay.toml", "--foreground"]
