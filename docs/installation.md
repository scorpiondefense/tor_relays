# Installation

## Prerequisites

### Required

- **C++ Compiler**: GCC 14+ (production), or GCC 11+/Clang 14+/MSVC 2022+ (development)
- **CMake**: 3.21 or higher
- **OpenSSL**: 3.0 or higher (3.x series)
- **Boost**: 1.82 or higher (headers only; Asio is header-only)
- **obfs4_cpp**: Sibling directory in the monorepo (linked via CMake `add_subdirectory`)

### Optional

- **Conan**: 2.x (recommended for dependency management; provides spdlog, toml11)
- **Docker**: For containerized deployment (production path)
- **Catch2**: 3.5.2 (fetched automatically via CMake FetchContent)

## Building from Source

### Using Conan (Recommended)

The build requires `obfs4_cpp` as a sibling directory. In the monorepo layout:

```
monorepo/
├── obfs4_cpp/       # obfs4 pluggable transport library
├── tor_relays/      # this project
└── ...
```

```bash
# Install Conan if not present
pip install conan

# From the monorepo
cd tor_relays

# Setup Conan profile (first time only)
conan profile detect

# Install dependencies
conan install . --build=missing --output-folder=build

# Configure with CMake
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake \
         -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . --parallel

# Run tests
ctest --output-on-failure

# Install (optional)
sudo cmake --install .
```

### Manual Dependency Installation

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    libboost-all-dev

# Clone and build
git clone <repository-url>
cd tor_relay
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

#### Fedora/RHEL

```bash
sudo dnf install -y \
    gcc-c++ \
    cmake \
    openssl-devel \
    boost-devel

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

#### macOS

```bash
brew install cmake openssl@3 boost

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build . --parallel
```

#### Windows (Visual Studio)

```powershell
# Using vcpkg
vcpkg install openssl:x64-windows boost:x64-windows

mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## Docker Installation

The Dockerfile expects to be built from the monorepo root (parent of `tor_relays/`), since it copies both `obfs4_cpp/` and `tor_relays/`.

```bash
# Build from monorepo root
docker build -f tor_relays/Dockerfile -t tor-relay .

# Run as bridge with obfs4
docker run -d \
    --name tor-bridge \
    -p 9002:9002 \
    -p 9443:9443 \
    -v tor-data:/var/lib/tor \
    tor-relay --mode bridge --port 9002

# Or use docker-compose from tor_relays/
cd tor_relays
docker-compose up -d
```

### Kubernetes Deployment

The production deployment uses Kubernetes on DigitalOcean with a PVC for key persistence:

```yaml
volumes:
  - name: tor-data
    persistentVolumeClaim:
      claimName: tor-bridge-data  # CRITICAL: preserves keys across pod restarts
```

Losing the PVC means losing the `curve25519_onion` key, which invalidates all existing client bridge lines.

## Verifying Installation

```bash
# Check version
./tor_relay --version

# Run as bridge with obfs4 (production mode)
./tor_relay --mode bridge --port 9002 --foreground

# Run as middle relay (simplest test)
./tor_relay --mode middle --port 9001 --foreground

# Run tests
ctest -L unit
ctest -L integration
```

## Build Options

| CMake Option | Default | Description |
|--------------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Debug | Build type (Debug/Release/RelWithDebInfo) |
| `BUILD_TESTING` | ON | Build test suite |
| `BUILD_SHARED_LIBS` | OFF | Build shared libraries |
| `ENABLE_SANITIZERS` | OFF | Enable AddressSanitizer/UBSan |
| `ENABLE_COVERAGE` | OFF | Enable code coverage |

Example with options:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DBUILD_TESTING=ON \
         -DENABLE_SANITIZERS=ON
```

## Troubleshooting Build Issues

### OpenSSL Not Found

```bash
# Set OpenSSL path explicitly
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
```

### Boost Not Found

```bash
# Set Boost path explicitly
cmake .. -DBOOST_ROOT=/path/to/boost
```

### C++23 Features Not Available

The project requires C++23 (`std::expected`). Ensure your compiler supports it:
- GCC: version 14+ (production), 12+ (minimum for `std::expected`)
- Clang: version 16+ (for `std::expected`)
- MSVC: Visual Studio 2022 17.4+

```bash
# Check GCC version
g++ --version

# Use specific compiler
cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++-14
```

### obfs4_cpp Not Found

The CMake configuration looks for `obfs4_cpp` in two locations:
1. `${CMAKE_SOURCE_DIR}/obfs4_cpp/` (copied into build context)
2. `${CMAKE_SOURCE_DIR}/../obfs4_cpp/` (monorepo sibling)

If neither is found, the build fails. Ensure `obfs4_cpp` is checked out as a sibling directory or symlinked.
