# Installation

## Prerequisites

### Required

- **C++ Compiler**: GCC 11+, Clang 14+, or MSVC 2022+
- **CMake**: 3.21 or higher
- **OpenSSL**: 3.0 or higher
- **Boost**: 1.82 or higher (system, asio components)

### Optional

- **Conan**: 2.x (recommended for dependency management)
- **Docker**: For containerized deployment
- **Catch2**: 3.5+ (for running tests)

## Building from Source

### Using Conan (Recommended)

```bash
# Install Conan if not present
pip install conan

# Clone repository
git clone <repository-url>
cd tor_relay

# Create build directory
mkdir build && cd build

# Install dependencies
conan install .. --build=missing --output-folder=.

# Configure with CMake
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

```bash
# Build image
docker build -t tor-relay .

# Run container
docker run -d \
    --name tor-relay \
    -p 9001:9001 \
    -v tor-data:/var/lib/tor \
    tor-relay --mode middle
```

## Verifying Installation

```bash
# Check version
./tor_relay --version

# Run with minimal config
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

### C++20 Features Not Available

Ensure your compiler supports C++20:
- GCC: version 11 or higher
- Clang: version 14 or higher
- MSVC: Visual Studio 2022 or higher

```bash
# Check GCC version
g++ --version

# Use specific compiler
cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++-12
```
