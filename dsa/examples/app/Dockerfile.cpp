# Dockerfile for Post-Quantum DSA Demo Application (C++)
#
# This image builds and runs the C++ demo server and client.

FROM ubuntu:24.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and netcat for healthchecks
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code (all files needed by CMakeLists.txt)
COPY src/cpp/ ./src/cpp/
COPY tests/cpp/ ./tests/cpp/
COPY examples/cpp/ ./examples/cpp/
COPY examples/app/ ./examples/app/

# Create build directory and build only the demo executables
RUN mkdir -p build && cd build && \
    cmake ../src/cpp -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) demo_server demo_client keygen dsa_demo

# Default command
CMD ["./build/demo_server", "--help"]
