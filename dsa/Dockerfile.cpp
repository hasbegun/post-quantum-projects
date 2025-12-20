# Dockerfile for ML-DSA and SLH-DSA C++20 Implementation
# Uses CMake and OpenSSL for building

FROM ubuntu:24.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY src/cpp/ ./src/cpp/
COPY tests/cpp/ ./tests/cpp/
COPY examples/cpp/ ./examples/cpp/
COPY examples/app/ ./examples/app/

# Create build directory and build
RUN mkdir -p build && cd build && \
    cmake ../src/cpp -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

# Default command runs ML-DSA tests
CMD ["./build/test_mldsa"]
