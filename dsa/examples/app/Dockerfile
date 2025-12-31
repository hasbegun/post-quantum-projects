# Dockerfile for Post-Quantum DSA Demo Application
# Builds with native C++ bindings

FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy DSA source code
COPY src/ ./src/
COPY pyproject.toml CMakeLists.txt README.md ./

# Copy demo app
COPY examples/app/ ./examples/app/

# Install build tools and the package
RUN pip install --no-cache-dir scikit-build-core pybind11
RUN pip install -v .

# Default command
CMD ["python", "--version"]
