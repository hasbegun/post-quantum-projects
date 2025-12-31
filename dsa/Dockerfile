# Dockerfile for Python with native C++ bindings
# Builds ML-DSA and SLH-DSA with pybind11

FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY src/ ./src/
COPY tests/ ./tests/
COPY examples/ ./examples/
COPY pyproject.toml CMakeLists.txt README.md ./

# Install build tools and the package with native bindings
RUN pip install --no-cache-dir scikit-build-core pybind11 pytest pytest-benchmark

# Build and install the package
RUN pip install -v .

# Default command runs tests
CMD ["python", "-m", "pytest", "tests/py/", "-v"]
