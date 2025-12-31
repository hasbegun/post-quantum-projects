# Building from Source

## Prerequisites

- CMake 3.20+
- C++20 compiler (GCC 10+, Clang 10+, MSVC 19.29+)
- OpenSSL development libraries
- Python 3.9+ (for Python bindings)

## C++ Library Only

Build the core C++ libraries without Python bindings:

```bash
cd dsa
mkdir build && cd build
cmake ../src/cpp -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Run C++ Tests

```bash
./test_mldsa
./test_slhdsa
./test_mldsa_kat
./test_slhdsa_kat
```

## Python Bindings

### Development Install

```bash
cd dsa
pip install scikit-build-core pybind11
pip install -e ".[dev]"
```

### Build Wheel

```bash
pip wheel . -w dist/
```

### Using Docker

```bash
make build-py
make test-py
```

## Build Options

CMake options:

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_PYTHON_BINDINGS` | OFF | Build Python bindings |
| `BUILD_TESTING` | ON | Build test executables |
| `CMAKE_BUILD_TYPE` | Release | Build type (Debug/Release) |

Example:
```bash
cmake .. -DBUILD_PYTHON_BINDINGS=ON -DCMAKE_BUILD_TYPE=Debug
```

## Project Structure

```
dsa/
├── src/
│   ├── cpp/
│   │   ├── mldsa/          # ML-DSA C++ implementation
│   │   ├── slhdsa/         # SLH-DSA C++ implementation
│   │   └── bindings/       # pybind11 bindings
│   └── py/
│       ├── mldsa/          # ML-DSA Python package
│       └── slhdsa/         # SLH-DSA Python package
├── tests/
│   ├── cpp/                # C++ tests
│   ├── py/                 # Python tests
│   └── benchmarks/         # Performance benchmarks
├── docs/                   # Documentation
├── CMakeLists.txt          # Root CMake config
└── pyproject.toml          # Python package config
```

## Troubleshooting

### pybind11 Not Found

```bash
pip install pybind11
```

### OpenSSL Headers Not Found

```bash
# macOS
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3

# Or specify in CMake
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
```
