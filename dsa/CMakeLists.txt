# Root CMakeLists.txt for DSA Project
# Supports both standalone C++ build and Python bindings via pybind11

cmake_minimum_required(VERSION 3.20)
project(dsa VERSION 1.0.0 LANGUAGES CXX)

# Options
option(BUILD_PYTHON_BINDINGS "Build Python bindings using pybind11" OFF)
option(BUILD_TESTING "Build test executables" ON)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -Wpedantic -DNDEBUG")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# ============================================================================
# Core Libraries (mldsa, slhdsa)
# ============================================================================

# Enable PIC for static libraries when building Python bindings
# This is required because static libs will be linked into shared objects
if(BUILD_PYTHON_BINDINGS)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# ML-DSA library
add_library(mldsa STATIC
    src/cpp/mldsa/utils.cpp
)

target_include_directories(mldsa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(mldsa PUBLIC
    OpenSSL::Crypto
)

# SLH-DSA library
add_library(slhdsa STATIC
    src/cpp/slhdsa/utils.cpp
    src/cpp/slhdsa/hash_functions.cpp
)

target_include_directories(slhdsa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(slhdsa PUBLIC
    OpenSSL::Crypto
)

# ============================================================================
# Python Bindings (optional)
# ============================================================================

if(BUILD_PYTHON_BINDINGS)
    # Fetch pybind11
    include(FetchContent)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG v2.11.1
    )
    FetchContent_MakeAvailable(pybind11)

    # ML-DSA Python module
    pybind11_add_module(_mldsa_native
        src/cpp/bindings/mldsa_module.cpp
    )
    target_link_libraries(_mldsa_native PRIVATE mldsa)
    target_include_directories(_mldsa_native PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
    )

    # SLH-DSA Python module
    pybind11_add_module(_slhdsa_native
        src/cpp/bindings/slhdsa_module.cpp
    )
    target_link_libraries(_slhdsa_native PRIVATE slhdsa)
    target_include_directories(_slhdsa_native PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
    )

    # Install Python modules to the correct location
    install(TARGETS _mldsa_native DESTINATION mldsa)
    install(TARGETS _slhdsa_native DESTINATION slhdsa)
endif()

# ============================================================================
# Executables (keygen, sign, demos)
# ============================================================================

# Key generation tool
add_executable(keygen
    src/cpp/main.cpp
)
target_link_libraries(keygen PRIVATE mldsa slhdsa)

# Signing tool
add_executable(sign
    src/cpp/sign.cpp
)
target_link_libraries(sign PRIVATE mldsa slhdsa)

# DSA demo
add_executable(dsa_demo
    examples/cpp/demo.cpp
)
target_link_libraries(dsa_demo PRIVATE mldsa slhdsa)
target_include_directories(dsa_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

# ML-DSA Certificate Example
add_executable(mldsa_cert_example
    examples/cpp/mldsa_certificate.cpp
)
target_link_libraries(mldsa_cert_example PRIVATE mldsa)
target_include_directories(mldsa_cert_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

# SLH-DSA Certificate Example
add_executable(slhdsa_cert_example
    examples/cpp/slhdsa_certificate.cpp
)
target_link_libraries(slhdsa_cert_example PRIVATE slhdsa)
target_include_directories(slhdsa_cert_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

# Demo App Server
add_executable(demo_server
    examples/app/server.cpp
)
target_link_libraries(demo_server PRIVATE mldsa slhdsa)
target_include_directories(demo_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

# Demo App Client
add_executable(demo_client
    examples/app/client.cpp
)
target_link_libraries(demo_client PRIVATE mldsa slhdsa)
target_include_directories(demo_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

# ============================================================================
# Tests
# ============================================================================

if(BUILD_TESTING)
    enable_testing()

    # ML-DSA Tests
    add_executable(test_mldsa tests/cpp/test_mldsa.cpp)
    target_link_libraries(test_mldsa PRIVATE mldsa)
    target_include_directories(test_mldsa PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME mldsa_tests COMMAND test_mldsa)

    # SLH-DSA Tests
    add_executable(test_slhdsa tests/cpp/test_slhdsa.cpp)
    target_link_libraries(test_slhdsa PRIVATE slhdsa)
    target_include_directories(test_slhdsa PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME slhdsa_tests COMMAND test_slhdsa)

    # ML-DSA KAT Tests
    add_executable(test_mldsa_kat tests/cpp/test_mldsa_kat.cpp)
    target_link_libraries(test_mldsa_kat PRIVATE mldsa)
    target_include_directories(test_mldsa_kat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME mldsa_kat_tests COMMAND test_mldsa_kat)

    # SLH-DSA KAT Tests
    add_executable(test_slhdsa_kat tests/cpp/test_slhdsa_kat.cpp)
    target_link_libraries(test_slhdsa_kat PRIVATE slhdsa)
    target_include_directories(test_slhdsa_kat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME slhdsa_kat_tests COMMAND test_slhdsa_kat)

    # Keygen Certificate Tests
    add_executable(test_keygen tests/cpp/test_keygen.cpp)
    target_include_directories(test_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME keygen_tests COMMAND test_keygen)
endif()

# ============================================================================
# Install
# ============================================================================

install(TARGETS mldsa slhdsa
    ARCHIVE DESTINATION lib
)

install(DIRECTORY src/cpp/mldsa/
    DESTINATION include/mldsa
    FILES_MATCHING PATTERN "*.hpp"
)

install(DIRECTORY src/cpp/slhdsa/
    DESTINATION include/slhdsa
    FILES_MATCHING PATTERN "*.hpp"
)
