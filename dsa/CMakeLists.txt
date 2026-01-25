# Root CMakeLists.txt for DSA Project
# Supports both standalone C++ build and Python bindings via pybind11

cmake_minimum_required(VERSION 3.20)
project(dsa VERSION 1.0.0 LANGUAGES CXX)

# Options
option(BUILD_PYTHON_BINDINGS "Build Python bindings using pybind11" OFF)
option(BUILD_TESTING "Build test executables" ON)
option(BUILD_EXAMPLES "Build example executables" ON)

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

# ML-KEM library (FIPS 203)
add_library(mlkem STATIC
    src/cpp/mlkem/utils.cpp
)

target_include_directories(mlkem PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(mlkem PUBLIC
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

    # ML-KEM Python module
    pybind11_add_module(_mlkem_native
        src/cpp/bindings/mlkem_module.cpp
    )
    target_link_libraries(_mlkem_native PRIVATE mlkem)
    target_include_directories(_mlkem_native PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
    )

    # Install Python modules to the correct location
    install(TARGETS _mldsa_native DESTINATION mldsa)
    install(TARGETS _slhdsa_native DESTINATION slhdsa)
    install(TARGETS _mlkem_native DESTINATION mlkem)
endif()

# ============================================================================
# Executables (keygen, sign)
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

# ============================================================================
# Examples (optional)
# ============================================================================

if(BUILD_EXAMPLES)
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

    # ML-KEM Demo
    add_executable(mlkem_demo
        examples/cpp/mlkem_demo.cpp
    )
    target_link_libraries(mlkem_demo PRIVATE mlkem)
    target_include_directories(mlkem_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

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

    # =========================================================================
    # Use Case Examples
    # =========================================================================

    # Code Signing - Sign Release
    add_executable(sign_release
        examples/use-cases/code-signing/sign_release.cpp
    )
    target_link_libraries(sign_release PRIVATE mldsa slhdsa)
    target_include_directories(sign_release PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # Code Signing - Verify Release
    add_executable(verify_release
        examples/use-cases/code-signing/verify_release.cpp
    )
    target_link_libraries(verify_release PRIVATE mldsa slhdsa)
    target_include_directories(verify_release PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # Firmware Signing - Sign Firmware
    add_executable(sign_firmware
        examples/use-cases/firmware-signing/sign_firmware.cpp
    )
    target_link_libraries(sign_firmware PRIVATE mldsa slhdsa)
    target_include_directories(sign_firmware PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # Firmware Signing - Verify Firmware
    add_executable(verify_firmware
        examples/use-cases/firmware-signing/verify_firmware.cpp
    )
    target_link_libraries(verify_firmware PRIVATE mldsa slhdsa)
    target_include_directories(verify_firmware PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # Document Signing - Sign Document
    add_executable(sign_document
        examples/use-cases/document-signing/sign_document.cpp
    )
    target_link_libraries(sign_document PRIVATE mldsa slhdsa)
    target_include_directories(sign_document PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # Document Signing - Verify Document
    add_executable(verify_document
        examples/use-cases/document-signing/verify_document.cpp
    )
    target_link_libraries(verify_document PRIVATE mldsa slhdsa)
    target_include_directories(verify_document PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # PQC Token - Create Token
    add_executable(pqc_token_create
        examples/use-cases/pqc-token/pqc_token.cpp
    )
    target_link_libraries(pqc_token_create PRIVATE mldsa slhdsa)
    target_include_directories(pqc_token_create PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

    # PQC Token - Verify Token
    add_executable(pqc_token_verify
        examples/use-cases/pqc-token/verify_pqc_token.cpp
    )
    target_link_libraries(pqc_token_verify PRIVATE mldsa slhdsa)
    target_include_directories(pqc_token_verify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
endif()

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

    # ML-KEM Tests
    add_executable(test_mlkem tests/cpp/test_mlkem.cpp)
    target_link_libraries(test_mlkem PRIVATE mlkem)
    target_include_directories(test_mlkem PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME mlkem_tests COMMAND test_mlkem)

    # Keygen Certificate Tests
    add_executable(test_keygen tests/cpp/test_keygen.cpp)
    target_include_directories(test_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME keygen_tests COMMAND test_keygen)

    # Constant-Time Verification Tests (dudect methodology)
    add_executable(test_constant_time tests/timing/test_constant_time.cpp)
    target_link_libraries(test_constant_time PRIVATE mldsa slhdsa)
    target_include_directories(test_constant_time PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/timing
    )
    add_test(NAME constant_time_tests COMMAND test_constant_time)

    # SIMD NTT Tests
    # Detect AVX2 support
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2)

    add_executable(test_simd tests/cpp/test_simd.cpp)
    target_link_libraries(test_simd PRIVATE mldsa mlkem)
    target_include_directories(test_simd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    if(COMPILER_SUPPORTS_AVX2)
        target_compile_options(test_simd PRIVATE -mavx2)
    endif()
    add_test(NAME simd_tests COMMAND test_simd)

    # PKCS#8 Key Format Tests
    add_executable(test_pkcs8 tests/cpp/test_pkcs8.cpp)
    target_link_libraries(test_pkcs8 PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_pkcs8 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME pkcs8_tests COMMAND test_pkcs8)

    # X.509 Certificate Tests
    add_executable(test_x509 tests/cpp/test_x509.cpp)
    target_link_libraries(test_x509 PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_x509 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME x509_tests COMMAND test_x509)

    # Runtime Algorithm Selection Tests
    add_executable(test_algorithm_factory tests/cpp/test_algorithm_factory.cpp)
    target_link_libraries(test_algorithm_factory PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_algorithm_factory PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME algorithm_factory_tests COMMAND test_algorithm_factory)

    # Batch Verification Tests
    add_executable(test_batch_verify tests/cpp/test_batch_verify.cpp)
    target_link_libraries(test_batch_verify PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_batch_verify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME batch_verify_tests COMMAND test_batch_verify)

    # Hybrid Cryptography Tests
    add_executable(test_hybrid tests/cpp/test_hybrid.cpp)
    target_link_libraries(test_hybrid PRIVATE mldsa slhdsa mlkem OpenSSL::Crypto)
    target_include_directories(test_hybrid PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME hybrid_tests COMMAND test_hybrid)

    # FIPS 140-3 Self-Test Tests
    add_executable(test_fips_selftest tests/cpp/test_fips_selftest.cpp)
    target_link_libraries(test_fips_selftest PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_fips_selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME fips_selftest_tests COMMAND test_fips_selftest)

    # Streaming API Tests
    add_executable(test_streaming tests/cpp/test_streaming.cpp)
    target_link_libraries(test_streaming PRIVATE mldsa slhdsa mlkem OpenSSL::Crypto)
    target_include_directories(test_streaming PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME streaming_tests COMMAND test_streaming)

    # HSM Integration Tests
    add_executable(test_hsm tests/cpp/test_hsm.cpp)
    target_link_libraries(test_hsm PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_hsm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME hsm_tests COMMAND test_hsm)

    # OpenSSL Provider Tests
    add_executable(test_ossl_provider tests/cpp/test_ossl_provider.cpp)
    target_link_libraries(test_ossl_provider PRIVATE mldsa slhdsa mlkem)
    target_include_directories(test_ossl_provider PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
    add_test(NAME ossl_provider_tests COMMAND test_ossl_provider)
endif()

# ============================================================================
# Fuzz Testing (requires Clang with libFuzzer)
# ============================================================================

option(BUILD_FUZZING "Build fuzz testing targets (requires Clang)" OFF)

if(BUILD_FUZZING)
    # Check for Clang (libFuzzer requires it)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "Fuzzing requires Clang compiler. Skipping fuzz targets.")
    else()
        message(STATUS "Building fuzz targets with libFuzzer")

        # Common fuzzer flags
        set(FUZZER_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g")

        # ML-DSA verification fuzzer
        add_executable(fuzz_mldsa_verify tests/fuzz/fuzz_mldsa_verify.cpp)
        target_link_libraries(fuzz_mldsa_verify PRIVATE mldsa)
        target_include_directories(fuzz_mldsa_verify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
        set_target_properties(fuzz_mldsa_verify PROPERTIES
            COMPILE_FLAGS "${FUZZER_FLAGS}"
            LINK_FLAGS "${FUZZER_FLAGS}"
        )

        # SLH-DSA verification fuzzer
        add_executable(fuzz_slhdsa_verify tests/fuzz/fuzz_slhdsa_verify.cpp)
        target_link_libraries(fuzz_slhdsa_verify PRIVATE slhdsa)
        target_include_directories(fuzz_slhdsa_verify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
        set_target_properties(fuzz_slhdsa_verify PROPERTIES
            COMPILE_FLAGS "${FUZZER_FLAGS}"
            LINK_FLAGS "${FUZZER_FLAGS}"
        )

        # ML-KEM decapsulation fuzzer
        add_executable(fuzz_mlkem_decaps tests/fuzz/fuzz_mlkem_decaps.cpp)
        target_link_libraries(fuzz_mlkem_decaps PRIVATE mlkem)
        target_include_directories(fuzz_mlkem_decaps PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)
        set_target_properties(fuzz_mlkem_decaps PROPERTIES
            COMPILE_FLAGS "${FUZZER_FLAGS}"
            LINK_FLAGS "${FUZZER_FLAGS}"
        )
    endif()
endif()

# ============================================================================
# Install
# ============================================================================

install(TARGETS mldsa slhdsa mlkem
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

install(DIRECTORY src/cpp/mlkem/
    DESTINATION include/mlkem
    FILES_MATCHING PATTERN "*.hpp"
)
