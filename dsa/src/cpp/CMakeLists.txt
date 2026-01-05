cmake_minimum_required(VERSION 3.20)
project(dsa VERSION 1.0.0 LANGUAGES CXX)

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

# ML-DSA library
add_library(mldsa STATIC
    mldsa/utils.cpp
)

target_include_directories(mldsa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(mldsa PUBLIC
    OpenSSL::Crypto
)

# SLH-DSA library
add_library(slhdsa STATIC
    slhdsa/utils.cpp
    slhdsa/hash_functions.cpp
)

target_include_directories(slhdsa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(slhdsa PUBLIC
    OpenSSL::Crypto
)

# ML-KEM library (FIPS 203)
add_library(mlkem STATIC
    mlkem/utils.cpp
)

target_include_directories(mlkem PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(mlkem PUBLIC
    OpenSSL::Crypto
)

# ML-DSA Test executable
add_executable(test_mldsa
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp/test_mldsa.cpp
)

target_link_libraries(test_mldsa PRIVATE
    mldsa
)

target_include_directories(test_mldsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# SLH-DSA Test executable
add_executable(test_slhdsa
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp/test_slhdsa.cpp
)

target_link_libraries(test_slhdsa PRIVATE
    slhdsa
)

target_include_directories(test_slhdsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Key generation tool (main executable)
add_executable(keygen
    main.cpp
)

target_link_libraries(keygen PRIVATE
    mldsa
    slhdsa
)

# Signing tool
add_executable(sign
    sign.cpp
)

target_link_libraries(sign PRIVATE
    mldsa
    slhdsa
)

# DSA demo executable
add_executable(dsa_demo
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/cpp/demo.cpp
)

target_link_libraries(dsa_demo PRIVATE
    mldsa
    slhdsa
)

target_include_directories(dsa_demo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ML-DSA Certificate Example
add_executable(mldsa_cert_example
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/cpp/mldsa_certificate.cpp
)

target_link_libraries(mldsa_cert_example PRIVATE
    mldsa
)

target_include_directories(mldsa_cert_example PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# SLH-DSA Certificate Example
add_executable(slhdsa_cert_example
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/cpp/slhdsa_certificate.cpp
)

target_link_libraries(slhdsa_cert_example PRIVATE
    slhdsa
)

target_include_directories(slhdsa_cert_example PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)


# ML-KEM Test executable
add_executable(test_mlkem
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp/test_mlkem.cpp
)

target_link_libraries(test_mlkem PRIVATE
    mlkem
)

target_include_directories(test_mlkem PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ML-KEM Demo executable
add_executable(mlkem_demo
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/cpp/mlkem_demo.cpp
)

target_link_libraries(mlkem_demo PRIVATE
    mlkem
)

target_include_directories(mlkem_demo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Install targets
install(TARGETS mldsa slhdsa mlkem
    ARCHIVE DESTINATION lib
)

install(DIRECTORY mldsa/
    DESTINATION include/mldsa
    FILES_MATCHING PATTERN "*.hpp"
)

install(DIRECTORY slhdsa/
    DESTINATION include/slhdsa
    FILES_MATCHING PATTERN "*.hpp"
)

install(DIRECTORY mlkem/
    DESTINATION include/mlkem
    FILES_MATCHING PATTERN "*.hpp"
)

# ML-DSA KAT Test executable
add_executable(test_mldsa_kat
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp/test_mldsa_kat.cpp
)

target_link_libraries(test_mldsa_kat PRIVATE
    mldsa
)

target_include_directories(test_mldsa_kat PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# SLH-DSA KAT Test executable
add_executable(test_slhdsa_kat
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp/test_slhdsa_kat.cpp
)

target_link_libraries(test_slhdsa_kat PRIVATE
    slhdsa
)

target_include_directories(test_slhdsa_kat PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Demo App Server
add_executable(demo_server
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/app/server.cpp
)

target_link_libraries(demo_server PRIVATE
    mldsa
    slhdsa
)

target_include_directories(demo_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Demo App Client
add_executable(demo_client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/app/client.cpp
)

target_link_libraries(demo_client PRIVATE
    mldsa
    slhdsa
)

target_include_directories(demo_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# CTest support
enable_testing()
add_test(NAME mldsa_tests COMMAND test_mldsa)
add_test(NAME slhdsa_tests COMMAND test_slhdsa)
add_test(NAME mlkem_tests COMMAND test_mlkem)
add_test(NAME mldsa_kat_tests COMMAND test_mldsa_kat)
add_test(NAME slhdsa_kat_tests COMMAND test_slhdsa_kat)

# Keygen Certificate Test executable
add_executable(test_keygen
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp/test_keygen.cpp
)

target_include_directories(test_keygen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_test(NAME keygen_tests COMMAND test_keygen)
