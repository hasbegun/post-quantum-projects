/**
 * Common utilities for pybind11 bindings
 *
 * Provides type conversion helpers between Python bytes and C++ std::vector<uint8_t>
 */

#ifndef DSA_BINDINGS_COMMON_HPP
#define DSA_BINDINGS_COMMON_HPP

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <cstdint>
#include <span>
#include <string>

namespace py = pybind11;

namespace dsa_bindings {

/**
 * Convert Python bytes to std::vector<uint8_t>
 */
inline std::vector<uint8_t> bytes_to_vector(const py::bytes& b) {
    std::string s = b;
    return std::vector<uint8_t>(s.begin(), s.end());
}

/**
 * Convert std::vector<uint8_t> to Python bytes
 */
inline py::bytes vector_to_bytes(const std::vector<uint8_t>& v) {
    return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
}

/**
 * Convert optional Python bytes to std::vector<uint8_t>
 * Returns empty vector if None
 */
inline std::vector<uint8_t> optional_bytes_to_vector(const py::object& obj) {
    if (obj.is_none()) {
        return {};
    }
    return bytes_to_vector(obj.cast<py::bytes>());
}

} // namespace dsa_bindings

#endif // DSA_BINDINGS_COMMON_HPP
