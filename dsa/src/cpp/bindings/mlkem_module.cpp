/**
 * ML-KEM Python Bindings
 *
 * Exposes ML-KEM-512, ML-KEM-768, ML-KEM-1024 classes to Python
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "common.hpp"
#include "mlkem/mlkem.hpp"

namespace py = pybind11;
using namespace mlkem;
using namespace dsa_bindings;

/**
 * Wrapper class for Python bindings
 * Handles type conversions between Python bytes and C++ vectors
 */
template<typename KEMClass>
class PyMLKEM {
public:
    PyMLKEM() : kem_() {}

    /**
     * Generate a key pair
     * @param seed Optional 64-byte seed for deterministic generation (d || z)
     * @return Tuple of (encapsulation_key, decapsulation_key) as bytes
     */
    py::tuple keygen(const py::object& seed = py::none()) {
        std::vector<uint8_t> seed_vec = optional_bytes_to_vector(seed);

        auto [ek, dk] = kem_.keygen(seed_vec);

        return py::make_tuple(vector_to_bytes(ek), vector_to_bytes(dk));
    }

    /**
     * Encapsulate to produce shared secret and ciphertext
     * @param ek Encapsulation key (bytes)
     * @param rand Optional 32-byte randomness for deterministic encapsulation
     * @return Tuple of (shared_secret, ciphertext) as bytes
     */
    py::tuple encaps(const py::bytes& ek, const py::object& rand = py::none()) {
        auto ek_vec = bytes_to_vector(ek);
        auto rand_vec = optional_bytes_to_vector(rand);

        // Validate encapsulation key size
        if (ek_vec.size() != kem_.params().ek_size()) {
            throw std::invalid_argument(
                "Invalid encapsulation key size: expected " +
                std::to_string(kem_.params().ek_size()) +
                " bytes, got " + std::to_string(ek_vec.size()));
        }

        auto [K, c] = kem_.encaps(ek_vec, rand_vec);

        return py::make_tuple(vector_to_bytes(K), vector_to_bytes(c));
    }

    /**
     * Decapsulate to recover shared secret
     * @param dk Decapsulation key (bytes)
     * @param ciphertext Ciphertext (bytes)
     * @return Shared secret as bytes
     */
    py::bytes decaps(const py::bytes& dk, const py::bytes& ciphertext) {
        auto dk_vec = bytes_to_vector(dk);
        auto ct_vec = bytes_to_vector(ciphertext);

        // Validate decapsulation key size
        if (dk_vec.size() != kem_.params().dk_size()) {
            throw std::invalid_argument(
                "Invalid decapsulation key size: expected " +
                std::to_string(kem_.params().dk_size()) +
                " bytes, got " + std::to_string(dk_vec.size()));
        }

        // Validate ciphertext size
        if (ct_vec.size() != kem_.params().ct_size()) {
            throw std::invalid_argument(
                "Invalid ciphertext size: expected " +
                std::to_string(kem_.params().ct_size()) +
                " bytes, got " + std::to_string(ct_vec.size()));
        }

        auto K = kem_.decaps(dk_vec, ct_vec);

        return vector_to_bytes(K);
    }

    /**
     * Get the parameter set
     */
    const Params& params() const { return kem_.params(); }

private:
    KEMClass kem_;
};

// Type aliases for convenience
using PyMLKEM512 = PyMLKEM<MLKEM512>;
using PyMLKEM768 = PyMLKEM<MLKEM768>;
using PyMLKEM1024 = PyMLKEM<MLKEM1024>;

/**
 * Bind the Params struct
 */
void bind_params(py::module_& m) {
    py::class_<Params>(m, "MLKEMParams",
        "ML-KEM parameter set containing algorithm constants")
        .def_readonly("name", &Params::name, "Parameter set name")
        .def_readonly("k", &Params::k, "Module rank")
        .def_readonly("eta1", &Params::eta1, "CBD parameter for secret")
        .def_readonly("eta2", &Params::eta2, "CBD parameter for error")
        .def_readonly("du", &Params::du, "Compression bits for u")
        .def_readonly("dv", &Params::dv, "Compression bits for v")
        .def_property_readonly("ek_size", &Params::ek_size,
            "Encapsulation key size in bytes")
        .def_property_readonly("dk_size", &Params::dk_size,
            "Decapsulation key size in bytes")
        .def_property_readonly("ct_size", &Params::ct_size,
            "Ciphertext size in bytes")
        .def_property_readonly("ss_size", &Params::ss_size,
            "Shared secret size in bytes")
        .def("__repr__", [](const Params& p) {
            return "<MLKEMParams '" + std::string(p.name) + "'>";
        });

    // Expose parameter set constants
    m.attr("MLKEM512_PARAMS") = &MLKEM512_PARAMS;
    m.attr("MLKEM768_PARAMS") = &MLKEM768_PARAMS;
    m.attr("MLKEM1024_PARAMS") = &MLKEM1024_PARAMS;
}

/**
 * Bind an ML-KEM class variant
 */
template<typename PyKEMClass>
void bind_mlkem_class(py::module_& m, const char* name, const char* doc) {
    py::class_<PyKEMClass>(m, name, doc)
        .def(py::init<>())
        .def("keygen", &PyKEMClass::keygen,
            py::arg("seed") = py::none(),
            R"doc(
Generate a key pair.

Args:
    seed: Optional 64-byte seed for deterministic key generation (d || z).
          If None, random keys are generated.

Returns:
    Tuple of (encapsulation_key, decapsulation_key) as bytes.

Raises:
    ValueError: If seed is provided but not 64 bytes.
)doc")
        .def("encaps", &PyKEMClass::encaps,
            py::arg("ek"),
            py::arg("rand") = py::none(),
            R"doc(
Encapsulate to produce shared secret and ciphertext.

Args:
    ek: Encapsulation key (bytes).
    rand: Optional 32-byte randomness for deterministic encapsulation.
          If None, random encapsulation is performed.

Returns:
    Tuple of (shared_secret, ciphertext) as bytes.

Raises:
    ValueError: If encapsulation key size is invalid.
)doc")
        .def("decaps", &PyKEMClass::decaps,
            py::arg("dk"),
            py::arg("ciphertext"),
            R"doc(
Decapsulate to recover shared secret.

Args:
    dk: Decapsulation key (bytes).
    ciphertext: Ciphertext (bytes).

Returns:
    Shared secret as bytes (32 bytes).

Note:
    If the ciphertext is invalid, a pseudorandom value is returned
    (implicit rejection) rather than raising an error. This provides
    protection against chosen-ciphertext attacks.

Raises:
    ValueError: If decapsulation key or ciphertext size is invalid.
)doc")
        .def_property_readonly("params", &PyKEMClass::params,
            py::return_value_policy::reference,
            "Get the parameter set for this instance");
}

PYBIND11_MODULE(_mlkem_native, m) {
    m.doc() = R"doc(
ML-KEM (FIPS 203) Native Bindings

This module provides Python bindings for the ML-KEM key encapsulation
mechanism, a post-quantum secure lattice-based KEM standardized by NIST.

Classes:
    MLKEM512: ML-KEM with security category 1 (128-bit classical)
    MLKEM768: ML-KEM with security category 3 (192-bit classical)
    MLKEM1024: ML-KEM with security category 5 (256-bit classical)

Example:
    >>> from mlkem import MLKEM768
    >>> kem = MLKEM768()
    >>> ek, dk = kem.keygen()
    >>> shared_secret, ciphertext = kem.encaps(ek)
    >>> recovered_secret = kem.decaps(dk, ciphertext)
    >>> assert shared_secret == recovered_secret
)doc";

    // Bind parameter struct and constants
    bind_params(m);

    // Bind ML-KEM classes
    bind_mlkem_class<PyMLKEM512>(m, "MLKEM512",
        "ML-KEM-512: Security Category 1 (NIST Level 1)");

    bind_mlkem_class<PyMLKEM768>(m, "MLKEM768",
        "ML-KEM-768: Security Category 3 (NIST Level 3)");

    bind_mlkem_class<PyMLKEM1024>(m, "MLKEM1024",
        "ML-KEM-1024: Security Category 5 (NIST Level 5)");

    // Version info
    m.attr("__version__") = "1.0.0";
}
