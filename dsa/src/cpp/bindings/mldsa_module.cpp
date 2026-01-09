/**
 * ML-DSA Python Bindings
 *
 * Exposes ML-DSA-44, ML-DSA-65, ML-DSA-87 classes to Python
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "common.hpp"
#include "mldsa/mldsa.hpp"

namespace py = pybind11;
using namespace mldsa;
using namespace dsa_bindings;

/**
 * Wrapper class for Python bindings
 * Handles type conversions between Python bytes and C++ vectors
 */
template<typename DSAClass>
class PyMLDSA {
public:
    PyMLDSA() : dsa_() {}

    /**
     * Generate a key pair
     * @param seed Optional 32-byte seed for deterministic generation
     * @return Tuple of (public_key, secret_key) as bytes
     */
    py::tuple keygen(const py::object& seed = py::none()) {
        std::vector<uint8_t> seed_vec = optional_bytes_to_vector(seed);

        auto [pk, sk] = dsa_.keygen(seed_vec);

        return py::make_tuple(vector_to_bytes(pk), vector_to_bytes(sk));
    }

    /**
     * Sign a message
     * @param sk Secret key (bytes)
     * @param message Message to sign (bytes)
     * @param ctx Context string (bytes, optional, max 255 bytes)
     * @param deterministic Use deterministic signing if true
     * @return Signature as bytes
     */
    py::bytes sign(const py::bytes& sk,
                   const py::bytes& message,
                   const py::object& ctx = py::none(),
                   bool deterministic = false) {
        auto sk_vec = bytes_to_vector(sk);
        auto msg_vec = bytes_to_vector(message);
        auto ctx_vec = optional_bytes_to_vector(ctx);

        // Validate secret key size
        if (sk_vec.size() != dsa_.params().sk_size()) {
            throw std::invalid_argument("Invalid secret key format");
        }

        // Validate context size
        if (ctx_vec.size() > 255) {
            throw std::invalid_argument(
                "Context string exceeds maximum length of 255 bytes");
        }

        auto sig = dsa_.sign(sk_vec, msg_vec, ctx_vec, deterministic);

        return vector_to_bytes(sig);
    }

    /**
     * Verify a signature
     * @param pk Public key (bytes)
     * @param message Message (bytes)
     * @param signature Signature (bytes)
     * @param ctx Context string (bytes, optional)
     * @return True if valid, False otherwise
     */
    bool verify(const py::bytes& pk,
                const py::bytes& message,
                const py::bytes& signature,
                const py::object& ctx = py::none()) {
        auto pk_vec = bytes_to_vector(pk);
        auto msg_vec = bytes_to_vector(message);
        auto sig_vec = bytes_to_vector(signature);
        auto ctx_vec = optional_bytes_to_vector(ctx);

        // Validate public key size
        if (pk_vec.size() != dsa_.params().pk_size()) {
            throw std::invalid_argument("Invalid public key format");
        }

        // Validate signature size
        if (sig_vec.size() != dsa_.params().sig_size()) {
            throw std::invalid_argument("Invalid signature format");
        }

        // Validate context size
        if (ctx_vec.size() > 255) {
            throw std::invalid_argument(
                "Context string exceeds maximum length of 255 bytes");
        }

        return dsa_.verify(pk_vec, msg_vec, sig_vec, ctx_vec);
    }

    /**
     * Get the parameter set
     */
    const Params& params() const { return dsa_.params(); }

private:
    DSAClass dsa_;
};

// Type aliases for convenience
using PyMLDSA44 = PyMLDSA<MLDSA44>;
using PyMLDSA65 = PyMLDSA<MLDSA65>;
using PyMLDSA87 = PyMLDSA<MLDSA87>;

/**
 * Bind the Params struct
 */
void bind_params(py::module_& m) {
    py::class_<Params>(m, "MLDSAParams",
        "ML-DSA parameter set containing algorithm constants")
        .def_readonly("name", &Params::name, "Parameter set name")
        .def_readonly("k", &Params::k, "Matrix rows")
        .def_readonly("l", &Params::l, "Matrix columns")
        .def_readonly("eta", &Params::eta, "Secret key range")
        .def_readonly("tau", &Params::tau, "Challenge weight")
        .def_readonly("beta", &Params::beta, "Signature bound")
        .def_readonly("gamma1", &Params::gamma1, "Mask range")
        .def_readonly("gamma2", &Params::gamma2, "Decomposition low bits")
        .def_readonly("omega", &Params::omega, "Max hint weight")
        .def_readonly("lambda_", &Params::lambda, "Security parameter (bits)")
        .def_property_readonly("pk_size", &Params::pk_size,
            "Public key size in bytes")
        .def_property_readonly("sk_size", &Params::sk_size,
            "Secret key size in bytes")
        .def_property_readonly("sig_size", &Params::sig_size,
            "Signature size in bytes")
        .def("__repr__", [](const Params& p) {
            return "<MLDSAParams '" + std::string(p.name) + "'>";
        });

    // Expose parameter set constants
    m.attr("MLDSA44_PARAMS") = &MLDSA44_PARAMS;
    m.attr("MLDSA65_PARAMS") = &MLDSA65_PARAMS;
    m.attr("MLDSA87_PARAMS") = &MLDSA87_PARAMS;
}

/**
 * Bind an ML-DSA class variant
 */
template<typename PyDSAClass>
void bind_mldsa_class(py::module_& m, const char* name, const char* doc) {
    py::class_<PyDSAClass>(m, name, doc)
        .def(py::init<>())
        .def("keygen", &PyDSAClass::keygen,
            py::arg("seed") = py::none(),
            R"doc(
Generate a key pair.

Args:
    seed: Optional 32-byte seed for deterministic key generation.
          If None, random keys are generated.

Returns:
    Tuple of (public_key, secret_key) as bytes.

Raises:
    ValueError: If seed is provided but not 32 bytes.
)doc")
        .def("sign", &PyDSAClass::sign,
            py::arg("sk"),
            py::arg("message"),
            py::arg("ctx") = py::none(),
            py::arg("deterministic") = false,
            R"doc(
Sign a message.

Args:
    sk: Secret key (bytes).
    message: Message to sign (bytes).
    ctx: Optional context string (bytes, max 255 bytes).
    deterministic: If True, use deterministic signing (same signature
                   for same inputs). Default False.

Returns:
    Signature as bytes.

Raises:
    ValueError: If context string exceeds 255 bytes.
)doc")
        .def("verify", &PyDSAClass::verify,
            py::arg("pk"),
            py::arg("message"),
            py::arg("signature"),
            py::arg("ctx") = py::none(),
            R"doc(
Verify a signature.

Args:
    pk: Public key (bytes).
    message: Message (bytes).
    signature: Signature to verify (bytes).
    ctx: Optional context string (bytes, must match signing context).

Returns:
    True if signature is valid, False otherwise.
)doc")
        .def_property_readonly("params", &PyDSAClass::params,
            py::return_value_policy::reference,
            "Get the parameter set for this instance");
}

PYBIND11_MODULE(_mldsa_native, m) {
    m.doc() = R"doc(
ML-DSA (FIPS 204) Native Bindings

This module provides Python bindings for the ML-DSA digital signature
algorithm, a post-quantum secure lattice-based signature scheme
standardized by NIST.

Classes:
    MLDSA44: ML-DSA with security category 2 (128-bit classical)
    MLDSA65: ML-DSA with security category 3 (192-bit classical)
    MLDSA87: ML-DSA with security category 5 (256-bit classical)

Example:
    >>> from mldsa import MLDSA65
    >>> dsa = MLDSA65()
    >>> pk, sk = dsa.keygen()
    >>> sig = dsa.sign(sk, b"Hello, World!")
    >>> assert dsa.verify(pk, b"Hello, World!", sig)
)doc";

    // Bind parameter struct and constants
    bind_params(m);

    // Bind ML-DSA classes
    bind_mldsa_class<PyMLDSA44>(m, "MLDSA44",
        "ML-DSA-44: Security Category 2 (NIST Level 2)");

    bind_mldsa_class<PyMLDSA65>(m, "MLDSA65",
        "ML-DSA-65: Security Category 3 (NIST Level 3)");

    bind_mldsa_class<PyMLDSA87>(m, "MLDSA87",
        "ML-DSA-87: Security Category 5 (NIST Level 5)");

    // Version info
    m.attr("__version__") = "1.0.0";
}
