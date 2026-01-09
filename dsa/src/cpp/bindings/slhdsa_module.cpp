/**
 * SLH-DSA Python Bindings
 *
 * Exposes all 12 SLH-DSA parameter set classes to Python
 *
 * IMPORTANT: We do NOT use "using namespace slhdsa" or directly bind slhdsa::Params
 * because the slhdsa namespace contains a template function `concat` which conflicts
 * with pybind11's internal `concat` function via ADL (Argument Dependent Lookup).
 * Instead, we create wrapper structs in our own namespace that are safe to bind.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include "common.hpp"
#include "slhdsa/slh_dsa.hpp"

namespace py = pybind11;
using namespace dsa_bindings;

namespace slhdsa_bindings {

/**
 * Wrapper struct for SLH-DSA parameters that lives outside the slhdsa namespace.
 * This avoids ADL conflicts with slhdsa::concat when used with pybind11.
 */
struct PySLHDSAParams {
    std::string name;
    size_t n;
    size_t h;
    size_t d;
    size_t hp;
    size_t a;
    size_t k;
    size_t lg_w;
    size_t m;
    size_t pk_size;
    size_t sk_size;
    size_t sig_size;

    PySLHDSAParams(const slhdsa::Params& p)
        : name(p.name)
        , n(p.n)
        , h(p.h)
        , d(p.d)
        , hp(p.hp)
        , a(p.a)
        , k(p.k)
        , lg_w(p.lg_w)
        , m(p.m)
        , pk_size(p.pk_size())
        , sk_size(p.sk_size())
        , sig_size(p.sig_size())
    {}

    size_t w() const { return 1 << lg_w; }

    std::string repr() const {
        return "<SLHDSAParams '" + name + "'>";
    }
};

// Pre-created parameter wrappers
inline PySLHDSAParams make_params(const slhdsa::Params& p) {
    return PySLHDSAParams(p);
}

/**
 * Wrapper class for Python bindings
 * Handles type conversions between Python bytes and C++ vectors
 */
template<const slhdsa::Params& P>
class PySLHDSA {
public:
    PySLHDSA() : dsa_() {}

    /**
     * Generate a key pair
     * @return Tuple of (public_key, secret_key) as bytes
     */
    py::tuple keygen() {
        auto [sk, pk] = dsa_.keygen();
        // Note: C++ returns (sk, pk), Python convention is (pk, sk)
        return py::make_tuple(vector_to_bytes(pk), vector_to_bytes(sk));
    }

    /**
     * Generate a key pair from seeds (for testing/KAT)
     */
    py::tuple keygen_from_seeds(const py::bytes& sk_seed,
                                 const py::bytes& sk_prf,
                                 const py::bytes& pk_seed) {
        auto sk_seed_vec = bytes_to_vector(sk_seed);
        auto sk_prf_vec = bytes_to_vector(sk_prf);
        auto pk_seed_vec = bytes_to_vector(pk_seed);

        auto [sk, pk] = dsa_.keygen(sk_seed_vec, sk_prf_vec, pk_seed_vec);

        return py::make_tuple(vector_to_bytes(pk), vector_to_bytes(sk));
    }

    /**
     * Sign a message
     * @param sk Secret key (bytes)
     * @param message Message to sign (bytes)
     * @param ctx Context string (bytes, optional, max 255 bytes)
     * @param randomize Use randomized signing if true (default)
     * @return Signature as bytes
     */
    py::bytes sign(const py::bytes& sk,
                   const py::bytes& message,
                   const py::object& ctx = py::none(),
                   bool randomize = true) {
        auto sk_vec = bytes_to_vector(sk);
        auto msg_vec = bytes_to_vector(message);
        auto ctx_vec = optional_bytes_to_vector(ctx);

        // Validate secret key size
        if (sk_vec.size() != P.sk_size()) {
            throw std::invalid_argument("Invalid secret key format");
        }

        // Validate context size
        if (ctx_vec.size() > 255) {
            throw std::invalid_argument(
                "Context string exceeds maximum length of 255 bytes");
        }

        auto sig = dsa_.sign(sk_vec, msg_vec, ctx_vec, randomize);

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
        if (pk_vec.size() != P.pk_size()) {
            throw std::invalid_argument("Invalid public key format");
        }

        // Validate signature size
        if (sig_vec.size() != P.sig_size()) {
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
     * Get the parameter set (returns a copy wrapped in our safe wrapper)
     */
    PySLHDSAParams get_params() const {
        return PySLHDSAParams(dsa_.params());
    }

private:
    slhdsa::SLHDSA<P> dsa_;
};

// Type aliases for all 12 parameter sets
using PySLHDSA_SHA2_128s = PySLHDSA<slhdsa::SLH_DSA_SHA2_128s>;
using PySLHDSA_SHA2_128f = PySLHDSA<slhdsa::SLH_DSA_SHA2_128f>;
using PySLHDSA_SHA2_192s = PySLHDSA<slhdsa::SLH_DSA_SHA2_192s>;
using PySLHDSA_SHA2_192f = PySLHDSA<slhdsa::SLH_DSA_SHA2_192f>;
using PySLHDSA_SHA2_256s = PySLHDSA<slhdsa::SLH_DSA_SHA2_256s>;
using PySLHDSA_SHA2_256f = PySLHDSA<slhdsa::SLH_DSA_SHA2_256f>;
using PySLHDSA_SHAKE_128s = PySLHDSA<slhdsa::SLH_DSA_SHAKE_128s>;
using PySLHDSA_SHAKE_128f = PySLHDSA<slhdsa::SLH_DSA_SHAKE_128f>;
using PySLHDSA_SHAKE_192s = PySLHDSA<slhdsa::SLH_DSA_SHAKE_192s>;
using PySLHDSA_SHAKE_192f = PySLHDSA<slhdsa::SLH_DSA_SHAKE_192f>;
using PySLHDSA_SHAKE_256s = PySLHDSA<slhdsa::SLH_DSA_SHAKE_256s>;
using PySLHDSA_SHAKE_256f = PySLHDSA<slhdsa::SLH_DSA_SHAKE_256f>;

} // namespace slhdsa_bindings

using namespace slhdsa_bindings;

/**
 * Bind the Params wrapper struct
 */
void bind_params(py::module_& m) {
    py::class_<PySLHDSAParams>(m, "SLHDSAParams",
        "SLH-DSA parameter set containing algorithm constants")
        .def_readonly("name", &PySLHDSAParams::name, "Parameter set name")
        .def_readonly("n", &PySLHDSAParams::n, "Security parameter (hash output bytes)")
        .def_readonly("h", &PySLHDSAParams::h, "Total tree height")
        .def_readonly("d", &PySLHDSAParams::d, "Number of hypertree layers")
        .def_readonly("hp", &PySLHDSAParams::hp, "Height per layer (h/d)")
        .def_readonly("a", &PySLHDSAParams::a, "FORS tree height")
        .def_readonly("k", &PySLHDSAParams::k, "Number of FORS trees")
        .def_readonly("lg_w", &PySLHDSAParams::lg_w, "Log2 of Winternitz parameter")
        .def_readonly("m", &PySLHDSAParams::m, "Message digest length")
        .def_property_readonly("w", &PySLHDSAParams::w, "Winternitz parameter (2^lg_w)")
        .def_readonly("pk_size", &PySLHDSAParams::pk_size, "Public key size in bytes")
        .def_readonly("sk_size", &PySLHDSAParams::sk_size, "Secret key size in bytes")
        .def_readonly("sig_size", &PySLHDSAParams::sig_size, "Signature size in bytes")
        .def("__repr__", &PySLHDSAParams::repr);

    // Expose parameter set constants as wrapper instances
    m.attr("SLH_DSA_SHA2_128s") = make_params(slhdsa::SLH_DSA_SHA2_128s);
    m.attr("SLH_DSA_SHA2_128f") = make_params(slhdsa::SLH_DSA_SHA2_128f);
    m.attr("SLH_DSA_SHA2_192s") = make_params(slhdsa::SLH_DSA_SHA2_192s);
    m.attr("SLH_DSA_SHA2_192f") = make_params(slhdsa::SLH_DSA_SHA2_192f);
    m.attr("SLH_DSA_SHA2_256s") = make_params(slhdsa::SLH_DSA_SHA2_256s);
    m.attr("SLH_DSA_SHA2_256f") = make_params(slhdsa::SLH_DSA_SHA2_256f);
    m.attr("SLH_DSA_SHAKE_128s") = make_params(slhdsa::SLH_DSA_SHAKE_128s);
    m.attr("SLH_DSA_SHAKE_128f") = make_params(slhdsa::SLH_DSA_SHAKE_128f);
    m.attr("SLH_DSA_SHAKE_192s") = make_params(slhdsa::SLH_DSA_SHAKE_192s);
    m.attr("SLH_DSA_SHAKE_192f") = make_params(slhdsa::SLH_DSA_SHAKE_192f);
    m.attr("SLH_DSA_SHAKE_256s") = make_params(slhdsa::SLH_DSA_SHAKE_256s);
    m.attr("SLH_DSA_SHAKE_256f") = make_params(slhdsa::SLH_DSA_SHAKE_256f);
}

/**
 * Bind an SLH-DSA class variant
 */
template<typename PyDSAClass>
void bind_slhdsa_class(py::module_& m, const char* name, const char* doc) {
    py::class_<PyDSAClass>(m, name, doc)
        .def(py::init<>())
        .def("keygen", &PyDSAClass::keygen,
            R"doc(
Generate a key pair.

Returns:
    Tuple of (public_key, secret_key) as bytes.
)doc")
        .def("keygen_from_seeds", &PyDSAClass::keygen_from_seeds,
            py::arg("sk_seed"),
            py::arg("sk_prf"),
            py::arg("pk_seed"),
            R"doc(
Generate a key pair from seeds (for testing/KAT).

Args:
    sk_seed: Secret seed (n bytes).
    sk_prf: PRF key for randomization (n bytes).
    pk_seed: Public seed (n bytes).

Returns:
    Tuple of (public_key, secret_key) as bytes.

Raises:
    ValueError: If seeds are not the correct size.
)doc")
        .def("sign", &PyDSAClass::sign,
            py::arg("sk"),
            py::arg("message"),
            py::arg("ctx") = py::none(),
            py::arg("randomize") = true,
            R"doc(
Sign a message.

Args:
    sk: Secret key (bytes).
    message: Message to sign (bytes).
    ctx: Optional context string (bytes, max 255 bytes).
    randomize: If True (default), use randomized signing.
               If False, use deterministic signing.

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
        .def_property_readonly("params", &PyDSAClass::get_params,
            "Get the parameter set for this instance");
}

PYBIND11_MODULE(_slhdsa_native, m) {
    m.doc() = R"doc(
SLH-DSA (FIPS 205) Native Bindings

This module provides Python bindings for the SLH-DSA digital signature
algorithm, a post-quantum secure stateless hash-based signature scheme
standardized by NIST.

Parameter Sets:
    SHA2 variants (faster on systems with SHA2 hardware acceleration):
        - SLHDSA_SHA2_128s, SLHDSA_SHA2_128f: 128-bit security
        - SLHDSA_SHA2_192s, SLHDSA_SHA2_192f: 192-bit security
        - SLHDSA_SHA2_256s, SLHDSA_SHA2_256f: 256-bit security

    SHAKE variants (consistent performance across platforms):
        - SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f: 128-bit security
        - SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f: 192-bit security
        - SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f: 256-bit security

    's' suffix = smaller signatures, slower signing
    'f' suffix = faster signing, larger signatures

Example:
    >>> from slhdsa import SLHDSA_SHAKE_128f
    >>> dsa = SLHDSA_SHAKE_128f()
    >>> pk, sk = dsa.keygen()
    >>> sig = dsa.sign(sk, b"Hello, World!")
    >>> assert dsa.verify(pk, b"Hello, World!", sig)
)doc";

    // Bind parameter struct and constants
    bind_params(m);

    // Bind SHA2 variants
    bind_slhdsa_class<PySLHDSA_SHA2_128s>(m, "SLHDSA_SHA2_128s",
        "SLH-DSA-SHA2-128s: 128-bit security, small signatures");
    bind_slhdsa_class<PySLHDSA_SHA2_128f>(m, "SLHDSA_SHA2_128f",
        "SLH-DSA-SHA2-128f: 128-bit security, fast signing");
    bind_slhdsa_class<PySLHDSA_SHA2_192s>(m, "SLHDSA_SHA2_192s",
        "SLH-DSA-SHA2-192s: 192-bit security, small signatures");
    bind_slhdsa_class<PySLHDSA_SHA2_192f>(m, "SLHDSA_SHA2_192f",
        "SLH-DSA-SHA2-192f: 192-bit security, fast signing");
    bind_slhdsa_class<PySLHDSA_SHA2_256s>(m, "SLHDSA_SHA2_256s",
        "SLH-DSA-SHA2-256s: 256-bit security, small signatures");
    bind_slhdsa_class<PySLHDSA_SHA2_256f>(m, "SLHDSA_SHA2_256f",
        "SLH-DSA-SHA2-256f: 256-bit security, fast signing");

    // Bind SHAKE variants
    bind_slhdsa_class<PySLHDSA_SHAKE_128s>(m, "SLHDSA_SHAKE_128s",
        "SLH-DSA-SHAKE-128s: 128-bit security, small signatures");
    bind_slhdsa_class<PySLHDSA_SHAKE_128f>(m, "SLHDSA_SHAKE_128f",
        "SLH-DSA-SHAKE-128f: 128-bit security, fast signing");
    bind_slhdsa_class<PySLHDSA_SHAKE_192s>(m, "SLHDSA_SHAKE_192s",
        "SLH-DSA-SHAKE-192s: 192-bit security, small signatures");
    bind_slhdsa_class<PySLHDSA_SHAKE_192f>(m, "SLHDSA_SHAKE_192f",
        "SLH-DSA-SHAKE-192f: 192-bit security, fast signing");
    bind_slhdsa_class<PySLHDSA_SHAKE_256s>(m, "SLHDSA_SHAKE_256s",
        "SLH-DSA-SHAKE-256s: 256-bit security, small signatures");
    bind_slhdsa_class<PySLHDSA_SHAKE_256f>(m, "SLHDSA_SHAKE_256f",
        "SLH-DSA-SHAKE-256f: 256-bit security, fast signing");

    // Version info
    m.attr("__version__") = "1.0.0";
}
