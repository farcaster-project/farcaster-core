use curve25519_dalek;

#[cfg(feature = "experimental")]
use ecdsa_fun;

struct DLEQProof {
    xg_p: curve25519_dalek::edwards::EdwardsPoint,
    xh_p: ecdsa_fun::fun::Point,
    c_g: Vec<curve25519_dalek::edwards::EdwardsPoint>,
    c_h: Vec<ecdsa_fun::fun::Point>,
    e_g_0: curve25519_dalek::scalar::Scalar,
    e_h_0: ecdsa_fun::fun::Scalar,
    e_g_1: curve25519_dalek::scalar::Scalar,
    e_h_1: ecdsa_fun::fun::Scalar,
    a_0: curve25519_dalek::scalar::Scalar,
    a_1: ecdsa_fun::fun::Scalar,
    b_0: curve25519_dalek::scalar::Scalar,
    b_1: ecdsa_fun::fun::Scalar,
}
