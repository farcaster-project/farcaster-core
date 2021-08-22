use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::EdwardsPoint as ed25519Point,
    scalar::Scalar as ed25519Scalar,
};

#[cfg(feature = "experimental")]
use ecdsa_fun::fun::{Point as secp256k1Point, Scalar as secp256k1Scalar, G};
#[cfg(feature = "experimental")]
use secp256kfun::marker::*;

struct DLEQProof {
    xg_p: ed25519Point,
    xh_p: secp256k1Point,
    c_g: Vec<ed25519Point>,
    c_h: Vec<secp256k1Point>,
    e_g_0: Vec<ed25519Scalar>,
    e_h_0: Vec<secp256k1Scalar>,
    e_g_1: Vec<ed25519Scalar>,
    e_h_1: Vec<secp256k1Scalar>,
    a_0: Vec<ed25519Scalar>,
    a_1: Vec<secp256k1Scalar>,
    b_0: Vec<ed25519Scalar>,
    b_1: Vec<secp256k1Scalar>,
}

impl DLEQProof {
    fn generate(x: [u8; 32]) -> Self {
        let x_ed25519 = ed25519Scalar::from_bits(x);
        let xg_p = x_ed25519 * ED25519_BASEPOINT_POINT;

        // TODO: do properly
        let mut x_secp256k1: secp256k1Scalar<_> = secp256k1Scalar::from_bytes(x)
            .unwrap()
            .mark::<NonZero>()
            .expect("x is zero");
        let xh_p = secp256k1Point::from_scalar_mul(G, &mut x_secp256k1).mark::<Normal>();

        DLEQProof {
            xg_p,
            xh_p,
            c_g: vec![ed25519Point::default()],
            c_h: vec![secp256k1Point::random(&mut rand::thread_rng())],
            e_g_0: vec![ed25519Scalar::default()],
            e_h_0: vec![secp256k1Scalar::random(&mut rand::thread_rng())],
            e_g_1: vec![ed25519Scalar::default()],
            e_h_1: vec![secp256k1Scalar::random(&mut rand::thread_rng())],
            a_0: vec![ed25519Scalar::default()],
            a_1: vec![secp256k1Scalar::random(&mut rand::thread_rng())],
            b_0: vec![ed25519Scalar::default()],
            b_1: vec![secp256k1Scalar::random(&mut rand::thread_rng())],
        }
    }
}
