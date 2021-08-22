use curve25519_dalek::{edwards::EdwardsPoint as ed25519Point, scalar::Scalar as ed25519Scalar};

#[cfg(feature = "experimental")]
use ecdsa_fun::fun::{Point as secp256k1Point, Scalar as secp256k1Scalar};

use crate::consensus::CanonicalBytes;

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
        DLEQProof {
            xg_p: ed25519Point::default(),
            xh_p: secp256k1Point::random(&mut rand::thread_rng()),
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
