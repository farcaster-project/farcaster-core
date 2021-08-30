use amplify::num::u256;
use bitvec::prelude::*;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint as ed25519Point,
    scalar::Scalar as ed25519Scalar,
    traits::Identity,
};

use rand::Rng;

// this is disgusting and must be removed asap
fn G_p() -> ed25519Point {
    monero::util::key::H.point.decompress().unwrap()
    }

#[cfg(feature = "experimental")]
use ecdsa_fun::fun::{Point as secp256k1Point, Scalar as secp256k1Scalar, G as H};
#[cfg(feature = "experimental")]
use secp256kfun::marker::*;

struct PedersenCommitment<Point, Scalar> {
    commitment: Point,
    blinder: Scalar,
}

// temporary implementations - we don't ultimately want these default values
// impl Default for PedersenCommitment<ed25519Point, ed25519Scalar> {
//     fn default() -> Self {
//         PedersenCommitment {
//             commitment: ed25519Point::default(),
//             blinder: ed25519Scalar::default(),
//         }
//     }
// }

impl Default for PedersenCommitment<secp256k1Point, secp256k1Scalar> {
    fn default() -> Self {
        PedersenCommitment {
            commitment: secp256k1Point::random(&mut rand::thread_rng()),
            blinder: secp256k1Scalar::random(&mut rand::thread_rng()),
        }
    }
}

impl From<(bool, usize)> for PedersenCommitment<ed25519Point, ed25519Scalar> {
    fn from((bit, index): (bool, usize)) -> PedersenCommitment<ed25519Point, ed25519Scalar> {
        let mut csprng = rand_alt::rngs::OsRng;
        let blinder = ed25519Scalar::random(&mut csprng);

        let one: u256 = u256::from(1u32);
        let order = one << index;

        let commitment = match bit {
            false => blinder * G,
            true => G_p() * ed25519Scalar::from_bits(order.to_le_bytes()) + blinder * G,
        };

        PedersenCommitment {
            commitment,
            blinder,
            }
    }
}

impl From<(bool, ed25519Scalar)> for PedersenCommitment<ed25519Point, ed25519Scalar> {
    fn from((bit, blinder): (bool, ed25519Scalar)) -> PedersenCommitment<ed25519Point, ed25519Scalar> {

        let commitment = match bit {
            false => blinder * G,
            true => G_p() + blinder * G,
        };

        PedersenCommitment {
            commitment,
            blinder,
        }
    }
}

fn key_commitment(x: [u8; 32]) -> Vec<PedersenCommitment<ed25519Point, ed25519Scalar>> {
    let x_bits = bitvec::prelude::BitSlice::<bitvec::order::Lsb0, u8>::from_slice(&x).unwrap();
    let mut commitment: Vec<PedersenCommitment<ed25519Point, ed25519Scalar>> = x_bits.iter().take(x_bits.len() - 1).enumerate().map(|(index, bit)| (*bit, index).into()).collect();
    let commitment_last = 
        x_bits.get(x_bits.len() - 1).unwrap();
    let commitment_last_value = match *commitment_last {
        true => ed25519Scalar::one(),
        false => ed25519Scalar::zero(),
    };
    let blinder_last = commitment.iter().fold(ed25519Scalar::zero(), |acc, x| acc - x.blinder);
    commitment.push((*commitment_last, blinder_last).into());
    commitment
}

struct DLEQProof {
    xg_p: ed25519Point,
    xh_p: secp256k1Point,
    c_g: Vec<PedersenCommitment<ed25519Point, ed25519Scalar>>,
    c_h: Vec<PedersenCommitment<secp256k1Point, secp256k1Scalar>>,
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
        let x_ed25519 = ed25519Scalar::from_bytes_mod_order(x);
        let xg_p = x_ed25519 * G_p();

        // TODO: do properly
        let mut x_secp256k1: secp256k1Scalar<_> = secp256k1Scalar::from_bytes(x)
            .unwrap()
            .mark::<NonZero>()
            .expect("x is zero");
        let xh_p = secp256k1Point::from_scalar_mul(H, &mut x_secp256k1).mark::<Normal>();


        DLEQProof {
            xg_p,
            xh_p,
            c_g: key_commitment(x),
            c_h: vec![PedersenCommitment::<secp256k1Point, secp256k1Scalar>::default()],
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

#[test]
fn pedersen_commitment_works() {
    let x: [u8; 32] = rand::thread_rng().gen();
    let key_commitment = key_commitment(x);
    let commitment_acc = key_commitment.iter().fold(ed25519Point::identity(), |acc, bit_commitment| acc + bit_commitment.commitment);
    assert_eq!(ed25519Scalar::from_bytes_mod_order(x) * G_p(), commitment_acc);
}

#[test]
fn blinders_sum_to_zero() {
    let x: [u8; 32] = rand::thread_rng().gen();
    let key_commitment = key_commitment(x);
    let blinder_acc = key_commitment.iter().fold(ed25519Scalar::zero(), |acc, bit_commitment| acc + bit_commitment.blinder);
    assert_eq!(blinder_acc, ed25519Scalar::zero());
}
