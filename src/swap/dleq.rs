use std::convert::TryInto;

use amplify::num::u256;

use bitcoin_hashes::{self, Hash};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint as ed25519Point,
    scalar::Scalar as ed25519Scalar, traits::Identity,
};

use rand::Rng;

fn _max_ed25519() -> u256 {
    let two = u256::from(2u32);
    (two << 252) + 27742317777372353535851937790883648493u128
}

// TODO: this is disgusting and must be removed asap
fn G_p() -> ed25519Point {
    monero::util::key::H.point.decompress().unwrap()
}

#[cfg(feature = "experimental")]
use ecdsa_fun::fun::{Point as secp256k1Point, Scalar as secp256k1Scalar, G as H};
#[cfg(feature = "experimental")]
use secp256kfun::{g, marker::*, s as sc};

fn _max_secp256k1() -> u256 {
    // let order_injected: [u8;32] = [
    //     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    //     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    //     0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    //     0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    //     ];

    // n = 2^256 − 432420386565659656852420866394968145599
    //   = 2^256 - 2^128 - 92138019644721193389046258963199934143
    //   = (2^256-1) - (2^128-1) - 92138019644721193389046258963199934143
    let mut n = u256::from_be_bytes([255u8; 32]);
    n -= u128::from_be_bytes([255u8; 16]);
    n -= 92138019644721193389046258963199934143u128;

    // assert_eq!(u256::from_be_bytes(order_injected), n);
    n
}

// Hash to curve of the generator G as explained over here:
// https://crypto.stackexchange.com/a/25603
// Matches the result here:
// https://github.com/mimblewimble/rust-secp256k1-zkp/blob/caa49992ae67f131157f6341f4e8b0b0c1e53055/src/constants.rs#L79-L136
// TODO: this is disgusting and must be removed asap (i.e. change to constant)
fn H_p() -> secp256k1Point {
    let hash_H: [u8; 32] =
        bitcoin_hashes::sha256::Hash::hash(&H.to_bytes_uncompressed()).into_inner();
    let even_y_prepend_hash_H: [u8; 33] = [2u8]
        .iter()
        .chain(hash_H.iter())
        .cloned()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    secp256k1Point::from_bytes(even_y_prepend_hash_H).expect("Alternate basepoint is invalid")
    // secp256k1Point::from_bytes([2, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192])
    // .expect("Alternate basepoint is invalid")
}

#[derive(Copy, Clone)]
struct PedersenCommitment<Point, Scalar> {
    commitment: Point,
    blinder: Scalar,
}

impl From<(bool, usize)> for PedersenCommitment<ed25519Point, ed25519Scalar> {
    fn from((bit, index): (bool, usize)) -> PedersenCommitment<ed25519Point, ed25519Scalar> {
        let mut csprng = rand_alt::rngs::OsRng;
        let blinder = ed25519Scalar::random(&mut csprng);

        let one: u256 = u256::from(1u32);
        let order = one << index;

        let commitment = match bit {
            false => blinder * G_p(),
            true => G * ed25519Scalar::from_bits(order.to_le_bytes()) + blinder * G_p(),
        };

        PedersenCommitment {
            commitment,
            blinder,
        }
    }
}

impl From<(bool, usize, ed25519Scalar)> for PedersenCommitment<ed25519Point, ed25519Scalar> {
    fn from(
        (bit, index, blinder): (bool, usize, ed25519Scalar),
    ) -> PedersenCommitment<ed25519Point, ed25519Scalar> {
        let one: u256 = u256::from(1u32);
        let order = one << index;

        let commitment = match bit {
            false => blinder * G_p(),
            true => G * ed25519Scalar::from_bits(order.to_le_bytes()) + blinder * G_p(),
        };

        PedersenCommitment {
            commitment,
            blinder,
        }
    }
}

impl From<(bool, usize)> for PedersenCommitment<secp256k1Point, secp256k1Scalar> {
    fn from((bit, index): (bool, usize)) -> PedersenCommitment<secp256k1Point, secp256k1Scalar> {
        let blinder = secp256k1Scalar::random(&mut rand::thread_rng());

        let one: u256 = u256::from(1u32);
        let order = one << index;

        let order_on_curve = secp256k1Scalar::from_bytes(order.to_le_bytes())
            .expect("integer greater than curve order");
        let H_p = H_p();
        let blinder_point = g!(blinder * H_p).mark::<NonZero>().unwrap();

        let commitment = match bit {
            true => g!(order_on_curve * H + blinder_point)
                .mark::<NonZero>()
                .unwrap(),
            false => blinder_point,
        }
        .mark::<Normal>();

        PedersenCommitment {
            commitment,
            blinder,
        }
    }
}

impl From<(bool, usize, secp256k1Scalar)> for PedersenCommitment<secp256k1Point, secp256k1Scalar> {
    fn from(
        (bit, index, blinder): (bool, usize, secp256k1Scalar),
    ) -> PedersenCommitment<secp256k1Point, secp256k1Scalar> {
        let one: u256 = u256::from(1u32);
        let order = one << index;

        let order_on_curve = secp256k1Scalar::from_bytes(order.to_le_bytes())
            .expect("integer greater than curve order");

        let H_p = H_p();
        let blinder_point = g!(blinder * H_p);

        let commitment = match bit {
            true => g!(order_on_curve * H + blinder_point)
                .mark::<NonZero>()
                .unwrap(),
            false => blinder_point,
        }
        .mark::<Normal>();

        PedersenCommitment {
            commitment,
            blinder,
        }
    }
}

fn key_commitment(
    x: [u8; 32],
    msb_index: usize,
) -> Vec<PedersenCommitment<ed25519Point, ed25519Scalar>> {
    let x_bits = bitvec::prelude::BitSlice::<bitvec::order::Lsb0, u8>::from_slice(&x).unwrap();
    let mut commitment: Vec<PedersenCommitment<ed25519Point, ed25519Scalar>> = x_bits
        .iter()
        .take(msb_index)
        .enumerate()
        .map(|(index, bit)| (*bit, index).into())
        .collect();
    let commitment_last = x_bits.get(msb_index).unwrap();
    let commitment_last_value = match *commitment_last {
        true => ed25519Scalar::one(),
        false => ed25519Scalar::zero(),
    };
    let blinder_last = commitment
        .iter()
        .fold(ed25519Scalar::zero(), |acc, x| acc - x.blinder);
    commitment.push((*commitment_last, msb_index, blinder_last).into());
    commitment
}

fn key_commitment_secp256k1(
    x: [u8; 32],
    msb_index: usize,
) -> Vec<PedersenCommitment<secp256k1Point, secp256k1Scalar>> {
    let x_bits = bitvec::prelude::BitSlice::<bitvec::order::Lsb0, u8>::from_slice(&x).unwrap();
    let mut commitment: Vec<PedersenCommitment<secp256k1Point, secp256k1Scalar>> = x_bits
        .iter()
        .take(msb_index)
        .enumerate()
        .map(|(index, bit)| (*bit, index).into())
        .collect();
    let commitment_last = x_bits.get(msb_index).unwrap();
    let commitment_last_value = match *commitment_last {
        true => secp256k1Scalar::one().mark::<Zero>(),
        false => secp256k1Scalar::zero(),
    };
    let blinder_last = commitment
        .iter()
        .fold(secp256k1Scalar::zero(), |acc, x| sc!(acc - x.blinder));
    commitment.push(
        (
            *commitment_last,
            msb_index,
            blinder_last.mark::<NonZero>().expect("is zero"),
        )
            .into(),
    );
    commitment
}

struct RingSignature<ScalarCurveA, ScalarCurveB> {
    e_g_0_i: ScalarCurveA,
    e_h_0_i: ScalarCurveB,
    a_0_i: ScalarCurveA,
    b_0_i: ScalarCurveB,
    a_1_i: ScalarCurveA,
    b_1_i: ScalarCurveB,
}

fn ring_hash(term0: [u8; 32], term1: [u8; 33], term2: [u8; 32], term3: [u8; 33]) -> [u8; 32] {
    let preimage: [u8; 130] = term0
        .iter()
        .chain(term1.iter())
        .chain(term2.iter())
        .chain(term3.iter())
        .cloned()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    bitcoin_hashes::sha256::Hash::hash(&preimage).into_inner()
}

impl
    From<(
        bool,
        PedersenCommitment<ed25519Point, ed25519Scalar>,
        PedersenCommitment<secp256k1Point, secp256k1Scalar>,
    )> for RingSignature<ed25519Scalar, secp256k1Scalar>
{
    fn from(
        (b_i, c_g_i, c_h_i): (
            bool,
            PedersenCommitment<ed25519Point, ed25519Scalar>,
            PedersenCommitment<secp256k1Point, secp256k1Scalar>,
        ),
    ) -> Self {
        let term0: [u8; 32] = c_g_i.commitment.compress().as_bytes().clone();
        let term1: [u8; 33] = c_h_i.commitment.to_bytes();

        let mut csprng = rand_alt::rngs::OsRng;
        let j_i = ed25519Scalar::random(&mut csprng);
        let k_i = secp256k1Scalar::random(&mut rand::thread_rng());

        let term2 = (j_i * G).compress().as_bytes().clone();
        let term3 = g!(k_i * H).mark::<Normal>().to_bytes();

        let (e_g_0_i, e_h_0_i, a_0_i, a_1_i, b_0_i, b_1_i) = if b_i {
            let e_0_i = ring_hash(term0, term1, term2, term3);
            let e_g_0_i = ed25519Scalar::from_bytes_mod_order(e_0_i);
            let e_h_0_i = secp256k1Scalar::from_bytes_mod_order(e_0_i)
                .mark::<NonZero>()
                .expect("is zero");

            let a_1_i = ed25519Scalar::random(&mut csprng);
            let b_1_i = secp256k1Scalar::random(&mut rand::thread_rng());

            let term2 = (a_1_i * G - e_g_0_i * c_g_i.commitment)
                .compress()
                .as_bytes()
                .clone();
            let term3 = g!(b_1_i * H - e_h_0_i * c_h_i.commitment)
                .mark::<Normal>()
                .mark::<NonZero>()
                .expect("is zero")
                .to_bytes();

            let e_1_i = ring_hash(term0, term1, term2, term3);
            let e_g_1_i = ed25519Scalar::from_bytes_mod_order(e_1_i);
            let e_h_1_i = secp256k1Scalar::from_bytes_mod_order(e_1_i);

            let a_0_i = j_i + e_g_1_i * c_g_i.blinder;

            let b_0_i = sc!(k_i + e_h_1_i * c_h_i.blinder)
                .mark::<NonZero>()
                .unwrap();
            (e_g_0_i, e_h_0_i, a_0_i, a_1_i, b_0_i, b_1_i)
        } else {
            let e_1_i = ring_hash(term0, term1, term2, term3);
            let e_g_1_i = ed25519Scalar::from_bytes_mod_order(e_1_i);
            let e_h_1_i = secp256k1Scalar::from_bytes_mod_order(e_1_i);

            let a_0_i = ed25519Scalar::random(&mut csprng);
            let b_0_i = secp256k1Scalar::random(&mut rand::thread_rng());

            let term2 = (a_0_i * G - e_g_1_i * (c_g_i.commitment - G_p()))
                .compress()
                .as_bytes()
                .clone();
            let term3 = g!(b_0_i * H - e_h_1_i * c_h_i.commitment)
                .mark::<Normal>()
                .mark::<NonZero>()
                .expect("is zero")
                .to_bytes();

            let e_0_i = ring_hash(term0, term1, term2, term3);
            let e_g_0_i = ed25519Scalar::from_bytes_mod_order(e_0_i);
            let e_h_0_i = secp256k1Scalar::from_bytes_mod_order(e_0_i)
                .mark::<NonZero>()
                .expect("is zero");

            let a_1_i = j_i + e_g_0_i * c_g_i.blinder;

            let b_1_i = sc!(k_i + e_h_0_i * c_h_i.blinder)
                .mark::<NonZero>()
                .expect("is zero");
            (e_g_0_i, e_h_0_i, a_0_i, a_1_i, b_0_i, b_1_i)
        };

        RingSignature {
            e_g_0_i,
            e_h_0_i,
            a_0_i,
            b_0_i,
            a_1_i,
            b_1_i,
        }
    }
}

struct DLEQProof {
    xg_p: ed25519Point,
    xh_p: secp256k1Point,
    c_g: Vec<PedersenCommitment<ed25519Point, ed25519Scalar>>,
    c_h: Vec<PedersenCommitment<secp256k1Point, secp256k1Scalar>>,
    ring_signatures: Vec<RingSignature<ed25519Scalar, secp256k1Scalar>>
}

fn zeroize_highest_bits(x: [u8; 32], highest_bit: usize) -> [u8; 32] {
    let mut x = x;
    let remainder = highest_bit % 8;
    let quotient = (highest_bit - remainder) / 8;

    for index in quotient..=31 {
        x[index] = 0;
    }

    if (remainder != 0) {
        let mask = (2 << (remainder - 1)) - 1;
        x[quotient-1] &= mask;
    }                       

    x
}

impl DLEQProof {
    fn generate(x: [u8; 32]) -> Self {
        let highest_bit = 252;

        let x_shaved = zeroize_highest_bits(x, highest_bit);
        let x_bits =
            bitvec::prelude::BitSlice::<bitvec::order::Lsb0, u8>::from_slice(&x_shaved).unwrap();

        let x_ed25519 = ed25519Scalar::from_bytes_mod_order(x_shaved);
        let xg_p = x_ed25519 * G;

        // TODO: do properly
        let mut x_secp256k1: secp256k1Scalar<_> = secp256k1Scalar::from_bytes(x_shaved)
            .unwrap()
            .mark::<NonZero>()
            .expect("x is zero");
        let xh_p = secp256k1Point::from_scalar_mul(H, &mut x_secp256k1).mark::<Normal>();

        let c_g = key_commitment(x_shaved, highest_bit);
        let c_h = key_commitment_secp256k1(x_shaved, highest_bit);

        let ring_signatures: Vec<RingSignature<ed25519Scalar, secp256k1Scalar>> = x_bits
            .iter()
            .take(highest_bit)
            .zip(c_g.clone())
            .zip(c_h.clone())
            .map(|((b_i, c_g_i), c_h_i)| RingSignature::from((*b_i, c_g_i, c_h_i)))
            .collect();

        DLEQProof {
            xg_p,
            xh_p,
            c_g,
            c_h,
            ring_signatures,
        }
    }
}

#[test]
fn pedersen_commitment_works() {
    let mut x: [u8; 32] = rand::thread_rng().gen();
    // ensure 256th bit is 0
    x[31] &= 0b0111_1111;
    let key_commitment = key_commitment(x, 255);
    let commitment_acc = key_commitment
        .iter()
        .fold(ed25519Point::identity(), |acc, bit_commitment| {
            acc + bit_commitment.commitment
        });
    assert_eq!(ed25519Scalar::from_bytes_mod_order(x) * G, commitment_acc);
}

#[test]
fn pedersen_commitment_sec256k1_works() {
    let x: [u8; 32] = rand::thread_rng().gen();
    // let mut x: [u8; 32] = rand::thread_rng().gen();
    // ensure 256th bit is 0
    // x[31] &= 0b0111_1111;
    let key_commitment = key_commitment_secp256k1(x, 255);
    // let commitment_acc: secp256k1Point<Jacobian, Public, Zero> = key_commitment
    let commitment_acc = key_commitment.iter().fold(
        secp256k1Point::zero(),
        |acc, bit_commitment| g!(acc + bit_commitment.commitment).mark::<Normal>(), // .fold(secp256k1Point::zero().mark::<Jacobian>(), |acc, bit_commitment| g!(acc + bit_commitment.commitment)
    );
    let x_secp256k1 = secp256k1Scalar::from_bytes_mod_order(x);
    // let H_p = H_p();
    assert_eq!(g!(x_secp256k1 * H), commitment_acc);
}

#[test]
fn blinders_sum_to_zero() {
    let x: [u8; 32] = rand::thread_rng().gen();
    let key_commitment = key_commitment(x, 255);
    let blinder_acc = key_commitment
        .iter()
        .fold(ed25519Scalar::zero(), |acc, bit_commitment| {
            acc + bit_commitment.blinder
        });
    assert_eq!(blinder_acc, ed25519Scalar::zero());
}

#[test]
fn ring_signature() {
    let mut csprng = rand_alt::rngs::OsRng;
    RingSignature::from((
        false,
        PedersenCommitment {
            commitment: ed25519Scalar::random(&mut csprng) * G,
            blinder: ed25519Scalar::random(&mut csprng),
        },
        PedersenCommitment {
            commitment: secp256k1Point::random(&mut rand::thread_rng()),
            blinder: secp256k1Scalar::random(&mut rand::thread_rng()),
        },
    ));
}
