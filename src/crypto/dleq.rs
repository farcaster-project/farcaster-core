use std::convert::TryInto;

use crate::{
    consensus::{self, deserialize, serialize, CanonicalBytes, Decodable, Encodable},
    crypto,
};
use amplify::num::u256;

use bitcoin_hashes::{self, Hash};

use bitvec::{order::Lsb0, prelude::BitSlice};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::CompressedEdwardsY as ed25519PointCompressed,
    edwards::EdwardsPoint as ed25519Point, scalar::Scalar as ed25519Scalar,
};

const ENTROPY: bool = true;

fn _max_ed25519() -> u256 {
    (u256::from(1u32) << 252) + 27742317777372353535851937790883648493u128
}

fn reverse_endianness(bytes: &[u8; 32]) -> [u8; 32] {
    let mut bytes_rev = *bytes;
    bytes_rev.reverse();
    bytes_rev
}

// matches https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
// i.e. hash-to-curve of G as in https://github.com/monero-project/mininero/blob/master/mininero.py#L305-L323
// TODO: this is disgusting and must be removed asap
#[allow(non_snake_case)]
fn G_p() -> ed25519Point {
    let hash_G = monero::cryptonote::hash::keccak_256(G.compress().as_bytes());

    ed25519PointCompressed::from_slice(&hash_G)
        .decompress()
        .unwrap()
        .mul_by_cofactor() // should be in basepoint's subgroup, i.e. 8 * toPoint(hash_G)
}

#[cfg(feature = "experimental")]
use ecdsa_fun::fun::{Point as secp256k1Point, Scalar as secp256k1Scalar, G as H};
#[cfg(feature = "experimental")]
use secp256kfun::{g, marker::*, s as sc};
use sha2::Digest;

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
#[allow(non_snake_case)]
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

#[derive(Copy, Clone, Debug)]
struct PedersenCommitment<Point, Scalar> {
    commitment: Point,
    blinder: Scalar,
}

impl From<(bool, usize)> for PedersenCommitment<ed25519Point, ed25519Scalar> {
    fn from((bit, index): (bool, usize)) -> PedersenCommitment<ed25519Point, ed25519Scalar> {
        // let mut csprng = rand_alt::rngs::OsRng;
        // let blinder = ed25519Scalar::random(&mut csprng);
        let blinder = match ENTROPY {
            true => ed25519Scalar::random(&mut rand_alt::rngs::OsRng),
            false => ed25519Scalar::zero(),
        };

        let order = u256::from(1u32) << index;

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
        let order = u256::from(1u32) << index;

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
        // let blinder = secp256k1Scalar::random(&mut rand::thread_rng());
        let blinder = match ENTROPY {
            true => secp256k1Scalar::random(&mut rand::thread_rng()),
            false => secp256k1Scalar::one(),
        };

        let order = u256::from(1u32) << index;

        let order_on_curve = secp256k1Scalar::from_bytes(order.to_be_bytes())
            .expect("integer greater than curve order");
        #[allow(non_snake_case)]
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
        let order = u256::from(1u32) << index;

        let order_on_curve = secp256k1Scalar::from_bytes(order.to_be_bytes())
            .expect("integer greater than curve order");

        #[allow(non_snake_case)]
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
    x_bits: &BitSlice<Lsb0, u8>,
    msb_index: usize,
) -> Vec<PedersenCommitment<ed25519Point, ed25519Scalar>> {
    let mut commitment: Vec<PedersenCommitment<ed25519Point, ed25519Scalar>> = x_bits
        .iter()
        .take(msb_index)
        .enumerate()
        .map(|(index, bit)| (*bit, index).into())
        .collect();
    let commitment_last = x_bits.get(msb_index).unwrap();
    let _commitment_last_value = match *commitment_last {
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
    x_bits: &BitSlice<Lsb0, u8>,
    msb_index: usize,
) -> Vec<PedersenCommitment<secp256k1Point, secp256k1Scalar>> {
    let mut commitment: Vec<PedersenCommitment<secp256k1Point, secp256k1Scalar>> = x_bits
        .iter()
        .take(msb_index)
        .enumerate()
        .map(|(index, bit)| (*bit, index).into())
        .collect();
    let commitment_last = x_bits.get(msb_index).unwrap();
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

#[derive(Clone, Debug, PartialEq)]
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

fn verify_ring_sig(
    index: usize,
    c_g_i: ed25519Point,
    c_h_i: secp256k1Point,
    ring_sig: RingSignature<ed25519Scalar, secp256k1Scalar>,
) -> bool {
    let term0: [u8; 32] = *c_g_i.compress().as_bytes();
    let term1: [u8; 33] = c_h_i.to_bytes();

    let order = u256::from(1u32) << index;
    let order_on_secp256k1 =
        secp256k1Scalar::from_bytes(order.to_be_bytes()).expect("integer greater than curve order");
    #[allow(non_snake_case)]
    let H_p = H_p();

    // compute e_1_i
    let e_1_i = {
        let term2: [u8; 32] = *(ring_sig.a_1_i * G_p() - ring_sig.e_g_0_i * c_g_i)
            .compress()
            .as_bytes();

        let term3: [u8; 33] = g!(ring_sig.b_1_i * H_p - ring_sig.e_h_0_i * c_h_i)
            .mark::<Normal>()
            .mark::<NonZero>()
            .expect("is zero")
            .to_bytes();

        ring_hash(term0, term1, term2, term3)
    };
    let e_g_1_i = ed25519Scalar::from_bytes_mod_order(e_1_i);
    let e_h_1_i = secp256k1Scalar::from_bytes_mod_order(e_1_i);

    // compute e_0_i
    let e_0_i = {
        let term2: [u8; 32] = *(ring_sig.a_0_i * G_p()
            - e_g_1_i * (c_g_i - ed25519Scalar::from_bytes_mod_order(order.to_le_bytes()) * G))
            .compress()
            .as_bytes();

        let term3: [u8; 33] = g!(ring_sig.b_0_i * H_p - e_h_1_i * (c_h_i - order_on_secp256k1 * H))
            .mark::<Normal>()
            .mark::<NonZero>()
            .expect("is zero")
            .to_bytes();

        ring_hash(term0, term1, term2, term3)
    };

    let e_g_0_i = ed25519Scalar::from_bytes_mod_order(e_0_i);
    let e_h_0_i = secp256k1Scalar::from_bytes_mod_order(e_0_i);

    // compare computed results with provided values
    (e_g_0_i == ring_sig.e_g_0_i) && (e_h_0_i == ring_sig.e_h_0_i)
}

impl
    From<(
        usize,
        bool,
        PedersenCommitment<ed25519Point, ed25519Scalar>,
        PedersenCommitment<secp256k1Point, secp256k1Scalar>,
    )> for RingSignature<ed25519Scalar, secp256k1Scalar>
{
    fn from(
        (index, b_i, c_g_i, c_h_i): (
            usize,
            bool,
            PedersenCommitment<ed25519Point, ed25519Scalar>,
            PedersenCommitment<secp256k1Point, secp256k1Scalar>,
        ),
    ) -> Self {
        // first confirm that the pedersen commitments are correctly calculated
        assert_eq!(
            c_g_i.commitment,
            PedersenCommitment::from((b_i, index, c_g_i.blinder)).commitment,
            "incorrect pedersen commitment!"
        );
        assert_eq!(
            c_h_i.commitment,
            PedersenCommitment::from((b_i, index, c_h_i.blinder.clone())).commitment,
            "incorrect pedersen commitment!"
        );
        let term0: [u8; 32] = *c_g_i.commitment.compress().as_bytes();
        let term1: [u8; 33] = c_h_i.commitment.to_bytes();

        // let j_i = ed25519Scalar::random(&mut csprng);
        // let k_i = secp256k1Scalar::random(&mut rand::thread_rng());
        let j_i = match ENTROPY {
            true => ed25519Scalar::random(&mut rand_alt::rngs::OsRng),
            false => ed25519Scalar::zero(),
        };
        let k_i = match ENTROPY {
            true => secp256k1Scalar::random(&mut rand::thread_rng()),
            false => secp256k1Scalar::one(),
        };

        #[allow(non_snake_case)]
        let H_p = H_p();

        let term2_generated = *(j_i * G_p()).compress().as_bytes();
        let term3_generated = g!(k_i * H_p).mark::<Normal>().to_bytes();

        // clippy insists it's better to avoid reuse like this ¯\_(ツ)_/¯
        let e_0_i = ring_hash(term0, term1, term2_generated, term3_generated);
        let e_g_0_i = ed25519Scalar::from_bytes_mod_order(e_0_i);

        let (e_g_0_i, e_h_0_i, a_0_i, a_1_i, b_0_i, b_1_i) = if b_i {
            let e_h_0_i = secp256k1Scalar::from_bytes_mod_order(e_0_i)
                .mark::<NonZero>()
                .expect("is zero");

            // let a_1_i = ed25519Scalar::random(&mut csprng);
            // let b_1_i = secp256k1Scalar::random(&mut rand::thread_rng());
            let a_1_i = match ENTROPY {
                true => ed25519Scalar::random(&mut rand_alt::rngs::OsRng),
                false => ed25519Scalar::zero(),
            };
            let b_1_i = match ENTROPY {
                true => secp256k1Scalar::random(&mut rand::thread_rng()),
                false => secp256k1Scalar::one(),
            };

            let term2 = *(a_1_i * G_p() - e_g_0_i * c_g_i.commitment)
                .compress()
                .as_bytes();
            let term3 = g!(b_1_i * H_p - e_h_0_i * c_h_i.commitment)
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

            let order = u256::from(1u32) << index;
            let order_on_secp256k1 = secp256k1Scalar::from_bytes(order.to_be_bytes())
                .expect("integer greater than curve order");

            let term2_calculated: [u8; 32] = *(a_0_i * G_p()
                - e_g_1_i * (c_g_i.commitment - ed25519Scalar::from_bits(order.to_le_bytes()) * G))
                .compress()
                .as_bytes();

            let term3_calculated: [u8; 33] =
                g!(b_0_i * H_p - e_h_1_i * (c_h_i.commitment - order_on_secp256k1 * H))
                    .mark::<Normal>()
                    .mark::<NonZero>()
                    .expect("is zero")
                    .to_bytes();

            assert_eq!(
                term2_calculated, term2_generated,
                "term2 bit=1 should match"
            );
            assert_eq!(
                term3_calculated, term3_generated,
                "term3 bit=1 should match"
            );

            let e_0_p = ring_hash(term0, term1, term2_calculated, term3_calculated);
            assert_eq!(e_0_i, e_0_p, "ring hash bit=1 should match");

            (e_g_0_i, e_h_0_i, a_0_i, a_1_i, b_0_i, b_1_i)
        } else {
            let e_1_i = e_0_i;
            let e_g_1_i = e_g_0_i;
            let e_h_1_i = secp256k1Scalar::from_bytes_mod_order(e_1_i);

            // let a_0_i = ed25519Scalar::random(&mut csprng);
            // let b_0_i = secp256k1Scalar::random(&mut rand::thread_rng());
            let a_0_i = match ENTROPY {
                true => ed25519Scalar::random(&mut rand_alt::rngs::OsRng),
                false => ed25519Scalar::zero(),
            };
            let b_0_i = match ENTROPY {
                true => secp256k1Scalar::random(&mut rand::thread_rng()),
                false => secp256k1Scalar::one(),
            };

            let order = u256::from(1u32) << index;
            let order_on_secp256k1 = secp256k1Scalar::from_bytes(order.to_be_bytes())
                .expect("integer greater than curve order");

            let term2 = *(a_0_i * G_p()
                - e_g_1_i
                    * (c_g_i.commitment
                        - ed25519Scalar::from_bytes_mod_order(order.to_le_bytes()) * G))
                .compress()
                .as_bytes();
            let term3 = g!(b_0_i * H_p - e_h_1_i * (c_h_i.commitment - order_on_secp256k1 * H))
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

            // verification
            let term2_calculated: [u8; 32] = *(a_1_i * G_p() - e_g_0_i * c_g_i.commitment)
                .compress()
                .as_bytes();

            let term3_calculated: [u8; 33] = g!(b_1_i * H_p - e_h_0_i * c_h_i.commitment)
                .mark::<Normal>()
                .mark::<NonZero>()
                .expect("is zero")
                .to_bytes();

            assert_eq!(
                term2_calculated, term2_generated,
                "term2 bit=0 should match"
            );
            assert_eq!(
                term3_calculated, term3_generated,
                "term3 bit=0 should match"
            );

            let e_1_p = ring_hash(term0, term1, term2_calculated, term3_calculated);
            assert_eq!(e_1_i, e_1_p, "ring hash bit=0 should match");

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

#[derive(Clone, Debug, PartialEq)]
#[allow(non_snake_case)]
pub struct DLEQProof {
    pub(crate) xG_p: ed25519Point,
    pub(crate) xH_p: secp256k1Point,
    c_g: Vec<ed25519Point>,
    c_h: Vec<secp256k1Point>,
    ring_signatures: Vec<RingSignature<ed25519Scalar, secp256k1Scalar>>,
    pok_0: (ed25519Point, ed25519Scalar),
    pok_1: ecdsa_fun::Signature,
}

impl Encodable for ed25519Point {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.compress().to_bytes().consensus_encode(writer)
    }
}

impl Decodable for ed25519Point {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(ed25519PointCompressed::from_slice(&bytes)
            .decompress()
            .unwrap())
    }
}

impl Encodable for secp256k1Point {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for secp256k1Point {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 33] = Decodable::consensus_decode(d)?;
        Ok(secp256k1Point::from_bytes(bytes).unwrap())
    }
}

impl Encodable for ed25519Scalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for ed25519Scalar {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(ed25519Scalar::from_bytes_mod_order(bytes))
    }
}

impl Encodable for secp256k1Scalar {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for secp256k1Scalar {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(secp256k1Scalar::from_bytes_mod_order(bytes)
            .mark::<NonZero>()
            .unwrap())
    }
}

impl Encodable for (ed25519Point, ed25519Scalar) {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        Ok(self.0.consensus_encode(writer)? + self.1.consensus_encode(writer)?)
    }
}

impl Decodable for (ed25519Point, ed25519Scalar) {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok((
            Decodable::consensus_decode(d)?,
            Decodable::consensus_decode(d)?,
        ))
    }
}

impl Encodable for ecdsa_fun::Signature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for ecdsa_fun::Signature {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 64] = Decodable::consensus_decode(d)?;
        Ok(ecdsa_fun::Signature::from_bytes(bytes).unwrap())
    }
}

impl Encodable for RingSignature<ed25519Scalar, secp256k1Scalar> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0usize;
        len += self.e_g_0_i.consensus_encode(writer)?;
        len += self.e_h_0_i.consensus_encode(writer)?;
        len += self.a_0_i.consensus_encode(writer)?;
        len += self.b_0_i.consensus_encode(writer)?;
        len += self.a_1_i.consensus_encode(writer)?;
        len += self.b_1_i.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for RingSignature<ed25519Scalar, secp256k1Scalar> {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let e_g_0_i = Decodable::consensus_decode(d)?;
        let e_h_0_i = Decodable::consensus_decode(d)?;
        let a_0_i = Decodable::consensus_decode(d)?;
        let b_0_i = Decodable::consensus_decode(d)?;
        let a_1_i = Decodable::consensus_decode(d)?;
        let b_1_i = Decodable::consensus_decode(d)?;
        Ok(RingSignature {
            e_g_0_i,
            e_h_0_i,
            a_0_i,
            b_0_i,
            a_1_i,
            b_1_i,
        })
    }
}

impl Encodable for DLEQProof {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0usize;
        len += self.xG_p.consensus_encode(writer)?;
        len += self.xH_p.consensus_encode(writer)?;
        len += self.c_g.consensus_encode(writer)?;
        len += self.c_h.consensus_encode(writer)?;
        len += self.ring_signatures.consensus_encode(writer)?;
        len += self.pok_0.consensus_encode(writer)?;
        len += self.pok_1.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for DLEQProof {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        #[allow(non_snake_case)]
        let xG_p = Decodable::consensus_decode(d)?;
        #[allow(non_snake_case)]
        let xH_p = Decodable::consensus_decode(d)?;
        let c_g = Decodable::consensus_decode(d)?;
        let c_h = Decodable::consensus_decode(d)?;
        let ring_signatures = Decodable::consensus_decode(d)?;
        let pok_0 = Decodable::consensus_decode(d)?;
        let pok_1 = Decodable::consensus_decode(d)?;

        Ok(DLEQProof {
            xG_p,
            xH_p,
            c_g,
            c_h,
            ring_signatures,
            pok_0,
            pok_1,
        })
    }
}

impl CanonicalBytes for DLEQProof {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        serialize(self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<DLEQProof, consensus::Error>
    where
        Self: Sized,
    {
        deserialize(bytes)
    }
}

fn _zeroize_highest_bits(x: [u8; 32], highest_bit: usize) -> [u8; 32] {
    let mut x = x;
    let remainder = highest_bit % 8;
    let quotient = (highest_bit - remainder) / 8;

    for bit in x.iter_mut().skip(quotient + 1) {
        *bit = 0;
    }

    if remainder != 0 {
        let mask = (2 << (remainder - 1)) - 1;
        x[quotient] &= mask;
    }

    x
}

impl DLEQProof {
    pub(crate) fn generate(x: [u8; 32]) -> Self {
        // convention: start count at 0
        let msb_index = 251;

        let x_bits = BitSlice::<Lsb0, u8>::from_slice(&x).unwrap();

        assert!(x_bits[msb_index + 1..].iter().all(|bit| !(*bit)));

        let x_ed25519 = ed25519Scalar::from_bytes_mod_order(x);
        #[allow(non_snake_case)]
        let xG_p = x_ed25519 * G;

        // TODO: do properly
        let x_secp256k1: secp256k1Scalar<_> =
            secp256k1Scalar::from_bytes_mod_order(reverse_endianness(&x))
                .mark::<NonZero>()
                .expect("x is zero");
        #[allow(non_snake_case)]
        let xH_p = g!(x_secp256k1 * H).mark::<Normal>();

        let c_g = key_commitment(x_bits, msb_index);
        let c_h = key_commitment_secp256k1(x_bits, msb_index);

        let ring_signatures: Vec<RingSignature<ed25519Scalar, secp256k1Scalar>> = x_bits
            .iter()
            .take(msb_index + 1)
            .enumerate()
            .zip(c_g.clone())
            .zip(c_h.clone())
            .map(|(((index, b_i), c_g_i), c_h_i)| RingSignature::from((index, *b_i, c_g_i, c_h_i)))
            .collect();

        let c_g: Vec<ed25519Point> = c_g.iter().map(|pc| pc.commitment).collect();
        let c_h: Vec<secp256k1Point> = c_h.iter().map(|pc| pc.commitment).collect();

        //Proof of Knowledge ed25519 (edDSA)
        let hash_x = monero::cryptonote::hash::keccak_256(x_ed25519.as_bytes());
        let pok_0_message = serialize(&c_g);

        let mut alpha_preimage = vec![];
        alpha_preimage.extend_from_slice(&hash_x);
        alpha_preimage.extend_from_slice(&pok_0_message);

        let alpha = ed25519Scalar::from_bytes_mod_order(monero::cryptonote::hash::keccak_256(
            &alpha_preimage,
        ));
        #[allow(non_snake_case)]
        let alpha_G = alpha * G;

        let mut challenge_preimage = vec![];
        challenge_preimage.extend_from_slice(alpha_G.compress().as_bytes());
        challenge_preimage.extend_from_slice(xG_p.compress().as_bytes());
        challenge_preimage.extend_from_slice(&pok_0_message);
        let challenge = ed25519Scalar::from_bytes_mod_order(monero::cryptonote::hash::keccak_256(
            &challenge_preimage,
        ));

        let response = alpha + challenge * x_ed25519;

        let pok_0 = (alpha_G, response);

        // Proof of Knowledge secp256k1 (ECDSA)
        let nonce_gen = ecdsa_fun::nonce::Synthetic::<
            sha2::Sha256,
            ecdsa_fun::nonce::GlobalRng<rand::rngs::ThreadRng>,
        >::default();
        let pok_1_message = serialize(&c_h);
        let pok_1_message_hash: [u8; 32] = sha2::Sha256::digest(&pok_1_message).try_into().unwrap();
        let ecdsa = ecdsa_fun::ECDSA::new(nonce_gen);

        let pok_1 = ecdsa.sign(&x_secp256k1, &pok_1_message_hash);

        assert!(ecdsa.verify(&xH_p, &pok_1_message_hash, &pok_1));

        DLEQProof {
            xG_p,
            xH_p,
            c_g,
            c_h,
            ring_signatures,
            pok_0,
            pok_1,
        }
    }

    pub(crate) fn verify(&self) -> Result<(), crypto::Error> {
        assert_eq!(252, self.c_g.len());
        assert_eq!(252, self.c_h.len());
        assert_eq!(252, self.ring_signatures.len());

        // Commitments
        let commitment_agg_ed25519 = self.c_g.iter().sum();

        if !(self.xG_p == commitment_agg_ed25519) {
            return Err(crypto::Error::InvalidPedersenCommitment);
        }

        let commitment_agg_secp256k1 = self
            .c_h
            .iter()
            .fold(secp256k1Point::zero(), |acc, bit_commitment| {
                g!(acc + bit_commitment).mark::<Normal>()
            });

        if !(self.xH_p == commitment_agg_secp256k1) {
            return Err(crypto::Error::InvalidPedersenCommitment);
        }

        // Ring signatures
        let valid_ring_signatures = self
            .c_g
            .clone()
            .iter()
            .enumerate()
            .zip(self.c_h.clone())
            .zip(self.ring_signatures.clone())
            .all(|(((index, c_g_i), c_h_i), ring_sig)| {
                verify_ring_sig(index, *c_g_i, c_h_i, ring_sig)
            });

        if !(valid_ring_signatures) {
            return Err(crypto::Error::InvalidRingSignature);
        }

        // Proof of Knowledge
        // ed25519 (edDSA)
        #[allow(non_snake_case)]
        let (alpha_G, r) = self.pok_0;
        let mut challenge_preimage = vec![];
        challenge_preimage.extend_from_slice(alpha_G.compress().as_bytes());
        challenge_preimage.extend_from_slice(self.xG_p.compress().as_bytes());
        challenge_preimage.extend_from_slice(serialize(&self.c_g).as_slice());
        let challenge = monero::cryptonote::hash::keccak_256(&challenge_preimage);

        if r * G != alpha_G + ed25519Scalar::from_bytes_mod_order(challenge) * self.xG_p {
            return Err(crypto::Error::InvalidProofOfKnowledge);
        }

        // secp256k1 (ECDSA)
        let ecdsa = ecdsa_fun::ECDSA::verify_only();
        let pok_1_message = serialize(&self.c_h);
        let pok_1_message_hash: [u8; 32] = sha2::Sha256::digest(pok_1_message.as_slice())
            .try_into()
            .unwrap();
        if !ecdsa_fun::ECDSA::verify(&ecdsa, &self.xH_p, &pok_1_message_hash, &self.pok_1) {
            return Err(crypto::Error::InvalidProofOfKnowledge);
        }

        // Everything ok
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pedersen_commitment_works() {
        use rand::Rng;
        let mut x: [u8; 32] = rand::thread_rng().gen();
        // ensure 256th bit is 0
        x[31] &= 0b0111_1111;
        let x_bits = BitSlice::<Lsb0, u8>::from_slice(&x).unwrap();
        let key_commitment = key_commitment(x_bits, 255);
        let commitment_acc = key_commitment.iter().map(|pc| pc.commitment).sum();
        assert_eq!(ed25519Scalar::from_bytes_mod_order(x) * G, commitment_acc);
    }

    #[test]
    fn pedersen_commitment_sec256k1_works() {
        use rand::Rng;
        let x: [u8; 32] = rand::thread_rng().gen();
        // let mut x: [u8; 32] = rand::thread_rng().gen();
        // ensure 256th bit is 0
        // x[31] &= 0b0111_1111;
        let x_bits = BitSlice::<Lsb0, u8>::from_slice(&x).unwrap();
        let key_commitment = key_commitment_secp256k1(x_bits, 255);
        // let commitment_acc: secp256k1Point<Jacobian, Public, Zero> = key_commitment
        let commitment_acc = key_commitment.iter().fold(
            secp256k1Point::zero(),
            |acc, bit_commitment| g!(acc + bit_commitment.commitment).mark::<Normal>(), // .fold(secp256k1Point::zero().mark::<Jacobian>(), |acc, bit_commitment| g!(acc + bit_commitment.commitment)
        );
        let x_secp256k1 = secp256k1Scalar::from_bytes_mod_order(reverse_endianness(&x));
        assert_eq!(g!(x_secp256k1 * H), commitment_acc);
    }

    #[test]
    fn dleq_proof_works() {
        use rand::Rng;
        let x: [u8; 32] = rand::thread_rng().gen();
        let x_shaved = _zeroize_highest_bits(x, 252);
        let dleq = DLEQProof::generate(x_shaved);

        assert!(dleq.verify().is_ok(), "{:?}", dleq.verify().err().unwrap());
    }

    #[test]
    fn blinders_sum_to_zero() {
        use rand::Rng;
        let x: [u8; 32] = rand::thread_rng().gen();
        let x_bits = BitSlice::<Lsb0, u8>::from_slice(&x).unwrap();
        let key_commitment = key_commitment(x_bits, 255);
        let blinder_acc = key_commitment
            .iter()
            .fold(ed25519Scalar::zero(), |acc, bit_commitment| {
                acc + bit_commitment.blinder
            });
        assert_eq!(blinder_acc, ed25519Scalar::zero());
    }

    #[test]
    #[allow(non_snake_case)]
    fn alt_ed25519_generator_is_correct() {
        assert_eq!(G_p(), monero::util::key::H.point.decompress().unwrap())
    }

    #[test]
    fn canonical_encoding_decoding_idempotent() {
        use rand::Rng;
        let x: [u8; 32] = rand::thread_rng().gen();
        let x_shaved = _zeroize_highest_bits(x, 252);
        let dleq = DLEQProof::generate(x_shaved);

        assert_eq!(
            DLEQProof::from_canonical_bytes(dleq.as_canonical_bytes().as_slice()).unwrap(),
            dleq
        )
    }
}
// #[test]
// fn ring_signature() {
//     let mut csprng = rand_alt::rngs::OsRng;
//     RingSignature::from((
//         false,
//         PedersenCommitment {
//             commitment: ed25519Scalar::random(&mut csprng) * G,
//             blinder: ed25519Scalar::random(&mut csprng),
//         },
//         PedersenCommitment {
//             commitment: secp256k1Point::random(&mut rand::thread_rng()),
//             blinder: secp256k1Scalar::random(&mut rand::thread_rng()),
//         },
//     ));
// }
