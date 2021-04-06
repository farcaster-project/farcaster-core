//! Defines and implements all the traits for Bitcoin

use bitcoin::blockdata::transaction::TxOut;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::secp256k1::Signature;
use bitcoin::util::address::Address;
use bitcoin::util::amount;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use monero::cryptonote::hash::Hash;
use strict_encoding::{StrictDecode, StrictEncode};

use farcaster_core::blockchain::{
    Blockchain, Fee, FeePolitic, FeeStrategy, FeeStrategyError, FeeUnit, Onchain,
};
use farcaster_core::consensus::{self, Decodable, Encodable};
use farcaster_core::crypto::{
    Commitment, CrossGroupDLEQ, Curve, ECDSAScripts, Keys, Script, Signatures,
};
use farcaster_core::role::Arbitrating;

use crate::monero::{Ed25519, Monero};

use std::io;
use std::fmt::Debug;
use std::str::FromStr;

pub mod transaction;

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin;

impl FromStr for Bitcoin {
    type Err = farcaster_core::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Bitcoin" => Ok(Self),
            _ => Err(farcaster_core::consensus::Error::UnknownType)
        }
    }
}

impl Blockchain for Bitcoin {
    /// Type for the traded asset unit
    type AssetUnit = Amount;

    /// Create a new Bitcoin blockchain
    fn new() -> Self {
        Bitcoin {}
    }

    fn from_u32(bytes: u32) -> Option<Self> {
        match bytes {
            0x80000000 => Some(Self::new()),
            _ => None,
        }
    }

    fn to_u32(&self) -> u32 {
        0x80000000
    }
}

impl FromStr for Amount {
    type Err = farcaster_core::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u64>()
            .map_err(|_| farcaster_core::consensus::Error::ParseFailed("Failed to parse amount"))?;
        Ok(Self(amount::Amount::from_sat(x)))
    }
}

/// Bitcoin amount wrapper
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, StrictDecode, StrictEncode)]
pub struct Amount(amount::Amount);

impl Amount {
    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    pub fn from_sat(sat: u64) -> Self {
        Self(amount::Amount::from_sat(sat))
    }

    pub fn checked_mul(&self, other: u64) -> Option<Self> {
        Some(Self(self.0.checked_mul(other)?))
    }

    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        Some(Self(self.0.checked_sub(other.0)?))
    }
}

impl Encodable for Amount {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.as_sat(), writer)
    }
}

impl Decodable for Amount {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let sats: u64 = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin amount parsing failed"))?;
        Ok(Amount::from_sat(sats))
    }
}

impl FromStr for SatPerVByte {
    type Err = farcaster_core::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u64>()
            .map_err(|_| farcaster_core::consensus::Error::ParseFailed("Failed to parse amount"))?;
        Ok(Self(Amount(amount::Amount::from_sat(x))))
    }
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, StrictDecode, StrictEncode)]
pub struct SatPerVByte(Amount);

impl SatPerVByte {
    pub fn from_sat(satoshi: u64) -> Self {
        SatPerVByte(Amount::from_sat(satoshi))
    }

    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    pub fn as_native_unit(&self) -> Amount {
        self.0
    }
}

impl Encodable for SatPerVByte {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for SatPerVByte {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let amount: Amount = Decodable::consensus_decode(d)?;
        Ok(SatPerVByte(amount))
    }
}

impl FeeUnit for Bitcoin {
    type FeeUnit = SatPerVByte;
}

impl Fee for Bitcoin {
    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(
        tx: &mut PartiallySignedTransaction,
        strategy: &FeeStrategy<SatPerVByte>,
        politic: FeePolitic,
    ) -> Result<Amount, FeeStrategyError> {
        // Get the available amount on the transaction
        let inputs: Result<Vec<TxOut>, FeeStrategyError> = tx
            .inputs
            .iter()
            .map(|psbt_in| {
                psbt_in
                    .witness_utxo
                    .clone()
                    .ok_or(FeeStrategyError::MissingInputsMetadata)
            })
            .collect();
        let input_sum = Amount::from_sat(inputs?.iter().map(|txout| txout.value).sum());

        // FIXME This does not account for witnesses
        // Get the transaction weight
        let weight = tx.global.unsigned_tx.get_weight() as u64;

        // Compute the fee amount to set in total
        let fee_amount = match strategy {
            FeeStrategy::Fixed(sat_per_vbyte) => sat_per_vbyte.as_native_unit().checked_mul(weight),
            FeeStrategy::Range(range) => match politic {
                FeePolitic::Aggressive => range.start.as_native_unit().checked_mul(weight),
                FeePolitic::Conservative => range.end.as_native_unit().checked_mul(weight),
            },
        }
        .ok_or_else(|| FeeStrategyError::AmountOfFeeTooHigh)?;

        if tx.global.unsigned_tx.output.len() != 1 {
            return Err(FeeStrategyError::MultiOutputUnsupported);
        }

        // Apply the fee on the first output
        tx.global.unsigned_tx.output[0].value = input_sum
            .checked_sub(fee_amount)
            .ok_or_else(|| FeeStrategyError::NotEnoughAssets)?
            .as_sat();

        // Return the fee amount set in native blockchain asset unit
        Ok(fee_amount)
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(
        _tx: &PartiallySignedTransaction,
        _strategy: &FeeStrategy<SatPerVByte>,
        _politic: FeePolitic,
    ) -> Result<bool, FeeStrategyError> {
        todo!()
    }
}

impl Arbitrating for Bitcoin {
    /// Defines the transaction format for the arbitrating blockchain
    type Address = Address;

    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = CSVTimelock;
}

impl FromStr for CSVTimelock {
    type Err = farcaster_core::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s.parse::<u32>().map_err(|_| {
            farcaster_core::consensus::Error::ParseFailed("Failed parsing CSV timelock")
        })?;
        Ok(CSVTimelock(x))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Clone, Debug, StrictDecode, StrictEncode, Copy)]
#[strict_encoding_crate(strict_encoding)]
pub struct CSVTimelock(u32);

impl CSVTimelock {
    pub fn new(timelock: u32) -> Self {
        Self(timelock)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Encodable for CSVTimelock {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.0, writer)
    }
}

impl Decodable for CSVTimelock {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let timelock: u32 = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin u32 timelock parsing failed"))?;
        Ok(CSVTimelock(timelock))
    }
}

impl Onchain for Bitcoin {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::blockdata::transaction::Transaction;
}

#[derive(Clone, Debug)]
pub struct Secp256k1;

impl Curve for Bitcoin {
    /// Eliptic curve
    type Curve = Secp256k1;
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct ECDSAAdaptorSig {
    pub sig: Signature,
    pub point: PublicKey,
    pub dleq: PDLEQ,
}

/// Produces a zero-knowledge proof of knowledge of the same relation k between two pairs of
/// elements in the same group, i.e. `(G, R')` and `(T, R)`.
#[derive(Clone, Debug)]
pub struct PDLEQ;

impl StrictEncode for PDLEQ {
    fn strict_encode<E: std::io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        let res = Hash::hash(&"Farcaster PDLEQ".as_bytes()).to_bytes();
        e.write(&res)?;
        Ok(res.len())
    }
}

impl StrictDecode for PDLEQ {
    fn strict_decode<D: std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        let expected = Hash::hash(&"Farcaster PDLEQ".as_bytes()).to_bytes();
        if expected == buf {
            Ok(PDLEQ)
        } else {
            Err(strict_encoding::Error::DataIntegrityError(
                "Not PDLEQ type".to_string(),
            ))
        }
    }
}

impl Script for Bitcoin {
    type Script = ECDSAScripts;
}

impl Keys for Bitcoin {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
}

impl Commitment for Bitcoin {
    type Commitment = PubkeyHash;
}

impl Signatures for Bitcoin {
    type Signature = Signature;
    type AdaptorSignature = ECDSAAdaptorSig;
}

//// TODO: implement on another struct or on a generic Bitcoin<T>
// impl Crypto for Bitcoin {
//     type PrivateKey = SecretKey;
//     type PublicKey = secp256k1::schnorrsig::PublicKey;
//     type Commitment = PubkeyHash;
// }

pub struct RingSignatureProof;

impl StrictEncode for Secp256k1 {
    fn strict_encode<E: std::io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        let res = Hash::hash(&"Farcaster Secp256k1".as_bytes()).to_bytes();
        e.write(&res)?;
        Ok(res.len())
    }
}

impl StrictDecode for Secp256k1 {
    fn strict_decode<D: std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        let expected = Hash::hash(&"Farcaster Secp256k1".as_bytes()).to_bytes();
        if expected == buf {
            Ok(Self)
        } else {
            Err(strict_encoding::Error::DataIntegrityError(
                "Not Secp256k1 type".to_string(),
            ))
        }
    }
}

impl CrossGroupDLEQ<Bitcoin, Monero> for RingSignatureProof {}

impl PartialEq<Ed25519> for Secp256k1 {
    fn eq(&self, _other: &Ed25519) -> bool {
        todo!()
    }
}

impl PartialEq<Secp256k1> for Ed25519 {
    fn eq(&self, other: &Secp256k1) -> bool {
        other.eq(self)
    }
}
