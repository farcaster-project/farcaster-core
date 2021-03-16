//! Defines and implements all the traits for Bitcoin

use bitcoin::blockdata::transaction::TxOut;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::SerializedSignature;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::blockchain::{
    Blockchain, Fee, FeePolitic, FeeStrategy, FeeStrategyError, FeeUnit, Onchain,
};
use crate::crypto::{Commitment, CrossGroupDLEQ, Curve, ECDSAScripts, Keys, Script, Signatures};
use crate::monero::{Ed25519, Monero};
use crate::role::Arbitrating;

pub mod transaction;

#[derive(Clone, Copy)]
pub struct Bitcoin;

impl Blockchain for Bitcoin {
    /// Type for the traded asset unit
    type AssetUnit = Amount;

    /// Type of the blockchain identifier
    type Id = String;

    /// Type of the chain identifier
    type ChainId = Network;

    /// Returns the blockchain identifier
    fn id(&self) -> String {
        String::from("btc")
    }

    /// Returns the chain identifier
    fn chain_id(&self) -> Network {
        Network::Bitcoin
    }

    /// Create a new Bitcoin blockchain
    fn new() -> Self {
        Bitcoin {}
    }
}

#[derive(Clone, PartialOrd, PartialEq)]
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

#[derive(Clone)]
pub enum FeeStrategies {
    Fixed(SatPerVByte),
    Range(std::ops::Range<SatPerVByte>),
}

impl FeeUnit for FeeStrategies {
    type FeeUnit = SatPerVByte;
}

impl FeeStrategy for FeeStrategies {
    fn fixed_fee(fee: Self::FeeUnit) -> Self {
        FeeStrategies::Fixed(fee)
    }

    fn range_fee(fee_low: Self::FeeUnit, fee_high: Self::FeeUnit) -> Self {
        if fee_low > fee_high {
            FeeStrategies::Fixed(fee_high)
        } else {
            FeeStrategies::Range(std::ops::Range {
                start: fee_low,
                end: fee_high,
            })
        }
    }
}

impl Fee for Bitcoin {
    type FeeStrategy = FeeStrategies;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(
        tx: &mut PartiallySignedTransaction,
        strategy: &FeeStrategies,
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
            FeeStrategies::Fixed(sat_per_vbyte) => {
                sat_per_vbyte.as_native_unit().checked_mul(weight)
            }
            FeeStrategies::Range(range) => match politic {
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
        _strategy: &FeeStrategies,
        _politic: FeePolitic,
    ) -> Result<bool, FeeStrategyError> {
        todo!()
    }
}

impl Arbitrating for Bitcoin {
    /// Defines the transaction format for the arbitrating blockchain
    type Address = Address;

    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = u32;
}

impl Onchain for Bitcoin {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::blockdata::transaction::Transaction;
}

pub struct Secp256k1;

impl Curve for Bitcoin {
    /// Eliptic curve
    type Curve = Secp256k1;
}

/// Produces a zero-knowledge proof of knowledge of the same relation k between two pairs of
/// elements in the same group, i.e. `(G, R')` and `(T, R)`.
pub struct PDLEQ;

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
    type Signature = SerializedSignature;
    type AdaptorSignature = (SerializedSignature, PublicKey, PDLEQ);
}

//// TODO: implement on another struct or on a generic Bitcoin<T>
// impl Crypto for Bitcoin {
//     type PrivateKey = SecretKey;
//     type PublicKey = secp256k1::schnorrsig::PublicKey;
//     type Commitment = PubkeyHash;
// }

pub struct RingSignatureProof;

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
