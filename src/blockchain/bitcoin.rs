//! Defines and implements all the traits for Bitcoin

use bitcoin::hash_types::PubkeyHash;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::psbt::PartiallySignedTransaction;
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;
use secp256k1::Signature;

use crate::blockchain::monero::{Ed25519, Monero};
use crate::blockchain::{Blockchain, Fee, FeeStrategy, FeeUnit};
use crate::crypto::{
    Arbitration, CrossGroupDLEQ, Keys, Curve, ECDSAScripts, Signatures, TrSchnorrScripts, Commitment
};
use crate::role::{Arbitrating, Transaction};

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

#[derive(Clone, Copy)]
pub struct SatPerVByte(Amount);

impl SatPerVByte {
    pub fn from_sat(satoshi: u64) -> Self {
        SatPerVByte(Amount::from_sat(satoshi))
    }
}

#[derive(Clone, Copy)]
pub enum FeeStrategies {
    Fixed(SatPerVByte),
    Range(SatPerVByte, SatPerVByte)
}

impl FeeStrategy for Bitcoin {
    type FeeStrategy = FeeStrategies;

    fn fixed_fee(fee: Self::FeeUnit) -> Self::FeeStrategy {
        FeeStrategies::Fixed(fee)
    }

    fn range_fee(fee_low: Self::FeeUnit, fee_high: Self::FeeUnit) -> Self::FeeStrategy {
        FeeStrategies::Range(fee_low, fee_high)
    }
}

impl FeeUnit for Bitcoin {
    type FeeUnit = SatPerVByte;
}

impl Fee for Bitcoin {

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(
        _tx: &mut PartiallySignedTransaction,
        _strategy: &FeeStrategies,
    ) -> SatPerVByte {
        todo!()
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(_tx: &PartiallySignedTransaction, _strategy: &FeeStrategies) -> bool {
        todo!()
    }
}


impl Arbitrating for Bitcoin {
    /// Defines the transaction format for the arbitrating blockchain
    type Address = Address;

    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = u32;
}
impl Transaction for Bitcoin {
    /// Defines the address format for the arbitrating blockchain
    type Transaction = PartiallySignedTransaction;
}

pub struct Secp256k1;

impl Curve for Bitcoin {
    /// Eliptic curve
    type Curve = Secp256k1;
}

/// Produces a zero-knowledge proof of knowledge of the same relation k between two pairs of
/// elements in the same group, i.e. `(G, R')` and `(T, R)`.
pub struct PDLEQ;

impl Arbitration for Bitcoin {
    type Arbitration = ECDSAScripts;
}

impl Keys for Bitcoin {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
}
impl Commitment for Bitcoin {
    type Commitment = PubkeyHash;
}

impl Signatures for Bitcoin {
    type Signature = Signature;
    type AdaptorSignature = (Signature, PublicKey, PDLEQ);
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
