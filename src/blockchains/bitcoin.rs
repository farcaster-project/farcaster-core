//! Defines and implements all the traits for Bitcoin

use bitcoin::hash_types::PubkeyHash;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::psbt::PartiallySignedTransaction;
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;
use secp256k1::Signature;

use crate::blockchains::{Blockchain, Fee, FixeFee};
use crate::crypto::{Crypto, ECDSAScripts, TrSchnorrScripts};
use crate::roles::Arbitrating;

pub struct Bitcoin {}

impl Blockchain for Bitcoin {
    type AssetUnit = Amount;

    fn id(&self) -> String {
        String::from("btc")
    }

    fn new() -> Self {
        Bitcoin {}
    }
}

pub struct SatPerVByte(Amount);

impl SatPerVByte {
    pub fn from_sat(satoshi: u64) -> Self {
        SatPerVByte(Amount::from_sat(satoshi))
    }
}

impl Fee<FixeFee<Bitcoin>> for Bitcoin {
    /// Type for describing the fees of a blockchain
    type FeeUnit = SatPerVByte;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(_tx: &mut PartiallySignedTransaction, _strategy: &FixeFee<Bitcoin>) -> SatPerVByte {
        todo!()
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(_tx: &PartiallySignedTransaction, _strategy: &FixeFee<Bitcoin>) -> bool {
        todo!()
    }
}

impl Arbitrating for Bitcoin {
    type Transaction = PartiallySignedTransaction;
    type Address = Address;
}

impl Crypto<ECDSAScripts> for Bitcoin {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
    type Commitment = PubkeyHash;
    type Signature = Signature;
}

impl Crypto<TrSchnorrScripts> for Bitcoin {
    type PrivateKey = SecretKey;
    type PublicKey = secp256k1::schnorrsig::PublicKey;
    type Commitment = PubkeyHash;
    type Signature = secp256k1::schnorrsig::Signature;
}
