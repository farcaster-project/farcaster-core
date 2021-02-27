//! Defines and implements all the traits for Bitcoin

use bitcoin::hash_types::PubkeyHash;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::psbt::PartiallySignedTransaction;
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;
use secp256k1::Signature;

use crate::blockchains::{Blockchain, Fee, StaticFee};
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

impl Fee<StaticFee<Bitcoin>> for Bitcoin {
    type FeeUnit = SatPerVByte;

    /// Calculate and return the fees for the given transaction
    fn set_fees(
        _tx: &mut PartiallySignedTransaction,
        _strategy: &StaticFee<Bitcoin>,
    ) -> SatPerVByte {
        todo!()
    }

    /// Validate that the fees for the given transaction are correct
    fn validate_fee(
        _tx: &PartiallySignedTransaction,
        _fee: &SatPerVByte,
        _strategy: &StaticFee<Bitcoin>,
    ) -> bool {
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
