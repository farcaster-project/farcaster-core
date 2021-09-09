//! SegWit version 0 implementation for Bitcoin. Inner implementation of [`BitcoinSegwitV0`].

use std::convert::TryFrom;
use std::fmt::Debug;
use std::str::FromStr;

use crate::bitcoin::segwitv0::{
    buy::Buy, cancel::Cancel, funding::Funding, lock::Lock, punish::Punish, refund::Refund,
};
use crate::bitcoin::transaction::TxInRef;
use crate::bitcoin::transaction::{MetadataOutput, Tx};
use crate::bitcoin::{Bitcoin, BitcoinSegwitV0, Btc, Strategy};

use crate::blockchain::Transactions;
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedPrivateKeys, Signatures};
use crate::role::Arbitrating;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::{
    key::{PublicKey, SecretKey},
    Message, Secp256k1, Signature, Signing,
};
use bitcoin::util::bip143::SigHashCache;

use ecdsa_fun::adaptor::EncryptedSignature;

mod buy;
mod cancel;
pub mod funding;
mod lock;
mod punish;
mod refund;

/// Spend the lock output and reveal the first secret.
pub type BuyTx = Tx<Buy>;

/// Cancel the buy transaction and allow refund or punish transaction.
pub type CancelTx = Tx<Cancel>;

/// Funding the swap creating a SegWit v0 output.
pub type FundingTx = Funding;

/// Locking the funding UTXO in a lock and allow buy or cancel transaction.
pub type LockTx = Tx<Lock>;

/// Spending the funds of the cancel transaction, terminating the swap in its non-optimal case.
pub type PunishTx = Tx<Punish>;

/// Spend the cancel output and reveal the second secret.
pub type RefundTx = Tx<Refund>;

/// Inner type for the implementation of SegWit version 0 transactions and ECDSA cryptography.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct SegwitV0;

impl Strategy for SegwitV0 {}

impl FromStr for Bitcoin<SegwitV0> {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SegwitV0" | "ECDSA" => Ok(Self::new()),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl From<BitcoinSegwitV0> for Btc {
    fn from(v: BitcoinSegwitV0) -> Self {
        Self::SegwitV0(v)
    }
}

impl Arbitrating for Bitcoin<SegwitV0> {}

impl TryFrom<Btc> for Bitcoin<SegwitV0> {
    type Error = consensus::Error;

    fn try_from(v: Btc) -> Result<Self, consensus::Error> {
        match v {
            Btc::SegwitV0(v) => Ok(v),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }
}

impl Transactions for Bitcoin<SegwitV0> {
    type Metadata = MetadataOutput;

    type Funding = Funding;
    type Lock = Tx<Lock>;
    type Buy = Tx<Buy>;
    type Cancel = Tx<Cancel>;
    type Refund = Tx<Refund>;
    type Punish = Tx<Punish>;
}

impl Keys for Bitcoin<SegwitV0> {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;

    fn extra_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }
}

impl CanonicalBytes for SecretKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        (&self.as_ref()[..]).into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        SecretKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

impl CanonicalBytes for PublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.serialize().as_ref().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        PublicKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

impl SharedPrivateKeys for Bitcoin<SegwitV0> {
    type SharedPrivateKey = SecretKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // No shared key in Bitcoin, transparent ledger
        vec![]
    }
}

impl Signatures for Bitcoin<SegwitV0> {
    type Message = Sha256dHash;
    type Signature = Signature;
    type AdaptorSignature = EncryptedSignature;
}

impl CanonicalBytes for Signature {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.serialize_compact().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Signature::from_compact(bytes).map_err(consensus::Error::new)
    }
}

impl CanonicalBytes for EncryptedSignature {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("serialization should always work")
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        bincode::deserialize::<EncryptedSignature>(bytes).map_err(consensus::Error::new)
    }
}

/// Computes the [`BIP-143`][bip-143] compliant sighash for a `SIGHASH_ALL` signature for the given
/// input.
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
pub fn signature_hash(
    txin: TxInRef,
    script: &Script,
    value: u64,
    sighash_type: SigHashType,
) -> Sha256dHash {
    SigHashCache::new(txin.transaction)
        .signature_hash(txin.index, script, value, sighash_type)
        .as_hash()
}

/// Computes the [`BIP-143`][bip-143] compliant signature for the given input.
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
pub fn sign_input<C>(
    context: &mut Secp256k1<C>,
    txin: TxInRef,
    script: &Script,
    value: u64,
    sighash_type: SigHashType,
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> Result<Signature, bitcoin::secp256k1::Error>
where
    C: Signing,
{
    // Computes sighash.
    let sighash = signature_hash(txin, script, value, sighash_type);
    // Makes signature.
    let msg = Message::from_slice(&sighash[..])?;
    let mut sig = context.sign(&msg, secret_key);
    sig.normalize_s();
    Ok(sig)
}

/// Computes the [`BIP-143`][bip-143] compliant signature for the given hash.
/// Assumes that the hash is correctly computed.
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
pub fn sign_hash(
    sighash: Sha256dHash,
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> Result<Signature, bitcoin::secp256k1::Error> {
    let context = Secp256k1::new();
    // Makes signature.
    let msg = Message::from_slice(&sighash[..])?;
    let mut sig = context.sign(&msg, secret_key);
    sig.normalize_s();
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string() {
        let parse = Bitcoin::<SegwitV0>::from_str("SegwitV0");
        assert!(parse.is_ok());
        let parse = Bitcoin::<SegwitV0>::from_str("ECDSA");
        assert!(parse.is_ok());
    }
}
