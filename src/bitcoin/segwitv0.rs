//! SegWit version 0 implementation for Bitcoin. Inner implementation of [`BitcoinSegwitV0`].

use std::convert::TryFrom;
use std::fmt::{self, Debug};
use std::str::FromStr;

use crate::bitcoin::segwitv0::{
    buy::Buy, cancel::Cancel, funding::Funding, lock::Lock, punish::Punish, refund::Refund,
};
use crate::bitcoin::transaction::TxInRef;
use crate::bitcoin::transaction::{MetadataOutput, Tx};
use crate::bitcoin::{Bitcoin, BitcoinSegwitV0, Btc, Strategy};

use crate::bitcoin::timelock::CSVTimelock;
use crate::blockchain::Transactions;
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedSecretKeys, Signatures};
use crate::role::{Arbitrating, SwapRole};
use crate::script::{DataLock, DataPunishableLock, DoubleKeys, ScriptPath};

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Instruction, Script};
use bitcoin::blockdata::transaction::EcdsaSighashType;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey, Signing};
use bitcoin::util::sighash::SighashCache;

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

impl fmt::Display for Bitcoin<SegwitV0> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bitcoin<SegwitV0>")
    }
}

impl FromStr for Bitcoin<SegwitV0> {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SegwitV0" | "ECDSA" | "Bitcoin" | "bitcoin" => Ok(Self::new()),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl From<BitcoinSegwitV0> for Btc {
    fn from(v: BitcoinSegwitV0) -> Self {
        Self::SegwitV0(v)
    }
}

pub struct CoopLock {
    a: PublicKey,
    b: PublicKey,
}

impl CoopLock {
    pub fn script(data: DataLock<CSVTimelock, PublicKey>) -> Script {
        let DataLock {
            success: DoubleKeys { alice, bob },
            ..
        } = data;
        Builder::new()
            .push_key(&bitcoin::util::key::PublicKey::new(alice))
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_key(&bitcoin::util::key::PublicKey::new(bob))
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    pub fn v0_p2wsh(data: DataLock<CSVTimelock, PublicKey>) -> Script {
        Self::script(data).to_v0_p2wsh()
    }

    pub fn from_script(s: &Script) -> Result<Self, crate::transaction::Error> {
        use crate::transaction::Error;
        use bitcoin::blockdata::opcodes::all;

        let mut ints = s.instructions();
        // Alice pubkey
        let bytes = ints
            .next() // Option<Result<Inst., Err>>
            .ok_or(Error::MissingPublicKey) // Result<Result, Inst., Err>, FErr>
            .map_or_else(
                // Pass the error through
                Err,
                |v| match v {
                    Ok(Instruction::PushBytes(b)) => Ok(b),
                    // Error in the script
                    Err(e) => Err(Error::new(e)),
                    // Not a push bytes, not a pubkey
                    _ => Err(Error::MissingPublicKey),
                },
            )?;
        let a = PublicKey::from_slice(bytes).map_err(Error::new)?;
        // Checksig verify
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_CHECKSIGVERIFY)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing CHECKSIGVERIFY opcode")),
            })?;
        // Bob pubkey
        let bytes = ints
            .next()
            .ok_or(Error::MissingPublicKey)
            .map_or_else(Err, |v| match v {
                Ok(Instruction::PushBytes(b)) => Ok(b),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::MissingPublicKey),
            })?;
        let b = PublicKey::from_slice(bytes).map_err(Error::new)?;
        // Checksig
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_CHECKSIG)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing CHECKSIG opcode")),
            })?;

        // Script done, return an error if some error or some instruction
        if let Some(v) = ints.next() {
            return match v {
                Ok(_) => Err(Error::WrongTemplate("Too many opcodes")),
                Err(e) => Err(Error::new(e)),
            };
        }

        Ok(Self { a, b })
    }

    pub fn get_pubkey(&self, swap_role: SwapRole) -> &PublicKey {
        match swap_role {
            SwapRole::Alice => &self.a,
            SwapRole::Bob => &self.b,
        }
    }
}

pub struct PunishLock {
    alice: PublicKey,
    bob: PublicKey,
    punish: PublicKey,
}

impl PunishLock {
    pub fn script(data: DataPunishableLock<CSVTimelock, PublicKey>) -> Script {
        let DataPunishableLock {
            timelock,
            success: DoubleKeys { alice, bob },
            failure,
        } = data;
        Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_key(&bitcoin::util::key::PublicKey::new(alice))
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_key(&bitcoin::util::key::PublicKey::new(bob))
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_key(&bitcoin::util::key::PublicKey::new(failure))
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script()
    }

    pub fn v0_p2wsh(data: DataPunishableLock<CSVTimelock, PublicKey>) -> Script {
        Self::script(data).to_v0_p2wsh()
    }

    pub fn from_script(s: &Script) -> Result<Self, crate::transaction::Error> {
        use crate::transaction::Error;
        use bitcoin::blockdata::opcodes::all;

        let mut ints = s.instructions();
        // If opcode
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_IF)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing IF opcode")),
            })?;
        // Alice pubkey
        let bytes = ints
            .next() // Option<Result<Inst., Err>>
            .ok_or(Error::MissingPublicKey) // Result<Result, Inst., Err>, FErr>
            .map_or_else(
                // Pass the error through
                Err,
                |v| match v {
                    Ok(Instruction::PushBytes(b)) => Ok(b),
                    // Error in the script
                    Err(e) => Err(Error::new(e)),
                    // Not a push bytes, not a pubkey
                    _ => Err(Error::MissingPublicKey),
                },
            )?;
        let alice = PublicKey::from_slice(bytes).map_err(Error::new)?;
        // Checksig verify
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_CHECKSIGVERIFY)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing CHECKSIGVERIFY opcode")),
            })?;
        // Bob pubkey
        let bytes = ints
            .next()
            .ok_or(Error::MissingPublicKey)
            .map_or_else(Err, |v| match v {
                Ok(Instruction::PushBytes(b)) => Ok(b),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::MissingPublicKey),
            })?;
        let bob = PublicKey::from_slice(bytes).map_err(Error::new)?;
        // Checksig
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_CHECKSIG)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing CHECKSIG opcode")),
            })?;
        // Else opcode
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_ELSE)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing ELSE opcode")),
            })?;
        // Timelock
        let _ = ints.next().ok_or(Error::WrongTemplate("Missing opcode"))?;
        // CSV opcode
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_CSV)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing CSV opcode")),
            })?;
        // CSV opcode
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_DROP)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing DROP opcode")),
            })?;
        // Punish pubkey
        let bytes = ints
            .next()
            .ok_or(Error::MissingPublicKey)
            .map_or_else(Err, |v| match v {
                Ok(Instruction::PushBytes(b)) => Ok(b),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::MissingPublicKey),
            })?;
        let punish = PublicKey::from_slice(bytes).map_err(Error::new)?;
        // Checksig
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_CHECKSIG)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing CHECKSIG opcode")),
            })?;
        // Endif opcode
        ints.next()
            .ok_or(Error::WrongTemplate("Missing opcode"))
            .map_or_else(Err, |v| match v {
                Ok(Instruction::Op(all::OP_ENDIF)) => Ok(()),
                Err(e) => Err(Error::new(e)),
                _ => Err(Error::WrongTemplate("Missing ENDIF opcode")),
            })?;

        // Script done, return an error if some error or some instruction
        if let Some(v) = ints.next() {
            return match v {
                Ok(_) => Err(Error::WrongTemplate("Too many opcodes")),
                Err(e) => Err(Error::new(e)),
            };
        }

        Ok(Self { alice, bob, punish })
    }

    pub fn get_pubkey(&self, swap_role: SwapRole, script_path: ScriptPath) -> Option<&PublicKey> {
        match script_path {
            ScriptPath::Success => match swap_role {
                SwapRole::Alice => Some(&self.alice),
                SwapRole::Bob => Some(&self.bob),
            },
            ScriptPath::Failure => match swap_role {
                SwapRole::Alice => Some(&self.punish),
                SwapRole::Bob => None,
            },
        }
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
    type SecretKey = SecretKey;
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

impl SharedSecretKeys for Bitcoin<SegwitV0> {
    type SharedSecretKey = SecretKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // No shared key in Bitcoin, transparent ledger
        vec![]
    }
}

impl Signatures for Bitcoin<SegwitV0> {
    type Message = Sha256dHash;
    type Signature = Signature;
    type EncryptedSignature = EncryptedSignature;
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
    sighash_type: EcdsaSighashType,
) -> Sha256dHash {
    SighashCache::new(txin.transaction)
        .segwit_signature_hash(txin.index, script, value, sighash_type)
        .expect("encoding works")
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
    sighash_type: EcdsaSighashType,
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> Result<Signature, bitcoin::secp256k1::Error>
where
    C: Signing,
{
    // Computes sighash.
    let sighash = signature_hash(txin, script, value, sighash_type);
    // Makes signature.
    let msg = Message::from_slice(&sighash[..])?;
    let mut sig = context.sign_ecdsa(&msg, secret_key);
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
    let mut sig = context.sign_ecdsa(&msg, secret_key);
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
        let parse = Bitcoin::<SegwitV0>::from_str("Bitcoin");
        assert!(parse.is_ok());
        let parse = Bitcoin::<SegwitV0>::from_str("bitcoin");
        assert!(parse.is_ok());
    }
}
