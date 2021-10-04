//! A bundle is an aggregate of data contextually related to each others needed by the swap daemon
//! and/or swap client. Bundles are used during the different steps of the swap by both Alice and
//! Bob client/daemon.
//!
//! In general a bundle will be created by a client, will transit through its own daemon to then be
//! served over the network as a protocol message. The counter-party daemon will receive the bundle
//! and forward it to its client, completing a full round of communication between between Alice
//! and Bob clients.

use std::io;

use crate::blockchain::{Address, Fee, FeeStrategy, Onchain, Timelock};
use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};
use crate::crypto::{Keys, SharedKeyId, SharedSecretKeys, Signatures, TaggedElement};
use crate::protocol_message;
use crate::swap::Swap;

#[derive(Debug, Clone, Display)]
#[display(Debug)]
pub struct AliceProof<Ctx: Swap> {
    pub proof: Ctx::Proof,
}

impl<Ctx> Encodable for AliceProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.proof.as_canonical_bytes().consensus_encode(s)
    }
}

impl<Ctx> Decodable for AliceProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            proof: Ctx::Proof::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}


/// Alice parameters required for the initialization step of a swap and used to generate the
/// [`CommitAliceParameters`] and [`RevealAliceParameters`] protocol messages in the commit/reveal
/// round.
///
/// [`CommitAliceParameters`]: protocol_message::CommitAliceParameters
/// [`RevealAliceParameters`]: protocol_message::RevealAliceParameters
#[derive(Debug, Clone, Display)]
#[display(Debug)]
pub struct AliceParameters<Ctx: Swap> {
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    pub punish: <Ctx::Ar as Keys>::PublicKey,
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedSecretKeys>::SharedSecretKey>>,
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedSecretKeys>::SharedSecretKey>>,
    pub destination_address: <Ctx::Ar as Address>::Address,
    pub cancel_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub punish_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub fee_strategy: Option<FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>>,
}

impl<Ctx> Encodable for AliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.buy.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        len += self.punish.as_canonical_bytes().consensus_encode(s)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_arbitrating_keys.consensus_encode(s)?;
        len += self.arbitrating_shared_keys.consensus_encode(s)?;
        len += self.spend.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_accordant_keys.consensus_encode(s)?;
        len += self.accordant_shared_keys.consensus_encode(s)?;
        len += self
            .destination_address
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self.cancel_timelock.consensus_encode(s)?;
        len += self.punish_timelock.consensus_encode(s)?;
        Ok(len + self.fee_strategy.consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for AliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            buy: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            refund: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            punish: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            adaptor: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: <Ctx::Ac as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            destination_address: <Ctx::Ar as Address>::Address::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            cancel_timelock: Decodable::consensus_decode(d)?,
            punish_timelock: Decodable::consensus_decode(d)?,
            fee_strategy: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(AliceParameters<Ctx>, Ctx: Swap);
impl_strict_encoding!(AliceProof<Ctx>, Ctx: Swap);

impl<Ctx> From<protocol_message::RevealAliceParameters<Ctx>> for AliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(msg: protocol_message::RevealAliceParameters<Ctx>) -> Self {
        Self {
            buy: msg.buy,
            cancel: msg.cancel,
            refund: msg.refund,
            punish: msg.punish,
            adaptor: msg.adaptor,
            extra_arbitrating_keys: msg.extra_arbitrating_keys,
            arbitrating_shared_keys: msg.arbitrating_shared_keys,
            spend: msg.spend,
            extra_accordant_keys: msg.extra_accordant_keys,
            accordant_shared_keys: msg.accordant_shared_keys,
            destination_address: msg.address,
            cancel_timelock: None,
            punish_timelock: None,
            fee_strategy: None,
        }
    }
}

#[derive(Debug, Clone, Display)]
#[display(Debug)]
pub struct BobProof<Ctx: Swap> {
    pub proof: Ctx::Proof,
}

impl<Ctx> Encodable for BobProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.proof.as_canonical_bytes().consensus_encode(s)
    }
}

impl<Ctx> Decodable for BobProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            proof: Ctx::Proof::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(BobProof<Ctx>, Ctx: Swap);

/// Bob parameters required for the initialization step of a swap and used to generate the
/// [`CommitBobParameters`] and [`RevealBobParameters`] protocol messages in the commit/reveal
/// round.
///
/// [`CommitBobParameters`]: protocol_message::CommitBobParameters
/// [`RevealBobParameters`]: protocol_message::RevealBobParameters
#[derive(Debug, Clone, Display)]
#[display(Debug)]
pub struct BobParameters<Ctx: Swap> {
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedSecretKeys>::SharedSecretKey>>,
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedSecretKeys>::SharedSecretKey>>,
    pub refund_address: <Ctx::Ar as Address>::Address,
    pub cancel_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub punish_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub fee_strategy: Option<FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>>,
}

impl<Ctx> Encodable for BobParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.buy.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_arbitrating_keys.consensus_encode(s)?;
        len += self.arbitrating_shared_keys.consensus_encode(s)?;
        len += self.spend.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_accordant_keys.consensus_encode(s)?;
        len += self.accordant_shared_keys.consensus_encode(s)?;
        len += self
            .refund_address
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self.cancel_timelock.consensus_encode(s)?;
        len += self.punish_timelock.consensus_encode(s)?;
        Ok(len + self.fee_strategy.consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for BobParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            buy: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            refund: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            adaptor: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: <Ctx::Ac as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            refund_address: <Ctx::Ar as Address>::Address::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            cancel_timelock: Decodable::consensus_decode(d)?,
            punish_timelock: Decodable::consensus_decode(d)?,
            fee_strategy: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(BobParameters<Ctx>, Ctx: Swap);

impl<Ctx> From<protocol_message::RevealBobParameters<Ctx>> for BobParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(msg: protocol_message::RevealBobParameters<Ctx>) -> Self {
        Self {
            buy: msg.buy,
            cancel: msg.cancel,
            refund: msg.refund,
            adaptor: msg.adaptor,
            extra_arbitrating_keys: msg.extra_arbitrating_keys,
            arbitrating_shared_keys: msg.arbitrating_shared_keys,
            spend: msg.spend,
            extra_accordant_keys: msg.extra_accordant_keys,
            accordant_shared_keys: msg.accordant_shared_keys,
            refund_address: msg.address,
            cancel_timelock: None,
            punish_timelock: None,
            fee_strategy: None,
        }
    }
}

/// Provides daemon with a signature on the unsigned [`Cancelable`] transaction. Two signatures are
/// generated for the co-signed transaction, one come from the protocol message
/// [`CoreArbitratingSetup`] and the second from the [`RefundProcedureSignatures`].
///
/// [`CoreArbitratingSetup`]: protocol_message::CoreArbitratingSetup
/// [`RefundProcedureSignatures`]: protocol_message::RefundProcedureSignatures
/// [`Cancelable`]: crate::transaction::Cancelable
#[derive(Debug, Clone, Display)]
#[display("Cancel signature: {cancel_sig}")]
pub struct CosignedArbitratingCancel<S>
where
    S: Signatures,
{
    pub cancel_sig: S::Signature,
}

impl<S> Encodable for CosignedArbitratingCancel<S>
where
    S: Signatures,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.cancel_sig.as_canonical_bytes().consensus_encode(s)
    }
}

impl<S> Decodable for CosignedArbitratingCancel<S>
where
    S: Signatures,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            cancel_sig: S::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(CosignedArbitratingCancel<S>, S: Signatures);

impl<Ctx> From<protocol_message::CoreArbitratingSetup<Ctx>> for CosignedArbitratingCancel<Ctx::Ar>
where
    Ctx: Swap,
{
    fn from(msg: protocol_message::CoreArbitratingSetup<Ctx>) -> Self {
        Self {
            cancel_sig: msg.cancel_sig,
        }
    }
}

impl<Ctx> From<protocol_message::RefundProcedureSignatures<Ctx>>
    for CosignedArbitratingCancel<Ctx::Ar>
where
    Ctx: Swap,
{
    fn from(msg: protocol_message::RefundProcedureSignatures<Ctx>) -> Self {
        Self {
            cancel_sig: msg.cancel_sig,
        }
    }
}

/// Provides Bob's daemon the [`Fundable`] transaction for building the transactions contained in
/// [`CoreArbitratingTransactions`] bundle, later used to create protocol messages.
///
/// [`Fundable`]: crate::transaction::Fundable
#[derive(Debug, Clone, Display)]
#[display(funding_tx_fmt)]
pub struct FundingTransaction<T>
where
    T: Onchain,
{
    pub funding: T::Transaction,
}

fn funding_tx_fmt<T>(b: &FundingTransaction<T>) -> String
where
    T: Onchain,
{
    format!("Funding transaction: {:?}", b.funding)
}

impl<T> Encodable for FundingTransaction<T>
where
    T: Onchain,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.funding.as_canonical_bytes().consensus_encode(s)
    }
}

impl<T> Decodable for FundingTransaction<T>
where
    T: Onchain,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            funding: T::Transaction::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(FundingTransaction<T>, T: Onchain);

/// Provides Bob's daemon or Alice's clients the core set of arbritrating transactions present in
/// [`CoreArbitratingSetup`].
///
/// [`CoreArbitratingSetup`]: protocol_message::CoreArbitratingSetup
#[derive(Debug, Clone, Display)]
#[display(core_arbitrating_tx_fmt)]
pub struct CoreArbitratingTransactions<T>
where
    T: Onchain,
{
    pub lock: T::PartialTransaction,
    pub cancel: T::PartialTransaction,
    pub refund: T::PartialTransaction,
}

fn core_arbitrating_tx_fmt<T>(b: &CoreArbitratingTransactions<T>) -> String
where
    T: Onchain,
{
    format!(
        "Lock: {:?}, Cancel: {:?}, Refund: {:?}",
        b.lock, b.cancel, b.refund
    )
}

impl<T> Encodable for CoreArbitratingTransactions<T>
where
    T: Onchain,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.lock.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        Ok(len + self.refund.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<T> Decodable for CoreArbitratingTransactions<T>
where
    T: Onchain,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            lock: T::PartialTransaction::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: T::PartialTransaction::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: T::PartialTransaction::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(CoreArbitratingTransactions<T>, T: Onchain);

impl<Ctx> From<protocol_message::CoreArbitratingSetup<Ctx>> for CoreArbitratingTransactions<Ctx::Ar>
where
    Ctx: Swap,
{
    fn from(msg: protocol_message::CoreArbitratingSetup<Ctx>) -> Self {
        Self {
            lock: msg.lock,
            cancel: msg.cancel,
            refund: msg.refund,
        }
    }
}

/// Provides Bob's daemon or Alice's daemon/client with an adaptor (i.e. encrypted) signature for
/// the unsigned [`Buyable`] transaction. After verification, Alice will return a
/// [`FullySignedBuy`] bundle containing the adapted (i.e. decrypted) signature.
///
/// [`Buyable`]: crate::transaction::Buyable
#[derive(Debug, Clone, Display)]
#[display(signed_adaptor_buy_fmt)]
pub struct SignedAdaptorBuy<T>
where
    T: Signatures + Onchain,
{
    pub buy: T::PartialTransaction,
    pub buy_adaptor_sig: T::EncryptedSignature,
}

fn signed_adaptor_buy_fmt<T>(b: &SignedAdaptorBuy<T>) -> String
where
    T: Signatures + Onchain,
{
    format!(
        "Buy partial: {:?}, Buy adaptor: {}",
        b.buy, b.buy_adaptor_sig
    )
}

impl<T> Encodable for SignedAdaptorBuy<T>
where
    T: Signatures + Onchain,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.buy.as_canonical_bytes().consensus_encode(s)?;
        Ok(len
            + self
                .buy_adaptor_sig
                .as_canonical_bytes()
                .consensus_encode(s)?)
    }
}

impl<T> Decodable for SignedAdaptorBuy<T>
where
    T: Signatures + Onchain,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            buy: T::PartialTransaction::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            buy_adaptor_sig: T::EncryptedSignature::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(SignedAdaptorBuy<T>, T: Signatures + Onchain);

/// Provides Alice's daemon or Bob's daemon/client with the two signatures on the unsigned
/// [`Buyable`] transaction. Alice's standard signature and the adapted (i.e. decrypted) version of
/// Bob's adaptor (i.e. encrypted) signature with Alice's key.
///
/// [`Buyable`]: crate::transaction::Buyable
#[derive(Debug, Clone, Display)]
#[display("Buy signature: {buy_sig}, Buy adapted: {buy_adapted_sig}")]
pub struct FullySignedBuy<S>
where
    S: Signatures,
{
    pub buy_sig: S::Signature,
    pub buy_adapted_sig: S::Signature,
}

impl<S> Encodable for FullySignedBuy<S>
where
    S: Signatures,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.buy_sig.as_canonical_bytes().consensus_encode(s)?;
        Ok(len
            + self
                .buy_adapted_sig
                .as_canonical_bytes()
                .consensus_encode(s)?)
    }
}

impl<S> Decodable for FullySignedBuy<S>
where
    S: Signatures,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            buy_sig: S::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            buy_adapted_sig: S::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(FullySignedBuy<S>, S: Signatures);

/// Provides Alice's daemon or Bob's daemon/client with an adaptor (i.e. encrypted) signature on
/// the unsigned [`Refundable`] transaction.. After verification, Bob will return a
/// [`FullySignedRefund`] bundle containing the adapted (i.e. decrypted) signature.
///
/// [`Refundable`]: crate::transaction::Refundable
#[derive(Debug, Clone, Display)]
#[display("Refund adaptor: {refund_adaptor_sig}")]
pub struct SignedAdaptorRefund<S>
where
    S: Signatures,
{
    pub refund_adaptor_sig: S::EncryptedSignature,
}

impl<S> Encodable for SignedAdaptorRefund<S>
where
    S: Signatures,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.refund_adaptor_sig
            .as_canonical_bytes()
            .consensus_encode(s)
    }
}

impl<S> Decodable for SignedAdaptorRefund<S>
where
    S: Signatures,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            refund_adaptor_sig: S::EncryptedSignature::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(SignedAdaptorRefund<S>, S: Signatures);

impl<Ctx> From<protocol_message::RefundProcedureSignatures<Ctx>> for SignedAdaptorRefund<Ctx::Ar>
where
    Ctx: Swap,
{
    fn from(msg: protocol_message::RefundProcedureSignatures<Ctx>) -> Self {
        Self {
            refund_adaptor_sig: msg.refund_adaptor_sig,
        }
    }
}

/// Provides Bob's daemon or Alice's daemon/client with the two signatures on the unsigned
/// [`Refundable`] transaction. Bob's standard signature and the adapted (i.e. decrypted) version of
/// Alice's adaptor (i.e. encrypted) signature with Bob's key.
///
/// [`Refundable`]: crate::transaction::Refundable
#[derive(Debug, Clone, Display)]
#[display("Refund signature: {refund_sig}, Refund adapted: {refund_adapted_sig}")]
pub struct FullySignedRefund<S>
where
    S: Signatures,
{
    pub refund_sig: S::Signature,
    pub refund_adapted_sig: S::Signature,
}

impl<S> Encodable for FullySignedRefund<S>
where
    S: Signatures,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.refund_sig.as_canonical_bytes().consensus_encode(s)?;
        Ok(len
            + self
                .refund_adapted_sig
                .as_canonical_bytes()
                .consensus_encode(s)?)
    }
}

impl<S> Decodable for FullySignedRefund<S>
where
    S: Signatures,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            refund_sig: S::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund_adapted_sig: S::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(FullySignedRefund<S>, S: Signatures);

/// Provides Bob's daemon with the signature on the unsigned [`Lockable`] transaction present in
/// [`CoreArbitratingTransactions`].
///
/// [`Lockable`]: crate::transaction::Lockable
#[derive(Debug, Clone, Display)]
#[display("Lock signature: {lock_sig}")]
pub struct SignedArbitratingLock<S>
where
    S: Signatures,
{
    pub lock_sig: S::Signature,
}

impl<S> Encodable for SignedArbitratingLock<S>
where
    S: Signatures,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.lock_sig.as_canonical_bytes().consensus_encode(s)
    }
}

impl<S> Decodable for SignedArbitratingLock<S>
where
    S: Signatures,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            lock_sig: S::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(SignedArbitratingLock<S>, S: Signatures);

/// Provides Alice's daemon with the signature on the unsigned [`Punishable`] transaction, ready
/// for broadcast.
///
/// [`Punishable`]: crate::transaction::Punishable
#[derive(Debug, Clone, Display)]
#[display(fully_signed_punish_fmt)]
pub struct FullySignedPunish<T>
where
    T: Signatures + Onchain,
{
    pub punish: T::PartialTransaction,
    pub punish_sig: T::Signature,
}

fn fully_signed_punish_fmt<T>(b: &FullySignedPunish<T>) -> String
where
    T: Signatures + Onchain,
{
    format!(
        "Punish partial: {:?}, Punish signature: {}",
        b.punish, b.punish_sig
    )
}

impl<T> Encodable for FullySignedPunish<T>
where
    T: Signatures + Onchain,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.punish.as_canonical_bytes().consensus_encode(s)?;
        Ok(len + self.punish_sig.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<T> Decodable for FullySignedPunish<T>
where
    T: Signatures + Onchain,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            punish: T::PartialTransaction::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish_sig: T::Signature::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(FullySignedPunish<T>, T: Signatures + Onchain);
