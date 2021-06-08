//! A bundle is an aggregate of 1 or more datum generally related to each others.
//!
//! Datum are succinct and are used to convey atomic chunk of data (datum) between clients and
//! daemons. Bundles are used during the different steps of the swap by both Alice and Bob.

use crate::blockchain::{Address, Fee, FeeStrategy, Onchain, Timelock};
use crate::crypto::{self, Keys, SharedKeyId, SharedPrivateKeys, Signatures, TaggedElement};
use crate::protocol_message;
use crate::swap::Swap;
use strict_encoding::{StrictDecode, StrictEncode};

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
#[derive(Debug, Clone)]
pub struct AliceParameters<Ctx: Swap> {
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    pub punish: <Ctx::Ar as Keys>::PublicKey,
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey>>,
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey>>,
    pub destination_address: <Ctx::Ar as Address>::Address,
    pub proof: Ctx::Proof,
    pub cancel_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub punish_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub fee_strategy: Option<FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>>,
}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
#[derive(Debug, Clone)]
pub struct BobParameters<Ctx: Swap> {
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey>>,
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey>>,
    pub refund_address: <Ctx::Ar as Address>::Address,
    pub proof: Ctx::Proof,
    pub cancel_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub punish_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    pub fee_strategy: Option<FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>>,
}

/// Provides daemon with a signature on the unsigned cancel (d) transaction. Two signature are
/// needed, one come from the protocol message [`CoreArbitratingSetup`] and the second from the
/// [`RefundProcedureSignatures`].
///
/// [`CoreArbitratingSetup`]: protocol_message::CoreArbitratingSetup
/// [`RefundProcedureSignatures`]: protocol_message::RefundProcedureSignatures
#[derive(Debug, Clone)]
pub struct CosignedArbitratingCancel<S>
where
    S: Signatures,
{
    pub cancel_sig: S::Signature,
}

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

/// Provides Bob's daemon the funding transaction for building the core arbritrating transactions.
#[derive(Debug, Clone)]
pub struct FundingTransaction<T>
where
    T: Onchain,
{
    pub funding: T::Transaction,
}

/// Provides Bob's daemon or Alice's clients the core set of arbritrating transactions.
#[derive(Debug, Clone)]
pub struct CoreArbitratingTransactions<T>
where
    T: Onchain,
{
    pub lock: T::PartialTransaction,
    pub cancel: T::PartialTransaction,
    pub refund: T::PartialTransaction,
}

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

/// Provides Bob's daemon or Alice's client with an adaptor signature for the unsigned buy (c)
/// transaction.
#[derive(Debug, Clone)]
pub struct SignedAdaptorBuy<T>
where
    T: Signatures + Onchain,
{
    pub buy: T::PartialTransaction,
    pub buy_adaptor_sig: T::AdaptorSignature,
}

/// Provides Alice's daemon or Bob's clients with the two signatures on the unsigned buy (c)
/// transaction.
#[derive(Debug, Clone)]
pub struct FullySignedBuy<S>
where
    S: Signatures,
{
    pub buy_sig: S::Signature,
    pub buy_adapted_sig: S::Signature,
}

/// Provides Alice's daemon or Bob's clients with a signature on the unsigned refund (e)
/// transaction.
#[derive(Debug, Clone)]
pub struct SignedAdaptorRefund<S>
where
    S: Signatures,
{
    pub refund_adaptor_sig: S::AdaptorSignature,
}

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

/// Provides Bob's daemon or Alice's clients with the two signatures on the unsigned refund (e)
/// transaction.
#[derive(Debug, Clone)]
pub struct FullySignedRefund<S>
where
    S: Signatures,
{
    pub refund_sig: S::Signature,
    pub refund_adapted_sig: S::Signature,
}

/// Provides Bob's daemon with the signature on the unsigned lock (b) transaction.
#[derive(Debug, Clone)]
pub struct SignedArbitratingLock<S>
where
    S: Signatures,
{
    pub lock_sig: S::Signature,
}

/// Provides Alice's daemon with the signature on the unsigned punish (f) transaction.
#[derive(Debug, Clone)]
pub struct FullySignedPunish<T>
where
    T: Signatures + Onchain,
{
    pub punish: T::PartialTransaction,
    pub punish_sig: T::Signature,
}
