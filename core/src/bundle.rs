//! A bundle is an aggregate of 1 or more datum generally related to each others.
//!
//! Datum are succinct and are used to convey atomic chunk of data (datum) between clients and
//! daemons. Bundles are used during the different steps of the swap by both Alice and Bob.

use crate::blockchain::Onchain;
use crate::crypto::Signatures;
use crate::datum;
use crate::swap::Swap;
use strict_encoding::{StrictDecode, StrictEncode};

pub trait Bundle: StrictDecode + StrictEncode {}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct AliceParameters<Ctx: Swap> {
    pub buy: datum::Key<Ctx>,
    pub cancel: datum::Key<Ctx>,
    pub refund: datum::Key<Ctx>,
    pub punish: datum::Key<Ctx>,
    pub adaptor: datum::Key<Ctx>,
    pub destination_address: datum::Parameter<Ctx::Ar>,
    pub view: datum::Key<Ctx>,
    pub spend: datum::Key<Ctx>,
    pub proof: datum::Proof<Ctx>,
    pub cancel_timelock: Option<datum::Parameter<Ctx::Ar>>,
    pub punish_timelock: Option<datum::Parameter<Ctx::Ar>>,
    pub fee_strategy: Option<datum::Parameter<Ctx::Ar>>,
}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct BobParameters<Ctx: Swap> {
    pub buy: datum::Key<Ctx>,
    pub cancel: datum::Key<Ctx>,
    pub refund: datum::Key<Ctx>,
    pub adaptor: datum::Key<Ctx>,
    pub refund_address: datum::Parameter<Ctx::Ar>,
    pub view: datum::Key<Ctx>,
    pub spend: datum::Key<Ctx>,
    pub proof: datum::Proof<Ctx>,
    pub cancel_timelock: Option<datum::Parameter<Ctx::Ar>>,
    pub punish_timelock: Option<datum::Parameter<Ctx::Ar>>,
    pub fee_strategy: Option<datum::Parameter<Ctx::Ar>>,
}

/// Provides daemon with a signature on the unsigned cancel (d) transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct CosignedArbitratingCancel<S>
where
    S: Signatures,
{
    pub cancel_sig: datum::Signature<S>,
}

impl<S> Bundle for CosignedArbitratingCancel<S> where S: Signatures {}

/// Provides Bob's daemon the funding transaction for building the core arbritrating transactions.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct FundingTransaction<T>
where
    T: Onchain,
{
    pub funding: datum::Transaction<T>,
}

impl<T> Bundle for FundingTransaction<T> where T: Onchain {}

/// Provides Bob's daemon or Alice's clients the core set of arbritrating transactions.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct CoreArbitratingTransactions<T>
where
    T: Onchain,
{
    pub lock: datum::Transaction<T>,
    pub cancel: datum::Transaction<T>,
    pub refund: datum::Transaction<T>,
}

impl<T> Bundle for CoreArbitratingTransactions<T> where T: Onchain {}

/// Provides Bob's daemon or Alice's client with an adaptor signature for the unsigned buy (c)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedAdaptorBuy<S>
where
    S: Signatures,
{
    pub buy_adaptor_sig: datum::Signature<S>,
}

impl<S> Bundle for SignedAdaptorBuy<S> where S: Signatures {}

/// Provides Alice's daemon or Bob's clients with the two signatures on the unsigned buy (c)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct FullySignedBuy<S>
where
    S: Signatures,
{
    pub buy_sig: datum::Signature<S>,
    pub buy_adapted_sig: datum::Signature<S>,
}

impl<S> Bundle for FullySignedBuy<S> where S: Signatures {}

/// Provides Alice's daemon or Bob's clients with a signature on the unsigned refund (e)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedAdaptorRefund<S>
where
    S: Signatures,
{
    pub refund_adaptor_sig: datum::Signature<S>,
}

impl<S> Bundle for SignedAdaptorRefund<S> where S: Signatures {}

/// Provides Bob's daemon or Alice's clients with the two signatures on the unsigned refund (e)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct FullySignedRefund<S>
where
    S: Signatures,
{
    pub refund_sig: datum::Signature<S>,
    pub refund_adapted_sig: datum::Signature<S>,
}

impl<S> Bundle for FullySignedRefund<S> where S: Signatures {}

/// Provides Bob's daemon with the signature on the unsigned lock (b) transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedArbitratingLock<S>
where
    S: Signatures,
{
    pub lock_sig: datum::Signature<S>,
}

impl<S> Bundle for SignedArbitratingLock<S> where S: Signatures {}

/// Provides Alice's daemon with the signature on the unsigned punish (f) transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedArbitratingPunish<S>
where
    S: Signatures,
{
    pub punish_sig: datum::Signature<S>,
}

impl<S> Bundle for SignedArbitratingPunish<S> where S: Signatures {}
