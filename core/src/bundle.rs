//! A bundle is an aggregate of 1 or more datum generally related to each others.
//!
//! Datum are succinct and are used to convey atomic chunk of data (datum) between clients and
//! daemons. Bundles are used during the different steps of the swap by both Alice and Bob.

use crate::datum;
use crate::role::Arbitrating;
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
pub struct CosignedArbitratingCancel<Ar>
where
    Ar: Arbitrating,
{
    /// The `Ac|Bc` `cancel (d)` signature
    pub cancel_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for CosignedArbitratingCancel<Ar> where Ar: Arbitrating {}

/// Provides Bob's daemon or Alice's clients the core set of arbritrating transactions.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct CoreArbitratingTransactions<Ar>
where
    Ar: Arbitrating,
{
    pub lock: datum::Transaction<Ar>,
    pub cancel: datum::Transaction<Ar>,
    pub refund: datum::Transaction<Ar>,
}

/// Provides Bob's daemon or Alice's client with an adaptor signature for the unsigned buy (c)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedAdaptorBuy<Ar>
where
    Ar: Arbitrating,
{
    pub buy_adaptor_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedAdaptorBuy<Ar> where Ar: Arbitrating {}

/// Provides Alice's daemon or Bob's clients with the two signatures on the unsigned buy (c)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct FullySignedBuy<Ar>
where
    Ar: Arbitrating,
{
    pub buy_sig: datum::Signature<Ar>,
    pub buy_adapted_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for FullySignedBuy<Ar> where Ar: Arbitrating {}

/// Provides Alice's daemon or Bob's clients with a signature on the unsigned refund (e)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedAdaptorRefund<Ar>
where
    Ar: Arbitrating,
{
    pub refund_adaptor_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedAdaptorRefund<Ar> where Ar: Arbitrating {}

/// Provides Bob's daemon or Alice's clients with the two signatures on the unsigned refund (e)
/// transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct FullySignedRefund<Ar>
where
    Ar: Arbitrating,
{
    pub refund_sig: datum::Signature<Ar>,
    pub refund_adapted_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for FullySignedRefund<Ar> where Ar: Arbitrating {}

/// Provides Bob's daemon with the signature on the unsigned lock (b) transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedArbitratingLock<Ar>
where
    Ar: Arbitrating,
{
    pub lock_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedArbitratingLock<Ar> where Ar: Arbitrating {}

/// Provides Alice's daemon with the signature on the unsigned punish (f) transaction.
#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct SignedArbitratingPunish<Ar>
where
    Ar: Arbitrating,
{
    pub punish_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedArbitratingPunish<Ar> where Ar: Arbitrating {}
