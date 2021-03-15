//! A bundle is an aggregate of 1 or more datum generally related to each others.
//!
//! Datum are succinct and are used to convey atomic chunk of data (datum) between clients and
//! daemons. Bundles are used during the different steps of the swap by both Alice and Bob.

use crate::blockchain::Fee;
use crate::datum;
use crate::role::{Accordant, Arbitrating};

pub trait Bundle {}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
pub struct AliceSessionParams<Ar, Ac>
where
    Ar: Arbitrating + Fee,
    Ac: Accordant,
{
    pub buy: datum::Key<Ar, Ac>,
    pub cancel: datum::Key<Ar, Ac>,
    pub refund: datum::Key<Ar, Ac>,
    pub punish: datum::Key<Ar, Ac>,
    pub adaptor: datum::Key<Ar, Ac>,
    pub destination_address: datum::Parameter<Ar>,
    pub view: datum::Key<Ar, Ac>,
    pub spend: datum::Key<Ar, Ac>,
    pub proof: datum::Proof<Ar, Ac>,
    pub cancel_timelock: datum::Parameter<Ar>,
    pub punish_timelock: datum::Parameter<Ar>,
    pub fee_strategy: datum::Parameter<Ar>,
}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
pub struct BobSessionParams<Ar, Ac>
where
    Ar: Arbitrating + Fee,
    Ac: Accordant,
{
    pub buy: datum::Key<Ar, Ac>,
    pub cancel: datum::Key<Ar, Ac>,
    pub refund: datum::Key<Ar, Ac>,
    pub adaptor: datum::Key<Ar, Ac>,
    pub refund_address: datum::Parameter<Ar>,
    pub view: datum::Key<Ar, Ac>,
    pub spend: datum::Key<Ar, Ac>,
    pub proof: datum::Proof<Ar, Ac>,
    pub cancel_timelock: datum::Parameter<Ar>,
    pub punish_timelock: datum::Parameter<Ar>,
    pub fee_strategy: datum::Parameter<Ar>,
}

/// Provides daemon with a signature on the unsigned cancel (d) transaction.
pub struct CosignedArbitratingCancel<Ar>
where
    Ar: Arbitrating,
{
    /// The `Ac|Bc` `cancel (d)` signature
    pub cancel_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for CosignedArbitratingCancel<Ar> where Ar: Arbitrating {}

/// Provides Bob's daemon or Alice's clients the core set of arbritrating transactions.
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
pub struct SignedAdaptorBuy<Ar>
where
    Ar: Arbitrating,
{
    pub buy_adaptor_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedAdaptorBuy<Ar> where Ar: Arbitrating {}

/// Provides Alice's daemon or Bob's clients with the two signatures on the unsigned buy (c)
/// transaction.
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
pub struct SignedAdaptorRefund<Ar>
where
    Ar: Arbitrating,
{
    pub refund_adaptor_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedAdaptorRefund<Ar> where Ar: Arbitrating {}

/// Provides Bob's daemon or Alice's clients with the two signatures on the unsigned refund (e)
/// transaction.
pub struct FullySignedRefund<Ar>
where
    Ar: Arbitrating,
{
    pub refund_sig: datum::Signature<Ar>,
    pub refund_adapted_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for FullySignedRefund<Ar> where Ar: Arbitrating {}

/// Provides Bob's daemon with the signature on the unsigned lock (b) transaction.
pub struct SignedArbitratingLock<Ar>
where
    Ar: Arbitrating,
{
    pub lock_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedArbitratingLock<Ar> where Ar: Arbitrating {}

/// Provides Alice's daemon with the signature on the unsigned punish (f) transaction.
pub struct SignedArbitratingPunish<Ar>
where
    Ar: Arbitrating,
{
    pub punish_sig: datum::Signature<Ar>,
}

impl<Ar> Bundle for SignedArbitratingPunish<Ar> where Ar: Arbitrating {}