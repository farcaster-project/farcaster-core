//! A bundle is an aggregate of 1 or more datum generally related to each others.
//!
//! Datum are succinct and are used to convey atomic chunk of data (datum) between clients and
//! daemons. Bundles are used during the different steps of the swap by both Alice and Bob.

use crate::blockchain::{Fee, FeeStrategy};
use crate::crypto::{Crypto, CryptoEngine};
use crate::datum;
use crate::role::{Accordant, Arbitrating};

pub trait Bundle {}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
pub struct AliceSessionParams<Ar, Ac, C, S>
where
    Ar: Arbitrating + Crypto<C> + Fee<S>,
    Ac: Accordant,
    C: CryptoEngine,
    S: FeeStrategy,
{
    pub buy: datum::Key<Ar, Ac, C>,
    pub cancel: datum::Key<Ar, Ac, C>,
    pub refund: datum::Key<Ar, Ac, C>,
    pub punish: datum::Key<Ar, Ac, C>,
    pub adaptor: datum::Key<Ar, Ac, C>,
    pub destination_address: datum::Parameter<Ar, S>,
    pub view: datum::Key<Ar, Ac, C>,
    pub spend: datum::Key<Ar, Ac, C>,
    pub proof: datum::Proof<Ar, Ac>,
    pub cancel_timelock: datum::Parameter<Ar, S>,
    pub punish_timelock: datum::Parameter<Ar, S>,
    pub fee_strategy: datum::Parameter<Ar, S>,
}

/// Provides the (counter-party) daemon with all the information required for the initialization
/// step of a swap.
pub struct BobSessionParams<Ar, Ac, C, S>
where
    Ar: Arbitrating + Crypto<C> + Fee<S>,
    Ac: Accordant,
    C: CryptoEngine,
    S: FeeStrategy,
{
    pub buy: datum::Key<Ar, Ac, C>,
    pub cancel: datum::Key<Ar, Ac, C>,
    pub refund: datum::Key<Ar, Ac, C>,
    pub adaptor: datum::Key<Ar, Ac, C>,
    pub refund_address: datum::Parameter<Ar, S>,
    pub view: datum::Key<Ar, Ac, C>,
    pub spend: datum::Key<Ar, Ac, C>,
    pub proof: datum::Proof<Ar, Ac>,
    pub cancel_timelock: datum::Parameter<Ar, S>,
    pub punish_timelock: datum::Parameter<Ar, S>,
    pub fee_strategy: datum::Parameter<Ar, S>,
}

/// Provides daemon with a signature on the unsigned cancel (d) transaction.
pub struct CosignedArbitratingCancel<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Ac|Bc` `cancel (d)` signature
    pub cancel_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for CosignedArbitratingCancel<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

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
pub struct SignedAdaptorBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub buy_adaptor_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for SignedAdaptorBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Alice's daemon or Bob's clients with the two signatures on the unsigned buy (c)
/// transaction.
pub struct FullySignedBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub buy_sig: datum::Signature<Ar, C>,
    pub buy_adapted_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for FullySignedBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Alice's daemon or Bob's clients with a signature on the unsigned refund (e)
/// transaction.
pub struct SignedAdaptorRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub refund_adaptor_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for SignedAdaptorRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Bob's daemon or Alice's clients with the two signatures on the unsigned refund (e)
/// transaction.
pub struct FullySignedRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub refund_sig: datum::Signature<Ar, C>,
    pub refund_adapted_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for FullySignedRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Bob's daemon with the signature on the unsigned lock (b) transaction.
pub struct SignedArbitratingLock<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub lock_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for SignedArbitratingLock<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Alice's daemon with the signature on the unsigned punish (f) transaction.
pub struct SignedArbitratingPunish<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub punish_sig: datum::Signature<Ar, C>,
}

impl<Ar, C> Bundle for SignedArbitratingPunish<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}
