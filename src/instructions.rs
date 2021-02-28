//! Farcaster instructions sent by client to daemon to instruct what to do next in the swap
//! process.

use crate::crypto::{Crypto, CryptoEngine};
use crate::roles::Arbitrating;

pub trait Instruction {}

/// Provides daemon with a signature on the unsigned `cancel (d)` transaction previously provided
/// by the daemon via `state digest`.
pub struct CosignedArbitratingCancel<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Ac|Bc` `cancel (d)` signature
    pub cancel_sig: Ar::Signature,
}

impl<Ar, C> Instruction for CosignedArbitratingCancel<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Bob's daemon with a signature on the unsigned `buy (c)` transaction previously
/// provided by the daemon via `state digest`.
pub struct SignedAdaptedBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Bb(Ta)` `buy (c)` adaptor signature
    pub buy_adaptor_sig: Ar::Signature,
}

impl<Ar, C> Instruction for SignedAdaptedBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Alice's daemon with the two signatures on the unsigned `buy (c)` transaction
/// previously provided by the daemon via `state digest`, ready to be broadcasted.
pub struct FullySignedBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Ab` `buy (c)` signature
    pub buy_sig: Ar::Signature,
    /// The decrypted `Bb(Ta)` `buy (c)` adaptor signature
    pub buy_adapted_sig: Ar::Signature,
}

impl<Ar, C> Instruction for FullySignedBuy<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Alice's daemon with a signature on the unsigned `refund (e)` transaction previously
/// provided by the daemon via `state digest`.
pub struct SignedAdaptedRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Ar(Tb)` `refund (e)` adaptor signature
    pub refund_adaptor_sig: Ar::Signature,
}

impl<Ar, C> Instruction for SignedAdaptedRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Bob's daemon with the two signatures on the unsigned `refund (e)` transaction
/// previously provided by the daemon via `state digest`, ready to be broadcasted.
pub struct FullySignedRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Br` `refund (e)` signature
    pub refund_sig: Ar::Signature,
    /// The decrypted `Ar(Tb)` `refund (e)` adaptor signature
    pub refund_adapted_sig: Ar::Signature,
}

impl<Ar, C> Instruction for FullySignedRefund<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Bob's daemon with the signature on the unsigned `lock (b)` transaction previously
/// provided by the daemon via `state digest`, ready to be broadcasted with this signature.
pub struct SignedArbitratingLock<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Bf` `lock (b)` signature for unlocking the funding
    pub lock_sig: Ar::Signature,
}

impl<Ar, C> Instruction for SignedArbitratingLock<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides Alice's daemon with the signature on the unsigned `punish (f)` transaction previously
/// provided by the daemon via `state digest`, ready to be broadcasted with this signature.
pub struct SignedArbitratingPunish<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Ap` `punish (f)` signature for unlocking the cancel transaction UTXO
    pub punish_sig: Ar::Signature,
}

impl<Ar, C> Instruction for SignedArbitratingPunish<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// Provides deamon the instruction to abort the swap, it is the daemon responsability to abort
/// accordingly to the current state swap. By transmitting latter feedback via `state digest`, the
/// client must be able to provide any missing signatures.
pub struct Abort {
    /// OPTIONAL: A code conveying the reason of the abort
    pub abort_code: Option<u16>,
}

impl Instruction for Abort {}

/// Provides deamon the instruction to follow the protocol swap, daemon can create locking steps
/// during the protocol execution and require client to acknoledge the execution progression.
pub struct Next {
    /// OPTIONAL: A code conveying the type of execution progression
    pub next_code: Option<u16>,
}

impl Instruction for Next {}
