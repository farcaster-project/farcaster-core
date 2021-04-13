//! Cryptographic type definitions and primitives supported in Farcaster

use std::fmt::Debug;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::role::{Acc, Accordant, Arbitrating, Blockchain};
use crate::swap::Swap;

/// Keys used during the swap by both role
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub enum Key<Ctx: Swap> {
    Alice(AliceKey<Ctx>),
    Bob(BobKey<Ctx>),
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub enum AliceKey<Ctx: Swap> {
    Buy(<Ctx::Ar as Keys>::PublicKey),
    Cancel(<Ctx::Ar as Keys>::PublicKey),
    Refund(<Ctx::Ar as Keys>::PublicKey),
    Punish(<Ctx::Ar as Keys>::PublicKey),
    Adaptor(<Ctx::Ar as Keys>::PublicKey),
    Spend(<Ctx::Ac as Keys>::PublicKey),
    PrivateView(<Ctx::Ac as SharedPrivateKeys<Acc>>::SharedPrivateKey),
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub enum BobKey<Ctx: Swap> {
    Fund(<Ctx::Ar as Keys>::PublicKey),
    Buy(<Ctx::Ar as Keys>::PublicKey),
    Cancel(<Ctx::Ar as Keys>::PublicKey),
    Refund(<Ctx::Ar as Keys>::PublicKey),
    Adaptor(<Ctx::Ar as Keys>::PublicKey),
    Spend(<Ctx::Ac as Keys>::PublicKey),
    PrivateView(<Ctx::Ac as SharedPrivateKeys<Acc>>::SharedPrivateKey),
}

/// Type of signatures
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub enum SignatureType<S>
where
    S: Signatures,
{
    Adaptor(S::AdaptorSignature),
    Adapted(S::Signature),
    Regular(S::Signature),
}

#[derive(Debug, Clone, Copy)]
pub enum ArbitratingKey {
    Fund,
    Buy,
    Cancel,
    Refund,
    Punish,
    // TODO special case as it is the same as Spend but on the "other" (can be the same tho) group
    //Adaptor,
}

#[derive(Debug, Clone, Copy)]
pub enum AccordantKey {
    Spend,
}

#[derive(Debug, Clone, Copy)]
pub enum SharedPrivateKey {
    View,
}

/// Generate the keys for a blockchain from a master seed.
pub trait FromSeed<T>: Keys
where
    T: Blockchain,
{
    /// Type of seed received as input
    type Seed;

    fn get_pubkey(seed: &Self::Seed, key_type: T::KeyList) -> Self::PublicKey;
}

/// This trait is required for blockchains to fix the concrete cryptographic key types. The public
/// key associated type is shared across the network.
pub trait Keys {
    /// Private key type given the blockchain and the crypto engine
    type PrivateKey;

    /// Public key type given the blockchain and the crypto engine
    type PublicKey: Clone + Debug + StrictEncode + StrictDecode;
}

/// This trait is required for blockchains for fixing the potential shared private key send over
/// the network.
pub trait SharedPrivateKeys<T>: FromSeed<T>
where
    T: Blockchain,
{
    /// A shareable private key type used to parse non-transparent blockchain
    type SharedPrivateKey: Clone + Debug + StrictEncode + StrictDecode;

    fn get_shared_privkey(seed: &Self::Seed, key_type: SharedPrivateKey) -> Self::SharedPrivateKey;
}

/// This trait is required for blockchains for fixing the commitment types of the keys.
pub trait Commitment {
    /// Commitment type given the blockchain and the crypto engine
    type Commitment: Clone + Debug + StrictEncode + StrictDecode;

    // TODO transform/validate PubKey into commitment
}

/// This trait is required for arbitrating blockchains for fixing the types of signatures and
/// adaptor signatures.
pub trait Signatures {
    /// Defines the signature format for the arbitrating blockchain
    type Signature: Clone + Debug + StrictEncode + StrictDecode;

    /// Defines the adaptor signature format for the arbitrating blockchain. Adaptor signature may
    /// have a different format from the signature depending on the cryptographic primitives used.
    type AdaptorSignature: Clone + Debug + StrictEncode + StrictDecode;
}

/// Define a proving system to link two different blockchain cryptographic group parameters.
pub trait DleqProof<Ar, Ac>: Clone + Debug + StrictEncode + StrictDecode
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    fn generate(ac_seed: &<Ac as FromSeed<Acc>>::Seed) -> (Ac::PublicKey, Ar::PublicKey, Self);

    fn verify(spend: &Ac::PublicKey, adaptor: &Ar::PublicKey, proof: Self) -> bool;
}
