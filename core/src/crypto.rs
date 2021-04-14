//! Cryptographic type definitions and primitives supported in Farcaster

use std::fmt::Debug;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::role::{Accordant, Arbitrating};
use crate::swap::Swap;

/// Keys used during the swap by both role
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub enum Key<Ctx: Swap> {
    AliceBuy(<Ctx::Ar as Keys>::PublicKey),
    AliceCancel(<Ctx::Ar as Keys>::PublicKey),
    AliceRefund(<Ctx::Ar as Keys>::PublicKey),
    AlicePunish(<Ctx::Ar as Keys>::PublicKey),
    AliceAdaptor(<Ctx::Ar as Keys>::PublicKey),
    AliceSpend(<Ctx::Ac as Keys>::PublicKey),
    AlicePrivateView(<Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey),
    BobFund(<Ctx::Ar as Keys>::PublicKey),
    BobBuy(<Ctx::Ar as Keys>::PublicKey),
    BobCancel(<Ctx::Ar as Keys>::PublicKey),
    BobRefund(<Ctx::Ar as Keys>::PublicKey),
    BobAdaptor(<Ctx::Ar as Keys>::PublicKey),
    BobSpend(<Ctx::Ac as Keys>::PublicKey),
    BobPrivateView(<Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey),
}

/// Type of signatures
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub enum SignatureType<Ar>
where
    Ar: Signatures,
{
    Adaptor(Ar::AdaptorSignature),
    Adapted(Ar::Signature),
    Regular(Ar::Signature),
}

/// This trait is required for blockchains to fix the concrete cryptographic key types. The public
/// key associated type is shared across the network.
pub trait Keys: Commitment {
    /// Private key type given the blockchain and the crypto engine
    type PrivateKey;

    /// Public key type given the blockchain and the crypto engine
    type PublicKey: Clone + Debug + StrictEncode + StrictDecode;
}

/// This trait is required for blockchains for fixing the potential shared private key send over
/// the network.
pub trait SharedPrivateKeys {
    /// A shareable private key type used to parse non-transparent blockchain
    type SharedPrivateKey: Clone + Debug + StrictEncode + StrictDecode;
}

/// This trait is required for blockchains for fixing the commitment types of the keys.
pub trait Commitment {
    /// Commitment type given the blockchain and the crypto engine
    type Commitment: Clone + Debug + StrictEncode + StrictDecode;
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

/// Define a prooving system to link two different blockchain cryptographic group parameters.
pub trait DleqProof<Ar, Ac>: Clone + StrictEncode + StrictDecode
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    // TODO
}

///// Defines the means of arbitration, such as, e.g. for Bitcoin, SegWit v0 p2wsh or SegWit v1
///// Taproot Schnorr in scripts.
/////
///// This trait is implemented on arbitrating blockchins.
//pub trait Script {
//    /// Defines the script engine implementation to use for the arbitrating blockchain.
//    type Script: ScriptEngine;
//
//    // TODO
//}
//
///// Defines a type of cryptography used inside arbitrating transactions to validate the
///// transactions at the blockchain level and transfer the secrets.
//pub trait ScriptEngine {
//    // TODO
//}
//
///// Uses ECDSA signatures inside the scripting layer of the arbitrating blockchain.
//pub struct ECDSAScripts;
//
//impl ScriptEngine for ECDSAScripts {}
//
///// Uses Schnorr signatures inside the scripting layer of the arbitrating blockchain.
//pub struct TrSchnorrScripts;
//
///// Uses MuSig2 Schnorr off-chain multi-signature protocol to sign for a regular public key at the
///// blockchain transaction layer.
//pub struct TrMuSig2;
