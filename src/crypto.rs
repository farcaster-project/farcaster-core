//! Cryptographic type definitions and primitives supported in Farcaster

use crate::role::{Accordant, Arbitrating};

pub enum Key<Ar, Ac>
where
    Ar: Keys,
    Ac: Keys,
{
    AliceBuy(Ar::PublicKey),
    AliceCancel(Ar::PublicKey),
    AliceRefund(Ar::PublicKey),
    AlicePunish(Ar::PublicKey),
    AliceAdaptor(Ar::PublicKey),
    AliceSpend(Ac::PublicKey),
    AlicePrivateView(Ac::PrivateKey),
    BobFund(Ar::PublicKey),
    BobBuy(Ar::PublicKey),
    BobCancel(Ar::PublicKey),
    BobRefund(Ar::PublicKey),
    BobAdaptor(Ar::PublicKey),
    BobSpend(Ac::PublicKey),
    BobPrivateView(Ac::PrivateKey),
}

pub enum Signature<Ar>
where
    Ar: Signatures,
{
    Adaptor(Ar::AdaptorSignature),
    Adapted(Ar::Signature),
    Regular(Ar::Signature),
}

pub enum Proof<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    CrossGroupDLEQ(Box<dyn CrossGroupDLEQ<Ar, Ac>>),
}

/// This trait is defined for blockchains once per cryptographic engine wanted and allow a
/// blockchain to use different cryptographic types depending on the engine used.
///
/// E.g. ECDSA and Schnorr signature in Bitcoin are stored/parsed differently as Schnorr has been
/// optimized further than ECDSA at the begining of Bitcoin.
pub trait Keys {
    /// Private key type given the blockchain and the crypto engine
    type PrivateKey;

    /// Public key type given the blockchain and the crypto engine
    type PublicKey;
}

pub trait Commitment {
    /// Commitment type given the blockchain and the crypto engine
    type Commitment;
}

pub trait Signatures {
    /// Defines the signature format for the arbitrating blockchain
    type Signature;

    /// Defines the adaptor signature format for the arbitrating blockchain. Adaptor signature may
    /// have a different format from the signature depending on the cryptographic engine used.
    type AdaptorSignature;
}

/// Defines a type of cryptography used inside arbitrating transactions to validate the
/// transactions at the blockchain level and transfer the secrets.
pub trait CryptoEngine {}

/// Define a prooving system to link to blockchain cryptographic group parameters.
pub trait CrossGroupDLEQ<Ar, Ac>
where
    Ar: Curve,
    Ac: Curve,
    Ar::Curve: PartialEq<Ac::Curve>,
    Ac::Curve: PartialEq<Ar::Curve>,
{
}

/// Eliptic curve ed25519 or secp256k1
pub trait Curve {
    type Curve;
}

/// Defines the means of arbitration, such as ECDSAScripts, TrSchnorrScripts and TrMuSig2
pub trait Arbitration {
    type Arbitration;
}

enum Arbitrator {
    ECDSAScripts(ECDSAScripts),
    TrSchnorrScripts(TrSchnorrScripts),
    TrMusig2(TrMuSig2),
}

/// Uses ECDSA signatures inside the scripting layer of the arbitrating blockchain.
pub struct ECDSAScripts;

/// Uses Schnorr signatures inside the scripting layer of the arbitrating blockchain.
pub struct TrSchnorrScripts;

/// Uses MuSig2 Schnorr off-chain multi-signature protocol to sign for a regular public key at the
/// blockchain transaction layer.
pub struct TrMuSig2;
