//! Cryptographic type definitions and primitives supported in Farcaster

use std::error;
use std::fmt::Debug;

use thiserror::Error;

use crate::consensus::{self};
use crate::swap::Swap;

/// List of cryptographic errors that can be encountered when processing cryptographic operation
/// such as signatures, proofs, key derivation, or commitments.
#[derive(Error, Debug)]
pub enum Error {
    /// The key identifier is not supported and the key cannot be derived.
    #[error("The key identifier is not supported and the key cannot be derived")]
    UnsupportedKey,
    /// The signature does not pass the validation tests.
    #[error("The signature does not pass the validation")]
    InvalidSignature,
    /// The adaptor signature does not pass the validation tests.
    #[error("The adaptor signature does not pass the validation")]
    InvalidAdaptorSignature,
    /// The proof does not pass the validation tests.
    #[error("The proof does not pass the validation")]
    InvalidProof,
    /// The commitment does not match the given value.
    #[error("The commitment does not match the given value")]
    InvalidCommitment,
    /// Any cryptographic error not part of this list.
    #[error("Cryptographic error: {0}")]
    Other(Box<dyn error::Error + Send + Sync>),
}

impl Error {
    /// Creates a new cryptographic error of type other with an arbitrary payload.
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::Other(error.into())
    }

    /// Consumes the `Error`, returning its inner error (if any).
    ///
    /// If this [`enum@Error`] was constructed via [`new`] then this function will return [`Some`],
    /// otherwise it will return [`None`].
    ///
    /// [`new`]: Error::new
    ///
    pub fn into_inner(self) -> Option<Box<dyn error::Error + Send + Sync>> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyType<Ctx>
where
    Ctx: Swap,
{
    PublicArbitrating(<Ctx::Ar as Keys>::PublicKey),
    PublicAccordant(<Ctx::Ac as Keys>::PublicKey),
    SharedPrivateKeys(<Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey),
}

impl<Ctx> KeyType<Ctx>
where
    Ctx: Swap,
{
    pub fn try_into_arbitrating_pubkey(
        &self,
    ) -> Result<<Ctx::Ar as Keys>::PublicKey, consensus::Error> {
        match self {
            KeyType::PublicArbitrating(key) => Ok(key.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_accordant_pubkey(
        &self,
    ) -> Result<<Ctx::Ac as Keys>::PublicKey, consensus::Error> {
        match self {
            KeyType::PublicAccordant(key) => Ok(key.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_shared_private(
        &self,
    ) -> Result<<Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey, consensus::Error> {
        match self {
            KeyType::SharedPrivateKeys(key) => Ok(key.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            KeyType::PublicArbitrating(key) => <Ctx::Ar as Keys>::as_bytes(&key),
            KeyType::PublicAccordant(key) => <Ctx::Ac as Keys>::as_bytes(&key),
            KeyType::SharedPrivateKeys(key) => <Ctx::Ac as SharedPrivateKeys>::as_bytes(&key),
        }
    }
}

/// Type of signatures
#[derive(Clone, Debug)]
pub enum SignatureType<S>
where
    S: Signatures,
{
    Adaptor(S::AdaptorSignature),
    Adapted(S::Signature),
    Regular(S::Signature),
}

impl<S> SignatureType<S>
where
    S: Signatures,
{
    pub fn try_into_adaptor(&self) -> Result<S::AdaptorSignature, consensus::Error> {
        match self {
            SignatureType::Adaptor(sig) => Ok(sig.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_adapted(&self) -> Result<S::Signature, consensus::Error> {
        match self {
            SignatureType::Adapted(sig) => Ok(sig.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_regular(&self) -> Result<S::Signature, consensus::Error> {
        match self {
            SignatureType::Regular(sig) => Ok(sig.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ArbitratingKeyId {
    Fund,
    Buy,
    Cancel,
    Refund,
    Punish,
    Extra(u16),
}

#[derive(Debug, Clone, Copy)]
pub enum AccordantKeyId {
    Spend,
    Extra(u16),
}

#[derive(Debug, Clone, Copy)]
pub struct SharedKeyId(u16);

impl SharedKeyId {
    pub fn new(id: u16) -> Self {
        Self(id)
    }
}

/// This trait is required for blockchains to fix the concrete cryptographic key types. The public
/// key associated type is shared across the network.
pub trait Keys {
    /// Private key type given the blockchain and the crypto engine.
    type PrivateKey;

    /// Public key type given the blockchain and the crypto engine.
    type PublicKey: Clone + PartialEq + Debug;

    /// Get the bytes from the public key.
    fn as_bytes(pubkey: &Self::PublicKey) -> Vec<u8>;

    fn extra_keys() -> Vec<u16>;
}

/// This trait is required for blockchains for fixing the potential shared private key send over
/// the network.
pub trait SharedPrivateKeys {
    /// A shareable private key type used to parse non-transparent blockchain
    type SharedPrivateKey: Clone + PartialEq + Debug;

    /// Get the bytes from the shared private key.
    fn as_bytes(privkey: &Self::SharedPrivateKey) -> Vec<u8>;

    fn shared_keys() -> Vec<SharedKeyId>;
}

/// This trait is required for blockchains for fixing the commitment types of the keys and
/// parameters that must go through the commit/reveal scheme at the beginning of the protocol.
pub trait Commitment {
    /// Commitment type used in the commit/reveal scheme during swap parameters setup.
    type Commitment: Clone + PartialEq + Eq + Debug;
}

/// This trait is required for arbitrating blockchains for defining the types of messages,
/// signatures and adaptor signatures used in the cryptographic operation such as signing/verifying
/// signatures and adaptor signatures.
pub trait Signatures {
    /// Type of the message passed to sign or adaptor sign methods, transactions will produce
    /// messages that will be passed to these methods.
    type Message: Clone + Debug;

    /// Defines the signature format for the arbitrating blockchain.
    type Signature: Clone + Debug;

    /// Defines the adaptor signature format for the arbitrating blockchain. Adaptor signature may
    /// have a different format from the signature depending on the cryptographic primitives used.
    type AdaptorSignature: Clone + Debug;
}

pub trait Wallet<ArPublicKey, AcPublicKey, ArSharedKey, AcSharedKey, Proof>:
    GenerateKey<ArPublicKey, ArbitratingKeyId>
    + GenerateKey<AcPublicKey, AccordantKeyId>
    + ProveCrossGroupDleq<ArPublicKey, AcPublicKey, Proof>
    + GenerateSharedKey<ArSharedKey>
    + GenerateSharedKey<AcSharedKey>
{
}

pub trait GenerateKey<PublicKey, KeyIds> {
    /// Retreive a specific public key by its key id. If the key cannot be derived the
    /// implementation must return an [`Error::UnsupportedKey`]
    fn get_pubkey(&self, key_id: KeyIds) -> Result<PublicKey, Error>;
}

pub trait GenerateSharedKey<SharedKey> {
    /// Retreive a specific shared private key by its key id. If the key cannot be derived the
    /// implementation must return an [`Error::UnsupportedKey`]
    fn get_shared_key(&self, key_id: SharedKeyId) -> Result<SharedKey, Error>;
}

pub trait Sign<PublicKey, PrivateKey, Message, Signature, AdaptorSignature> {
    /// Sign the message with the corresponding private key identified by the provided public key.
    fn sign_with_key(&self, key: &PublicKey, msg: Message) -> Result<Signature, Error>;

    /// Verify a signature for a given message with the provided public key.
    fn verify_signature(&self, key: &PublicKey, msg: Message, sig: &Signature)
        -> Result<(), Error>;

    /// Sign the message with the corresponding private key identified by the provided public key
    /// and encrypt it (create an adaptor signature) with the provided adaptor public key.
    fn adaptor_sign_with_key(
        &self,
        key: &PublicKey,
        adaptor: &PublicKey,
        msg: Message,
    ) -> Result<AdaptorSignature, Error>;

    /// Verify a adaptor signature for a given message with the provided public key and the public
    /// adaptor key.
    fn verify_adaptor_signature(
        &self,
        key: &PublicKey,
        adaptor: &PublicKey,
        msg: Message,
        sig: &AdaptorSignature,
    ) -> Result<(), Error>;

    /// Finalize an adaptor signature (decrypt the signature) into an adapted signature (decrypted
    /// signatures) with the corresponding private key identified by the provided public key.
    fn adapt_signature(&self, key: &PublicKey, sig: AdaptorSignature) -> Result<Signature, Error>;

    /// Recover the encryption key based on the adaptor signature and the decrypted signature.
    fn recover_key(&self, sig: Signature, adapted_sig: AdaptorSignature) -> PrivateKey;
}

pub trait Commit<Commitment: Eq> {
    /// Provides a generic method to commit to any value referencable as stream of bytes.
    fn commit_to<T: AsRef<[u8]>>(&self, value: T) -> Commitment;

    /// Validate the equality between a value and a commitment, return ok if the value commits to
    /// the same commitment's value.
    fn validate<T: AsRef<[u8]>>(&self, value: T, commitment: Commitment) -> Result<(), Error> {
        if self.commit_to(value) == commitment {
            Ok(())
        } else {
            Err(Error::InvalidCommitment)
        }
    }
}

pub trait ProveCrossGroupDleq<Adaptor, PublicSpendKey, Proof> {
    /// Generate the proof and the two public keys: the arbitrating public key, also called the
    /// adaptor public key, and the accordant public spend key.
    fn generate(&self) -> Result<(PublicSpendKey, Adaptor, Proof), Error>;

    /// Project the accordant sepnd secret key over the arbitrating curve to get the public key
    /// used as the adaptor public key.
    fn project_over(&self) -> Result<Adaptor, Error>;

    /// Verify the proof given the two public keys: the accordant spend public key and the
    /// arbitrating adaptor public key.
    fn verify(
        &self,
        public_spend: &PublicSpendKey,
        adaptor: &Adaptor,
        proof: Proof,
    ) -> Result<(), Error>;
}
