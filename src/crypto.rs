//! Cryptographic types (keys, signatures, commitments, etc) and traits (commit, generate key,
//! sign, etc) used to create the generic framework for supporting multiple blockchains under the
//! same interface.

use std::convert::TryInto;
use std::error;
use std::fmt::{self, Debug};
use std::io;

use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};

/// List of cryptographic errors that can be encountered in cryptographic operations such as
/// signatures, proofs, key derivation, or commitments.
#[derive(Error, Debug)]
pub enum Error {
    /// The key identifier is not supported and the key cannot be derived.
    #[error("The key identifier is not supported and the key cannot be derived")]
    UnsupportedKey,
    /// The signature does not pass the validation tests.
    #[error("The signature does not pass the validation")]
    InvalidSignature,
    /// The adaptor key is not valid.
    #[error("The adaptor key is not valid")]
    InvalidAdaptorKey,
    /// The adaptor signature does not pass the validation tests.
    #[error("The adaptor signature does not pass the validation")]
    InvalidAdaptorSignature,
    /// The proof does not pass the validation tests.
    #[error("The proof does not pass the validation")]
    InvalidProof,
    /// The commitment does not match the given value.
    #[error("The commitment does not match the given value")]
    InvalidCommitment,
    /// SLIP10 error when manipulating extended secret keys.
    #[error("SLIP10 error: {0}")]
    Slip10(#[from] slip10::Error),
    /// Any cryptographic error not part of this list.
    #[error("Cryptographic error: {0}")]
    Other(Box<dyn error::Error + Send + Sync>),
}

impl Error {
    /// Creates a new cryptographic error of type [`Self::Other`] with an arbitrary payload.
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

/// Element `E` prefixed with a tag `T`. Used to tag content with some ids. Tag needs `Eq` to be
/// used in vectors or sets and identify the content. Tags can be [`ArbitratingKeyId`],
/// [`AccordantKeyId`] or any other type of identifiers.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct TaggedElement<T, E>
where
    T: Eq,
{
    tag: T,
    elem: E,
}

impl<T, E> TaggedElement<T, E>
where
    T: Eq,
{
    /// Create a new tagged element `E` with the tag `T`.
    pub fn new(tag: T, elem: E) -> Self {
        Self { tag, elem }
    }

    /// Returns the tag `T`.
    pub fn tag(&self) -> &T {
        &self.tag
    }

    /// Returns the element `E`.
    pub fn elem(&self) -> &E {
        &self.elem
    }
}

impl<T, E> fmt::Display for TaggedElement<T, E>
where
    T: Eq + fmt::Display,
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}: {}>", self.tag, self.elem)
    }
}

impl<T, E> Encodable for TaggedElement<T, E>
where
    T: Eq + Encodable,
    E: CanonicalBytes,
{
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let len = self.tag.consensus_encode(s)?;
        Ok(len + self.elem.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<T, E> Decodable for TaggedElement<T, E>
where
    T: Eq + Decodable,
    E: CanonicalBytes,
{
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let tag = T::consensus_decode(d)?;
        let elem = E::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?;
        Ok(TaggedElement { tag, elem })
    }
}

/// A vector of `T` tagged elements `E`.
pub type TaggedElements<T, E> = Vec<TaggedElement<T, E>>;

/// A vector of [`u16`] tagged keys of type `E`.
pub type TaggedExtraKeys<E> = Vec<TaggedElement<u16, E>>;

/// A vector of shared keys tagged with [`SharedKeyId`] of type `E`.
pub type TaggedSharedKeys<E> = Vec<TaggedElement<SharedKeyId, E>>;

/// List of all possible arbitrating keys as defined for the base protocol in the RFCs. Extra keys
/// can be defined with [`Self::Extra`] variant and an `u16` identifier. Those keys can be used for
/// extra off-chain protocol such as multi-signature or multi-party computation schemes.
#[derive(Debug, Clone, Copy, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum ArbitratingKeyId {
    /// Arbitrating key used to fund the [`Lockable`] transaction through [`Fundable`].
    ///
    /// [`Lockable`]: crate::transaction::Lockable
    /// [`Fundable`]: crate::transaction::Fundable
    Lock,
    /// Key used in the [`Buyable`] transaction.
    ///
    /// [`Buyable`]: crate::transaction::Buyable
    Buy,
    /// Key used in the [`Cancelable`] transaction.
    ///
    /// [`Cancelable`]: crate::transaction::Cancelable
    Cancel,
    /// Key used in the [`Refundable`] transaction.
    ///
    /// [`Refundable`]: crate::transaction::Refundable
    Refund,
    /// Key used in the [`Punishable`] transaction.
    ///
    /// [`Punishable`]: crate::transaction::Punishable
    Punish,
    /// Any other key used for extra off-chain protocol such as multi-signature or multi-party
    /// computation schemes. Contains its own identifier. The identifier must not conflict with
    /// defined identifiers in RFCs.
    Extra(u16),
}

/// Defines the base accordant key identifier [`Self::Spend`] and all possible extra keys with
/// [`Self::Extra`] variant containing the `u16` identifier.
#[derive(Debug, Clone, Copy, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum AccordantKeyId {
    /// Accordant bought/sold key over the arbitrating blockchain.
    Spend,
    /// Any other key needed in the context of an accordant blockchain. Contains its own
    /// identifier.  The identifier must not conflict with defined identifiers in RFCs.
    Extra(u16),
}

/// Identifier for shared private keys over the arbitrating and accordant blockchains. E.g. the
/// `view` key needed to parse the Monero blockchain is a shared private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct SharedKeyId(u16);

impl SharedKeyId {
    /// Create a new shared key identifier.
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the identifier value.
    pub fn id(&self) -> u16 {
        self.0
    }
}

impl Encodable for SharedKeyId {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for SharedKeyId {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self(u16::consensus_decode(d)?))
    }
}

fixed_hash::construct_fixed_hash!(
    /// Result of a keccak256 commitment.
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(crate = "serde_crate"),
    )]
    pub struct KeccakCommitment(32);
);

impl KeccakCommitment {
    /// Create a null commitment hash with all zeros.
    pub fn null_hash() -> Self {
        Self([0u8; 32])
    }

    /// Hash a stream of bytes with the Keccak-256 hash function.
    pub fn new(input: [u8; 32]) -> Self {
        Self(input)
    }
}

impl CanonicalBytes for KeccakCommitment {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        (*self).to_fixed_bytes().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(bytes.try_into().map_err(consensus::Error::new)?))
    }
}

/// Engine to produce and validate hash commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentEngine;

impl Commit<KeccakCommitment> for CommitmentEngine {
    fn commit_to<T: AsRef<[u8]>>(&self, value: T) -> KeccakCommitment {
        let mut out = [0u8; 32];
        let mut keccak = Keccak::v256();
        keccak.update(value.as_ref());
        keccak.finalize(&mut out);
        KeccakCommitment::new(out)
    }
}

/// Required for [`Arbitrating`] and [`Accordant`] blockchains to fix the cryptographic secret key
/// and public key types. The public key type is shared across the network and used in
/// transactions, the secret key type is used during signing operation, proofs, etc.
///
/// [`Arbitrating`]: crate::role::Arbitrating
/// [`Accordant`]: crate::role::Accordant
pub trait Keys {
    /// Secret key type used for signing and proving.
    type SecretKey;

    /// Public key type used in transactions.
    type PublicKey: Clone + PartialEq + Debug + fmt::Display + CanonicalBytes;

    /// Return a list of extra public key identifiers to use during the setup phase.
    fn extra_keys() -> Vec<u16>;
}

/// Required for [`Arbitrating`] and [`Accordant`] blockchains to fix the potential shared secret
/// keys send over the network. E.g. the private `view` key needed to parse the Monero blockchain.
///
/// [`Arbitrating`]: crate::role::Arbitrating
/// [`Accordant`]: crate::role::Accordant
pub trait SharedSecretKeys {
    /// Shareable secret key type used to parse, e.g., non-transparent blockchain.
    type SharedSecretKey: Clone + PartialEq + Debug + CanonicalBytes;

    /// Return a list of extra shared secret key identifiers to use during the setup phase.
    fn shared_keys() -> Vec<SharedKeyId>;
}

/// Trait required for [`Arbitrating`] blockchains to define the cryptographic message format to
/// sign, the signature format and adaptor signature format used in the cryptographic operations
/// such as signing and verifying signatures and adaptor signatures.
///
/// [`Arbitrating`]: crate::role::Arbitrating
pub trait Signatures {
    /// Type of the message passed to sign or adaptor sign methods, transactions will produce
    /// messages that will be passed to these methods.
    type Message: Clone + Debug;

    /// Defines the signature format for the arbitrating blockchain.
    type Signature: Clone + Debug + fmt::Display + CanonicalBytes;

    /// Defines the adaptor signature format for the arbitrating blockchain. Adaptor signature may
    /// have a different format from the signature depending on the cryptographic primitives used.
    type AdaptorSignature: Clone + Debug + fmt::Display + CanonicalBytes;
}

/// Meta trait regrouping all the needed trait combinaisons a key manager must implement. Used when
/// executing the protocol on [`Alice`] and [`Bob`] methods. This trait is auto-implemented for all
/// `T` meeting the requirements.
///
/// [`Alice`]: crate::role::Alice
/// [`Bob`]: crate::role::Bob
pub trait Wallet<ArPublicKey, AcPublicKey, ArSharedKey, AcSharedKey, Proof>:
    GenerateKey<ArPublicKey, ArbitratingKeyId>
    + GenerateKey<AcPublicKey, AccordantKeyId>
    + ProveCrossGroupDleq<ArPublicKey, AcPublicKey, Proof>
    + GenerateSharedKey<ArSharedKey>
    + GenerateSharedKey<AcSharedKey>
{
}

impl<T, ArPublicKey, AcPublicKey, ArSharedKey, AcSharedKey, Proof>
    Wallet<ArPublicKey, AcPublicKey, ArSharedKey, AcSharedKey, Proof> for T
where
    T: GenerateKey<ArPublicKey, ArbitratingKeyId>
        + GenerateKey<AcPublicKey, AccordantKeyId>
        + GenerateSharedKey<ArSharedKey>
        + GenerateSharedKey<AcSharedKey>
        + ProveCrossGroupDleq<ArPublicKey, AcPublicKey, Proof>,
{
}

/// Public key generator. Generic interface over `PublicKey`, the public key type, and `KeyId`, the
/// identifier, used to retreive public keys by their identifiers.
pub trait GenerateKey<PublicKey, KeyId> {
    /// Retreive a specific public key by its key id. If the key cannot be derived the
    /// implementation must return an [`Error::UnsupportedKey`], otherwise `Ok(PublicKey)` is
    /// returned.
    fn get_pubkey(&mut self, key_id: KeyId) -> Result<PublicKey, Error>;

    /// Return a vector of public keys matching the vector of key ids. Errors on the first key that
    /// can't be derived and return an [`Error::UnsupportedKey`].
    fn get_pubkeys(&mut self, key_ids: Vec<KeyId>) -> Result<Vec<PublicKey>, Error> {
        key_ids.into_iter().map(|id| self.get_pubkey(id)).collect()
    }
}

/// Private shared key generator. Generic interface over `SharedKey`, the private key type, used to
/// retreive private shared keys by their identifiers: [`SharedKeyId`].
pub trait GenerateSharedKey<SharedKey> {
    /// Retreive a specific shared private key by its key id. If the key cannot be derived the
    /// implementation must return an [`Error::UnsupportedKey`].
    fn get_shared_key(&mut self, key_id: SharedKeyId) -> Result<SharedKey, Error>;
}

// TODO give extra keys and/or shared keys in signing methods

/// Signature and adaptor signature generator and verifier. Produce and verify signatures and
/// adaptor sigantures based on public keys. Recover the private key through the complete
/// adaptor/adapted signature.
pub trait Sign<PublicKey, SecretKey, Message, Signature, AdaptorSignature> {
    /// Sign the message with the corresponding private key identified by the provided arbitrating
    /// key identifier.
    fn sign_with_key(&mut self, key: ArbitratingKeyId, msg: Message) -> Result<Signature, Error>;

    /// Verify a signature for a given message with the provided public key.
    fn verify_signature(&self, key: &PublicKey, msg: Message, sig: &Signature)
        -> Result<(), Error>;

    /// Sign the message with the corresponding private key identified by the provided arbitrating
    /// key identifier and encrypt it (create an adaptor signature) with the provided adaptor
    /// public key.
    fn adaptor_sign_with_key(
        &mut self,
        key: ArbitratingKeyId,
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
    /// signatures) with the corresponding private key identified by the provided accordant key
    /// identifier.
    fn adapt_signature(
        &mut self,
        key: AccordantKeyId,
        sig: AdaptorSignature,
    ) -> Result<Signature, Error>;

    /// Recover the encryption key based on the adaptor signature and the decrypted signature.
    fn recover_key(
        &self,
        adaptor_key: &PublicKey,
        sig: Signature,
        adapted_sig: AdaptorSignature,
    ) -> SecretKey;
}

/// Commitment generator and verifier. Generated commitments can be validated against candidates,
/// if correct the commit/reveal process is validated.
pub trait Commit<Commitment: Eq> {
    /// Provides a generic method to commit to any value referencable as stream of bytes.
    fn commit_to<T: AsRef<[u8]>>(&self, value: T) -> Commitment;

    /// Validate the equality between a candidate and a commitment, return `Ok(())` if the value
    /// commits to the same commitment's candidate, return [`Error::InvalidCommitment`]
    /// otherwise.
    fn validate<T: AsRef<[u8]>>(&self, candidate: T, commitment: Commitment) -> Result<(), Error> {
        if self.commit_to(candidate) == commitment {
            Ok(())
        } else {
            Err(Error::InvalidCommitment)
        }
    }
}

/// Proof generator and verifier for the cross-group projection of the accordant public spend key.
pub trait ProveCrossGroupDleq<Adaptor, PublicSpendKey, Proof> {
    /// Generate the proof and the two public keys: the arbitrating public key, also called the
    /// adaptor public key, and the accordant public spend key.
    fn generate(&mut self) -> Result<(PublicSpendKey, Adaptor, Proof), Error>;

    /// Project the accordant sepnd secret key over the arbitrating curve to get the public key
    /// used as the adaptor public key.
    fn project_over(&mut self) -> Result<Adaptor, Error>;

    /// Verify the proof given the two public keys: the accordant spend public key and the
    /// arbitrating adaptor public key.
    fn verify(
        &mut self,
        public_spend: &PublicSpendKey,
        adaptor: &Adaptor,
        proof: Proof,
    ) -> Result<(), Error>;
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub mod slip10 {
    //! SLIP-10 implementation for secp256k1 and ed25519. This implementation does not support NIST
    //! P-256 curve.

    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    use bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
    use bitcoin::secp256k1::{self, Secp256k1};

    use thiserror::Error;

    pub use bitcoin::hash_types::XpubIdentifier;
    /// A public key fingerprint, the first four bytes of the identifier.
    pub use bitcoin::util::bip32::Fingerprint;
    pub use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath};

    /// Possible errors when deriving keys as described in SLIP-10.
    #[derive(Error, Debug)]
    pub enum Error {
        /// Secp256k1 curve error.
        #[error("Secp256k1 curve error: {0}")]
        Secp256k1(#[from] bitcoin::secp256k1::Error),
        /// Hardened not supported in ed25519.
        #[error("Hardened not supported in ed25519")]
        HardenedNotSupportedForEd25519,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Ed25519ExtSecretKey {
        pub depth: u8,
        pub parent_fingerprint: Fingerprint,
        pub child_number: ChildNumber,
        pub secret_key: [u8; 32],
        pub chain_code: ChainCode,
    }

    impl Ed25519ExtSecretKey {
        pub fn new_master(seed: impl AsRef<[u8]>) -> Self {
            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"ed25519 seed");
            hmac_engine.input(seed.as_ref());
            let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

            let mut secret_key = [0u8; 32];
            secret_key.clone_from_slice(&hmac_result[..32]);

            Ed25519ExtSecretKey {
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::Normal { index: 0 },
                secret_key,
                chain_code: ChainCode::from(&hmac_result[32..]),
            }
        }

        pub fn derive_priv(&self, path: &impl AsRef<[ChildNumber]>) -> Result<Self, Error> {
            let mut sk = *self;
            for cnum in path.as_ref() {
                sk = sk.ckd_priv(*cnum)?;
            }
            Ok(sk)
        }

        pub fn ckd_priv(&self, i: ChildNumber) -> Result<Ed25519ExtSecretKey, Error> {
            if i.is_normal() {
                return Err(Error::HardenedNotSupportedForEd25519);
            }

            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
            // Hardened key: use only secret data to prevent public derivation
            // Pad the secret key to make it 33 bytes long
            hmac_engine.input(&[0u8]);
            hmac_engine.input(self.secret_key.as_ref());
            hmac_engine.input(u32::from(i).to_be_bytes().as_ref());

            let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

            let mut secret_key = [0u8; 32];
            secret_key.clone_from_slice(&hmac_result[..32]);

            Ok(Ed25519ExtSecretKey {
                depth: self.depth + 1,
                parent_fingerprint: self.fingerprint(),
                child_number: i,
                secret_key,
                chain_code: ChainCode::from(&hmac_result[32..]),
            })
        }

        pub fn public_key(&self) -> CompressedEdwardsY {
            let mut h = sha512::HashEngine::default();
            let mut bits: [u8; 32] = [0u8; 32];

            h.input(self.secret_key.as_ref());
            let hash = sha512::Hash::from_engine(h).into_inner();
            bits.copy_from_slice(&hash[..32]);

            bits[0] &= 248;
            bits[31] &= 127;
            bits[31] |= 64;

            let scalar = Scalar::from_bits(bits);
            let point = &scalar * &ED25519_BASEPOINT_TABLE;
            point.compress()
        }

        /// Returns the serialized public key, begins with a null byte.
        pub fn serialized_public_key(&self) -> [u8; 33] {
            let mut bytes = [0u8; 33];
            bytes[1..].copy_from_slice(self.public_key().as_bytes().as_ref());
            bytes
        }

        /// Returns the HASH160 of the serialized public key belonging to the xpriv.
        pub fn identifier(&self) -> XpubIdentifier {
            let mut engine = XpubIdentifier::engine();
            engine.input(self.serialized_public_key().as_ref());
            XpubIdentifier::from_engine(engine)
        }

        /// Returns the first four bytes of the identifier.
        pub fn fingerprint(&self) -> Fingerprint {
            Fingerprint::from(&self.identifier()[0..4])
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Secp256k1ExtSecretKey {
        pub depth: u8,
        pub parent_fingerprint: Fingerprint,
        pub child_number: ChildNumber,
        pub secret_key: secp256k1::SecretKey,
        pub chain_code: ChainCode,
    }

    impl Secp256k1ExtSecretKey {
        /// Construct a new master key from a seed value, as defined in SLIP10 if secret key is not
        /// valid retry with a new round on the HMAC engine.
        pub fn new_master(seed: impl AsRef<[u8]>) -> Secp256k1ExtSecretKey {
            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
            hmac_engine.input(seed.as_ref());
            let mut hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

            let (secret_key, chain_code) = loop {
                match secp256k1::SecretKey::from_slice(&hmac_result[..32]) {
                    Ok(key) => break (key, ChainCode::from(&hmac_result[32..])),
                    Err(_) => {
                        hmac_engine = HmacEngine::new(b"Bitcoin seed");
                        hmac_engine.input(&hmac_result[..32]);
                        hmac_result = Hmac::from_engine(hmac_engine);
                    }
                }
            };

            Secp256k1ExtSecretKey {
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::Normal { index: 0 },
                secret_key,
                chain_code,
            }
        }

        pub fn derive_priv<C: secp256k1::Signing>(
            &self,
            secp: &Secp256k1<C>,
            path: &impl AsRef<[ChildNumber]>,
        ) -> Result<Self, Error> {
            let mut sk = *self;
            for cnum in path.as_ref() {
                sk = sk.ckd_priv(secp, *cnum)?;
            }
            Ok(sk)
        }

        pub fn ckd_priv<C: secp256k1::Signing>(
            &self,
            secp: &Secp256k1<C>,
            i: ChildNumber,
        ) -> Result<Secp256k1ExtSecretKey, Error> {
            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
            match i {
                ChildNumber::Normal { .. } => {
                    // Non-hardened key: compute public data and use that
                    hmac_engine.input(
                        &secp256k1::PublicKey::from_secret_key(secp, &self.secret_key).serialize()
                            [..],
                    );
                }
                ChildNumber::Hardened { .. } => {
                    // Hardened key: use only secret data to prevent public derivation
                    hmac_engine.input(&[0u8]);
                    hmac_engine.input(&self.secret_key[..]);
                }
            }

            hmac_engine.input(u32::from(i).to_be_bytes().as_ref());
            let mut hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

            let (mut secret_key, chain_code) = loop {
                match secp256k1::SecretKey::from_slice(&hmac_result[..32]) {
                    Ok(key) => break (key, ChainCode::from(&hmac_result[32..])),
                    Err(_) => {
                        // let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2.
                        hmac_engine = HmacEngine::new(&self.chain_code[..]);
                        hmac_engine.input(&[1u8]);
                        hmac_engine.input(&hmac_result[32..]);
                        hmac_engine.input(u32::from(i).to_be_bytes().as_ref());
                        hmac_result = Hmac::from_engine(hmac_engine);
                    }
                }
            };

            secret_key.add_assign(&self.secret_key[..])?;

            Ok(Secp256k1ExtSecretKey {
                depth: self.depth + 1,
                parent_fingerprint: self.fingerprint(secp),
                child_number: i,
                secret_key,
                chain_code,
            })
        }

        pub fn public_key<C: secp256k1::Signing>(
            &self,
            secp: &Secp256k1<C>,
        ) -> secp256k1::PublicKey {
            secp256k1::PublicKey::from_secret_key(secp, &self.secret_key)
        }

        pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XpubIdentifier {
            let mut engine = XpubIdentifier::engine();
            engine.input(self.public_key(secp).serialize().as_ref());
            XpubIdentifier::from_engine(engine)
        }

        pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
            Fingerprint::from(&self.identifier(secp)[0..4])
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum ExtSecretKey {
        Secp256k1(Secp256k1ExtSecretKey),
        Ed25519(Ed25519ExtSecretKey),
    }

    impl ExtSecretKey {
        pub fn new_master_secp256k1(seed: impl AsRef<[u8]>) -> Self {
            ExtSecretKey::Secp256k1(Secp256k1ExtSecretKey::new_master(seed))
        }

        pub fn new_master_ed25519(seed: impl AsRef<[u8]>) -> Self {
            ExtSecretKey::Ed25519(Ed25519ExtSecretKey::new_master(seed))
        }

        pub fn derive_priv(&self, path: &impl AsRef<[ChildNumber]>) -> Result<Self, Error> {
            let mut sk = *self;
            for cnum in path.as_ref() {
                sk = sk.ckd_priv(*cnum)?;
            }
            Ok(sk)
        }

        /// Derive the private key given the provided child number. When operating on Bitcoin curve
        /// a new `secp256k1` context is created.
        pub fn ckd_priv(&self, i: ChildNumber) -> Result<Self, Error> {
            match &self {
                Self::Secp256k1(extended_key) => {
                    let secp = Secp256k1::new();
                    Ok(Self::Secp256k1(extended_key.ckd_priv(&secp, i)?))
                }
                Self::Ed25519(extended_key) => Ok(Self::Ed25519(extended_key.ckd_priv(i)?)),
            }
        }

        pub fn to_secp256k1(self) -> Option<Secp256k1ExtSecretKey> {
            match self {
                Self::Secp256k1(extended_key) => Some(extended_key),
                _ => None,
            }
        }

        /// Return some inner ed25519 extended private key, `None` oterhwise.
        pub fn to_ed25519(self) -> Option<Ed25519ExtSecretKey> {
            match self {
                Self::Ed25519(extended_key) => Some(extended_key),
                _ => None,
            }
        }

        /// Returns the HASH160 of the public key belonging to the xpriv.
        pub fn identifier(&self) -> XpubIdentifier {
            match self {
                Self::Secp256k1(extended_key) => {
                    let secp = Secp256k1::new();
                    extended_key.identifier(&secp)
                }
                Self::Ed25519(extended_key) => extended_key.identifier(),
            }
        }

        /// Returns the first four bytes of the identifier.
        pub fn fingerprint(&self) -> Fingerprint {
            match self {
                Self::Secp256k1(extended_key) => {
                    let secp = Secp256k1::new();
                    extended_key.fingerprint(&secp)
                }
                Self::Ed25519(extended_key) => extended_key.fingerprint(),
            }
        }

        /// Returns the chain code of the extended private key.
        pub fn chain_code(&self) -> ChainCode {
            match self {
                Self::Secp256k1(Secp256k1ExtSecretKey { chain_code, .. }) => *chain_code,
                Self::Ed25519(Ed25519ExtSecretKey { chain_code, .. }) => *chain_code,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use std::str::FromStr;

        fn assert_secp256k1_curve(master: &ExtSecretKey, asserts: Vec<Vec<&str>>) {
            for mut assert in asserts {
                let chain = master
                    .derive_priv(&DerivationPath::from_str(assert[0]).unwrap())
                    .unwrap()
                    .to_secp256k1()
                    .unwrap();
                assert_eq_secp256k1_elem(&chain, assert.drain(1..).collect());
            }
        }

        fn assert_eq_secp256k1_elem(res: &Secp256k1ExtSecretKey, asserts: Vec<&str>) {
            let ctx = Secp256k1::new();

            assert_eq!(asserts[0], res.parent_fingerprint.to_string());
            assert_eq!(asserts[1], res.chain_code.to_string());
            assert_eq!(asserts[2], res.secret_key.to_string());
            assert_eq!(asserts[3], res.public_key(&ctx).to_string());
        }

        #[test]
        fn secp256k1_vector_1() {
            let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
            let master = ExtSecretKey::new_master_secp256k1(&seed);

            assert_secp256k1_curve(
                &master,
                vec![
                    vec![
                        "m",
                        "00000000",
                        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                    ],
                    vec![
                        "m/0'",
                        "3442193e",
                        "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                        "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                    ],
                    vec![
                        "m/0'/1",
                        "5c1bd648",
                        "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                        "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
                    ],
                    vec![
                        "m/0'/1/2'",
                        "bef5a2f9",
                        "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                        "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                        "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
                    ],
                    vec![
                        "m/0'/1/2'/2",
                        "ee7ab90c",
                        "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                        "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                        "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
                    ],
                    vec![
                        "m/0'/1/2'/2/1000000000",
                        "d880d7d8",
                        "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                        "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                        "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
                    ],
                ],
            );
        }

        #[test]
        fn secp256k1_vector_2() {
            let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
            let master = ExtSecretKey::new_master_secp256k1(&seed);

            assert_secp256k1_curve(
                &master,
                vec![
                    vec![
                        "m",
                        "00000000",
                        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                        "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
                    ],
                    vec![
                        "m/0",
                        "bd16bee5",
                        "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                        "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                        "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
                    ],
                    vec![
                        "m/0/2147483647'",
                        "5a61ff8e",
                        "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                        "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                        "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
                    ],
                    vec![
                        "m/0/2147483647'/1",
                        "d8ab4937",
                        "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                        "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                        "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
                    ],
                    vec![
                        "m/0/2147483647'/1/2147483646'",
                        "78412e3a",
                        "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                        "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                        "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
                    ],
                    vec![
                        "m/0/2147483647'/1/2147483646'/2",
                        "31a507b8",
                        "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                        "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                        "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
                    ],
                ],
            );
        }

        fn assert_ed25519_curve(master: &ExtSecretKey, asserts: Vec<Vec<&str>>) {
            for mut assert in asserts {
                let chain = master
                    .derive_priv(&DerivationPath::from_str(assert[0]).unwrap())
                    .unwrap()
                    .to_ed25519()
                    .unwrap();
                assert_eq_ed25519_elem(&chain, assert.drain(1..).collect());
            }
        }

        fn assert_eq_ed25519_elem(res: &Ed25519ExtSecretKey, asserts: Vec<&str>) {
            assert_eq!(asserts[0], res.parent_fingerprint.to_string());
            assert_eq!(asserts[1], res.chain_code.to_string());
            assert_eq!(asserts[2], hex::encode(res.secret_key));
            assert_eq!(asserts[3], hex::encode(res.serialized_public_key()));
        }

        #[test]
        fn ed25519_vector_1() {
            let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
            let master = ExtSecretKey::new_master_ed25519(&seed);

            assert_ed25519_curve(
                &master,
                vec![
                    vec![
                        "m",
                        "00000000",
                        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                        "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
                    ],
                    vec![
                        "m/0'",
                        "ddebc675",
                        "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                        "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                    ],
                    vec![
                        "m/0'/1'",
                        "13dab143",
                        "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                        "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                        "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                    ],
                    vec![
                        "m/0'/1'/2'",
                        "ebe4cb29",
                        "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                        "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                        "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                    ],
                    vec![
                        "m/0'/1'/2'/2'",
                        "316ec1c6",
                        "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                        "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                        "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                    ],
                    vec![
                        "m/0'/1'/2'/2'/1000000000'",
                        "d6322ccd",
                        "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                        "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                        "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                    ],
                ],
            );
        }

        #[test]
        fn ed25519_vector_2() {
            let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
            let master = ExtSecretKey::new_master_ed25519(&seed);

            assert_ed25519_curve(
                &master,
                vec![
                    vec![
                        "m",
                        "00000000",
                        "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                        "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                        "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
                    ],
                    vec![
                        "m/0'",
                        "31981b50",
                        "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                        "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                        "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
                    ],
                    vec![
                        "m/0'/2147483647'",
                        "1e9411b1",
                        "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                        "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                        "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
                    ],
                    vec![
                        "m/0'/2147483647'/1'",
                        "fcadf38c",
                        "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                        "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                        "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
                    ],
                    vec![
                        "m/0'/2147483647'/1'/2147483646'",
                        "aca70953",
                        "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                        "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                        "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                    ],
                    vec![
                        "m/0'/2147483647'/1'/2147483646'/2'",
                        "422c654b",
                        "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                        "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                        "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                    ],
                ],
            );
        }
    }
}
