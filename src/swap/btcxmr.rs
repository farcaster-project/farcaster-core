//! Concrete implementation of a swap between Bitcoin as the arbitrating blockchain and Monero as the
//! accordant blockchain.

use crate::crypto::{
    self,
    slip10::{ChildNumber, DerivationPath, Ed25519ExtSecretKey, Secp256k1ExtSecretKey},
    AccordantKeyId, ArbitratingKeyId, GenerateKey, GenerateSharedKey, KeccakCommitment,
    ProveCrossGroupDleq, SharedKeyId,
};
#[cfg(feature = "experimental")]
use crate::{bitcoin::BitcoinSegwitV0, crypto::Sign, monero::Monero, swap::Swap};
use crate::{blockchain::Blockchain, crypto::dleq::DLEQProof};

use monero::cryptonote::hash::Hash;

#[cfg(feature = "experimental")]
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature, HashTranscript},
    fun::{Point, Scalar},
    nonce, ECDSA,
};
#[cfg(feature = "experimental")]
use rand::rngs::ThreadRng;
#[cfg(feature = "experimental")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "experimental")]
use sha2::Sha256;

#[cfg(feature = "experimental")]
use bitcoin::{hashes::sha256d::Hash as Sha256dHash, secp256k1::Message, secp256k1::Signature};

use bitcoin::secp256k1::{
    key::{PublicKey, SecretKey},
    Secp256k1,
};

use std::collections::HashMap;
use std::str::FromStr;

#[cfg(feature = "experimental")]
type Transcript = HashTranscript<Sha256, ChaCha20Rng>;

#[cfg(feature = "experimental")]
type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>;

/// Index, used as hardened derivation, to derive standard keys defined in the protocol for Bitcoin
/// and Monero.
pub const STD_KEY_DERIVE_INDEX: u32 = 1;
/// Index, used as hardened derivation, to derive extra keys for Bitcoin and Monero.
pub const EXTRA_KEY_DERIVE_INDEX: u32 = 2;
/// Index, used as hardened derivation, to derive shared secret keys for Bitcoin and Monero.
pub const SHARED_KEY_DERIVE_INDEX: u32 = 3;

/// Clamping mask for the accordant spend key. The key is generated `(mod l)` which is `mod 2^252 +
/// 27742317777372353535851937790883648493`, we need to clamp it to `<= 2^252` for the cross group
/// discrete logarithm proof.
pub const CLAMPING_TO_252_BITS_MASK: u8 = 0b0000_1111;

/// The context for a Bitcoin and Monero swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtcXmr;

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl Swap for BtcXmr {
    type Ar = BitcoinSegwitV0;
    type Ac = Monero;
    type Proof = DLEQProof;
    type Commitment = KeccakCommitment;
}

/// Retrieve the derivation path of something. Might be a blockchain, a type of key, anything that
/// can contribute to the full derivation path of a key.
pub trait Derivation {
    /// Returns the derivation path contribution of the element.
    fn derivation_path(&self) -> Result<DerivationPath, crypto::Error>;
}

impl Derivation for Blockchain {
    fn derivation_path(&self) -> Result<DerivationPath, crypto::Error> {
        Ok(match self {
            Blockchain::Bitcoin => DerivationPath::from_str("m/44'/0'").unwrap(),
            Blockchain::Monero => DerivationPath::from_str("m/44'/128'").unwrap(),
        })
    }
}

impl Derivation for ArbitratingKeyId {
    fn derivation_path(&self) -> Result<DerivationPath, crypto::Error> {
        let std_key_index = ChildNumber::from_hardened_idx(STD_KEY_DERIVE_INDEX).unwrap();
        let key_path = match self {
            ArbitratingKeyId::Lock => [std_key_index, ChildNumber::from_hardened_idx(1).unwrap()],
            // Use the same key for buy and cancel
            ArbitratingKeyId::Buy | ArbitratingKeyId::Cancel => {
                [std_key_index, ChildNumber::from_hardened_idx(2).unwrap()]
            }
            // Use the same key for refund and punish
            ArbitratingKeyId::Refund | ArbitratingKeyId::Punish => {
                [std_key_index, ChildNumber::from_hardened_idx(3).unwrap()]
            }
            ArbitratingKeyId::Extra(i) => [
                ChildNumber::from_hardened_idx(EXTRA_KEY_DERIVE_INDEX).unwrap(),
                ChildNumber::from_hardened_idx(*i as u32).map_err(crypto::Error::new)?,
            ],
        };
        Ok(key_path.as_ref().into())
    }
}

impl Derivation for AccordantKeyId {
    fn derivation_path(&self) -> Result<DerivationPath, crypto::Error> {
        let std_key_index = ChildNumber::from_hardened_idx(STD_KEY_DERIVE_INDEX).unwrap();
        let key_path = match self {
            AccordantKeyId::Spend => [std_key_index, ChildNumber::from_hardened_idx(1).unwrap()],
            AccordantKeyId::Extra(i) => [
                ChildNumber::from_hardened_idx(EXTRA_KEY_DERIVE_INDEX).unwrap(),
                ChildNumber::from_hardened_idx(*i as u32).map_err(crypto::Error::new)?,
            ],
        };
        Ok(key_path.as_ref().into())
    }
}

impl Derivation for SharedKeyId {
    fn derivation_path(&self) -> Result<DerivationPath, crypto::Error> {
        let shared_key_index = ChildNumber::from_hardened_idx(SHARED_KEY_DERIVE_INDEX).unwrap();
        let idx = ChildNumber::from_hardened_idx(self.id() as u32).map_err(crypto::Error::new)?;
        Ok([shared_key_index, idx].as_ref().into())
    }
}

/// Manager responsible for handling key operations (secret and public). Implements traits for
/// handling [`GenerateKey`], [`GenerateSharedKey`] and [`Sign`].
#[derive(Debug)]
pub struct KeyManager {
    /// The master 32-bytes seed used to derive all the keys for all the swaps.
    master_seed: [u8; 32],
    /// The swap identifier used in the derivation.
    swap_index: ChildNumber,
    /// The master secp256k1 seed.
    bitcoin_master_key: Secp256k1ExtSecretKey,
    /// The master ed25519 seed.
    monero_master_key: Ed25519ExtSecretKey,
    /// A list of already derived keys for secp256k1 by derivation path.
    bitcoin_derivations: HashMap<DerivationPath, SecretKey>,
    /// A list of already derived monero keys for ed25519 by derivation path.
    monero_derivations: HashMap<DerivationPath, monero::PrivateKey>,
}

impl KeyManager {
    /// Generate the derivation path of a key, computed as:
    /// `m/44'/{blockchain}'/{swap_index}'/{key_type}'/{key_idx}'`.
    pub fn get_derivation_path(
        &self,
        blockchain: Blockchain,
        key_id: impl Derivation,
    ) -> Result<DerivationPath, crypto::Error> {
        let path = blockchain.derivation_path()?;
        let path = path.extend(&[self.swap_index]);
        Ok(path.extend(&key_id.derivation_path()?))
    }

    /// Try to retreive the secret key internally if already generated, if the key is not found
    /// derive the secret key and save it internally.
    pub fn get_or_derive_bitcoin_key(
        &mut self,
        key_id: impl Derivation,
    ) -> Result<SecretKey, crypto::Error> {
        let path = self.get_derivation_path(Blockchain::Bitcoin, key_id)?;
        self.bitcoin_derivations
            .get(&path)
            // Option<Result<SecretKey, _>>
            .map(|key| Ok(*key))
            // Some(Ok(_)) => Ok(_)
            // None => || { ... } => Result<SecretKey, crypto::Error>
            .unwrap_or_else(|| {
                let secp = Secp256k1::new();
                match self.bitcoin_master_key.derive_priv(&secp, &path) {
                    Ok(key) => {
                        self.bitcoin_derivations.insert(path, key.secret_key);
                        Ok(key.secret_key)
                    }
                    Err(e) => Err(e.into()),
                }
            })
    }

    /// Try to retreive the secret key internally if already generated, if the key is not found
    /// derive the secret key and save it internally.
    pub fn get_or_derive_monero_key(
        &mut self,
        key_id: impl Derivation,
    ) -> Result<monero::PrivateKey, crypto::Error> {
        let path = self.get_derivation_path(Blockchain::Monero, key_id)?;
        self.monero_derivations
            .get(&path)
            // Option<Result<PrivateKey, _>>
            .map(|key| Ok(*key))
            // Some(Ok(_)) => Ok(_)
            // None => || { ... } => Result<PrivateKey, crypto::Error>
            .unwrap_or_else(|| {
                let key_seed = self
                    .monero_master_key
                    .derive_priv(&path)
                    .expect("Path does not contain non-hardened derivation")
                    .secret_key;
                let secret_key = Hash::from_slice(&key_seed).as_scalar();

                self.monero_derivations.insert(path, secret_key);
                Ok(secret_key)
            })
    }

    /// Get the monero accordant spend secret key. The key is derived from the master seed like all
    /// other keys but clamped to only 252 bits.
    pub fn get_or_derive_monero_spend_key(&mut self) -> Result<monero::PrivateKey, crypto::Error> {
        let mut little_endian_bytes = self
            .get_or_derive_monero_key(AccordantKeyId::Spend)?
            .to_bytes();
        little_endian_bytes[31] &= CLAMPING_TO_252_BITS_MASK;
        Ok(monero::PrivateKey::from_slice(little_endian_bytes.as_ref())
            .expect("Valid canonical bytes"))
    }

    /// Create a new key manager with the provided master seed, returns an error if the swap index is
    /// not within `[0, 2^31 - 1]`.
    pub fn new(seed: [u8; 32], swap_index: u32) -> Result<Self, crypto::Error> {
        Ok(Self {
            master_seed: seed,
            swap_index: ChildNumber::from_hardened_idx(swap_index).map_err(crypto::Error::new)?,
            bitcoin_master_key: Secp256k1ExtSecretKey::new_master(seed.as_ref()),
            monero_master_key: Ed25519ExtSecretKey::new_master(seed.as_ref()),
            bitcoin_derivations: HashMap::new(),
            monero_derivations: HashMap::new(),
        })
    }
}

impl GenerateKey<monero::PublicKey, AccordantKeyId> for KeyManager {
    fn get_pubkey(&mut self, key_id: AccordantKeyId) -> Result<monero::PublicKey, crypto::Error> {
        let secret_key = match key_id {
            AccordantKeyId::Spend => self.get_or_derive_monero_spend_key()?,
            AccordantKeyId::Extra(_) => self.get_or_derive_monero_key(key_id)?,
        };

        Ok(monero::PublicKey::from_private_key(&secret_key))
    }
}

impl GenerateSharedKey<monero::PrivateKey> for KeyManager {
    fn get_shared_key(&mut self, key_id: SharedKeyId) -> Result<monero::PrivateKey, crypto::Error> {
        self.get_or_derive_monero_key(key_id)
    }
}

impl GenerateKey<PublicKey, ArbitratingKeyId> for KeyManager {
    fn get_pubkey(&mut self, key_id: ArbitratingKeyId) -> Result<PublicKey, crypto::Error> {
        let secp = Secp256k1::new();
        let secret_key = self.get_or_derive_bitcoin_key(key_id)?;

        Ok(PublicKey::from_secret_key(&secp, &secret_key))
    }
}

impl GenerateSharedKey<SecretKey> for KeyManager {
    fn get_shared_key(&mut self, key_id: SharedKeyId) -> Result<SecretKey, crypto::Error> {
        self.get_or_derive_bitcoin_key(key_id)
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl Sign<PublicKey, SecretKey, Sha256dHash, Signature, EncryptedSignature> for KeyManager {
    fn sign(
        &mut self,
        key: ArbitratingKeyId,
        msg: Sha256dHash,
    ) -> Result<Signature, crypto::Error> {
        let secret_key = self.get_or_derive_bitcoin_key(key)?;

        let secret_key = Scalar::from(secret_key);
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
        let ecdsa = ECDSA::new(nonce_gen);

        Ok(ecdsa.sign(&secret_key, message_hash).into())
    }

    fn verify_signature(
        &self,
        key: &PublicKey,
        msg: Sha256dHash,
        sig: &Signature,
    ) -> Result<(), crypto::Error> {
        let secp = Secp256k1::new();
        let message = Message::from_slice(&msg).expect("Hash is always ok");
        secp.verify(&message, sig, key).map_err(crypto::Error::new)
    }

    fn encrypt_sign(
        &mut self,
        signing_key: ArbitratingKeyId,
        encryption_key: &PublicKey,
        msg: Sha256dHash,
    ) -> Result<EncryptedSignature, crypto::Error> {
        let secret_key = self.get_or_derive_bitcoin_key(signing_key)?;

        let engine = Adaptor::<Transcript, NonceGen>::default();
        let secret_signing_key = Scalar::from(secret_key);
        let encryption_key = Point::from(*encryption_key);
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        Ok(engine.encrypted_sign(&secret_signing_key, &encryption_key, message_hash))
    }

    fn verify_encrypted_signature(
        &self,
        signing_key: &PublicKey,
        encryption_key: &PublicKey,
        msg: Sha256dHash,
        sig: &EncryptedSignature,
    ) -> Result<(), crypto::Error> {
        let engine = Adaptor::<Transcript, NonceGen>::default();
        let verification_key = Point::from(*signing_key);
        let encryption_key = Point::from(*encryption_key);
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        match engine.verify_encrypted_signature(
            &verification_key,
            &encryption_key,
            message_hash,
            sig,
        ) {
            true => Ok(()),
            false => Err(crypto::Error::InvalidEncryptedSignature),
        }
    }

    fn decrypt_signature(
        &mut self,
        decryption_key: AccordantKeyId,
        sig: EncryptedSignature,
    ) -> Result<Signature, crypto::Error> {
        let secret_key = match decryption_key {
            AccordantKeyId::Spend => self.get_or_derive_monero_spend_key()?,
            _ => return Err(crypto::Error::UnsupportedKey),
        };
        let mut little_endian_secret_bytes = secret_key.to_bytes();
        little_endian_secret_bytes.reverse();
        let secret_key = SecretKey::from_slice(little_endian_secret_bytes.as_ref())
            .map_err(crypto::Error::new)?;

        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        let decryption_key = Scalar::from(secret_key);

        Ok(adaptor.decrypt_signature(&decryption_key, sig).into())
    }

    fn recover_secret_key(
        &self,
        encrypted_sig: EncryptedSignature,
        encryption_key: &PublicKey,
        sig: Signature,
    ) -> SecretKey {
        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        let encryption_key = Point::from(*encryption_key);
        let signature = ecdsa_fun::Signature::from(sig);

        match adaptor.recover_decryption_key(&encryption_key, &signature, &encrypted_sig) {
            Some(decryption_key) => decryption_key.into(),
            None => panic!("signature is not the decryption of our original encrypted signature"),
        }
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl ProveCrossGroupDleq<PublicKey, monero::PublicKey, DLEQProof> for KeyManager {
    fn generate_proof(
        &mut self,
    ) -> Result<(monero::PublicKey, PublicKey, DLEQProof), crypto::Error> {
        let spend = self.get_pubkey(AccordantKeyId::Spend)?;
        let encryption_key = self.get_encryption_key()?;

        let x = self.get_or_derive_monero_spend_key()?.to_bytes();
        let proof = crypto::dleq::DLEQProof::generate(x);

        Ok((spend, encryption_key, proof))
    }

    fn get_encryption_key(&mut self) -> Result<PublicKey, crypto::Error> {
        let secp = Secp256k1::new();
        let secret = self.get_or_derive_monero_spend_key()?;
        let mut little_endian_secret_bytes = secret.to_bytes();
        little_endian_secret_bytes.reverse();
        let encryption_secret_key =
            SecretKey::from_slice(&little_endian_secret_bytes).map_err(crypto::Error::new)?;
        Ok(PublicKey::from_secret_key(&secp, &encryption_secret_key))
    }

    fn verify_proof(
        &mut self,
        public_spend: &monero::PublicKey,
        encryption_key: &PublicKey,
        proof: DLEQProof,
    ) -> Result<(), crypto::Error> {
        if public_spend.point != proof.xG_p.compress() {
            return Err(crypto::Error::InvalidProof);
        }
        if encryption_key.serialize_uncompressed() != proof.xH_p.to_bytes_uncompressed() {
            return Err(crypto::Error::InvalidProof);
        }
        proof.verify()
    }
}
