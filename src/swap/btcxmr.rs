// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

//! Concrete implementation of a swap between Bitcoin as the arbitrating blockchain and Monero as the
//! accordant blockchain.

use crate::bitcoin::{fee::SatPerKvB, timelock::CSVTimelock, BitcoinSegwitV0};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{
    self,
    slip10::{ChildNumber, DerivationPath, Ed25519ExtSecretKey, Secp256k1ExtSecretKey},
    AccordantKeyId, ArbitratingKeyId, GenerateKey, GenerateSharedKey, ProveCrossGroupDleq,
    SharedKeyId,
};
#[cfg(feature = "experimental")]
use crate::crypto::{EncSign, RecoverSecret, Sign};
use crate::monero::Monero;
use crate::protocol;
use crate::trade;
use crate::{blockchain::Blockchain, crypto::dleq::DLEQProof};

use monero::cryptonote::hash::Hash;

#[cfg(feature = "experimental")]
use ecdsa_fun::{
    adaptor::{Adaptor, HashTranscript},
    fun::{Point, Scalar},
    nonce, ECDSA,
};
// FIXME: when secp256kfun as new crates.io release
#[cfg(feature = "experimental")]
use rand::rngs::ThreadRng;
#[cfg(feature = "experimental")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "experimental")]
use secp256kfun::marker::*;
#[cfg(feature = "experimental")]
use sha2::Sha256;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
#[cfg(feature = "experimental")]
use bitcoin::{hashes::sha256d::Hash as Sha256dHash, secp256k1::Message};

use std::collections::HashMap;
use std::str::FromStr;

pub mod message;

#[cfg(feature = "experimental")]
type Transcript = HashTranscript<Sha256, ChaCha20Rng>;

#[cfg(feature = "experimental")]
type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>;

/// Fully defined type for Bitcoin-Monero atomic swap sets of parameters.
pub type Parameters = protocol::Parameters<
    PublicKey,
    monero::PublicKey,
    SecretKey,
    monero::PrivateKey,
    bitcoin::Address,
    CSVTimelock,
    SatPerKvB,
    DLEQProof,
>;

/// Fully defined type for Bitcoin-Monero atomic swap Alice protocol role.
pub type Alice = protocol::Alice<bitcoin::Address, BitcoinSegwitV0, Monero>;
impl_strict_encoding!(Alice);

/// Fully defined type for Bitcoin-Monero atomic swap Bob protocol role.
pub type Bob = protocol::Bob<bitcoin::Address, BitcoinSegwitV0, Monero>;
impl_strict_encoding!(Bob);

/// Fully defined type for Bitcoin-Monero atomic swap trade.
pub type DealParameters =
    trade::DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerKvB>;

/// Fully defined type for Bitcoin-Monero atomic swap public trade.
pub type Deal = trade::Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerKvB>;

/// Fully defined type for Bitcoin-Monero atomic swap arbitrating parameters.
pub type ArbitratingParameters =
    protocol::ArbitratingParameters<bitcoin::Amount, CSVTimelock, SatPerKvB>;

/// Fully defined type for Bitcoin-Monero atomic swap arbitrating set of transaction.
pub type CoreArbitratingTransactions =
    protocol::CoreArbitratingTransactions<PartiallySignedTransaction>;

/// Fully defined type for Bitcoin-Monero atomic swap fully signed punish transaction.
pub type FullySignedPunish = protocol::FullySignedPunish<PartiallySignedTransaction, Signature>;

/// Fully defined type for Bitcoin-Monero atomic swap transaction signatures.
pub type TxSignatures = protocol::TxSignatures<Signature>;

/// An ECDSA signature used in Bitcoin blockchain.
pub use bitcoin::secp256k1::ecdsa::Signature;

/// An encrypted ECDSA signature exchanged between peers during a swap.
pub use ecdsa_fun::adaptor::EncryptedSignature;

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
#[derive(Clone, Debug)]
pub struct KeyManager {
    /// The swap identifier used in the derivation.
    swap_index: ChildNumber,
    /// The secp256k1 account key as derived from swap_index.
    bitcoin_account_key: Secp256k1ExtSecretKey,
    /// The ed25519 account key as derived from swap_index.
    monero_account_key: Ed25519ExtSecretKey,
    /// A list of already derived keys for secp256k1 by derivation path.
    bitcoin_derivations: HashMap<DerivationPath, SecretKey>,
    /// A list of already derived monero keys for ed25519 by derivation path.
    monero_derivations: HashMap<DerivationPath, monero::PrivateKey>,
}

impl Encodable for KeyManager {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = Into::<u32>::into(self.swap_index).consensus_encode(writer)?;
        len += self.bitcoin_account_key.consensus_encode(writer)?;
        len += self.monero_account_key.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for KeyManager {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let swap_index: u32 = Decodable::consensus_decode(d)?;
        let bitcoin_account_key = Secp256k1ExtSecretKey::consensus_decode(d)?;
        let monero_account_key = Ed25519ExtSecretKey::consensus_decode(d)?;
        Ok(KeyManager {
            swap_index: ChildNumber::from(swap_index),
            bitcoin_account_key,
            monero_account_key,
            bitcoin_derivations: HashMap::new(),
            monero_derivations: HashMap::new(),
        })
    }
}

impl_strict_encoding!(KeyManager);

impl KeyManager {
    /// Generate the derivation path of an account key, computed as:
    /// `m/44'/{blockchain}'/{swap_index}'`.
    pub fn get_account_derivation_path(
        blockchain: Blockchain,
        swap_index: ChildNumber,
    ) -> Result<DerivationPath, crypto::Error> {
        let path = blockchain.derivation_path()?;
        Ok(path.extend([swap_index]))
    }

    /// Try to retreive the secret key internally if already generated, if the key is not found
    /// derive the secret key and save it internally.
    pub fn get_or_derive_bitcoin_key(
        &mut self,
        key_id: impl Derivation,
    ) -> Result<SecretKey, crypto::Error> {
        let path = key_id.derivation_path()?;
        self.bitcoin_derivations
            .get(&path)
            // Option<Result<SecretKey, _>>
            .map(|key| Ok(*key))
            // Some(Ok(_)) => Ok(_)
            // None => || { ... } => Result<SecretKey, crypto::Error>
            .unwrap_or_else(|| {
                let secp = Secp256k1::new();
                match self.bitcoin_account_key.derive_priv(&secp, &path) {
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
        let path = key_id.derivation_path()?;
        self.monero_derivations
            .get(&path)
            // Option<Result<PrivateKey, _>>
            .map(|key| Ok(*key))
            // Some(Ok(_)) => Ok(_)
            // None => || { ... } => Result<PrivateKey, crypto::Error>
            .unwrap_or_else(|| {
                let key_seed = self
                    .monero_account_key
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
        let swap_index = ChildNumber::from_hardened_idx(swap_index).map_err(crypto::Error::new)?;
        let secp = Secp256k1::new();
        Ok(Self {
            swap_index,
            bitcoin_account_key: Secp256k1ExtSecretKey::new_master(seed.as_ref()).derive_priv(
                &secp,
                &Self::get_account_derivation_path(Blockchain::Bitcoin, swap_index)?,
            )?,
            monero_account_key: Ed25519ExtSecretKey::new_master(seed.as_ref()).derive_priv(
                &Self::get_account_derivation_path(Blockchain::Monero, swap_index)?,
            )?,
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
impl Sign<PublicKey, Sha256dHash, Signature> for KeyManager {
    fn sign(
        &mut self,
        key: ArbitratingKeyId,
        msg: Sha256dHash,
    ) -> Result<Signature, crypto::Error> {
        let secret_key = self.get_or_derive_bitcoin_key(key)?;

        // FIXME: when new version is released on crates.io
        // let secret_key = Scalar::from(secret_key);
        let secret_key = Scalar::from_slice(&secret_key[..])
            .unwrap()
            .mark::<NonZero>()
            .expect("SecretKey is never zero");
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
        let ecdsa = ECDSA::new(nonce_gen);

        // FIXME
        // Ok(ecdsa.sign(&secret_key, message_hash).into())
        Ok(
            Signature::from_compact(ecdsa.sign(&secret_key, message_hash).to_bytes().as_ref())
                .unwrap(),
        )
    }

    fn verify_signature(
        &self,
        key: &PublicKey,
        msg: Sha256dHash,
        sig: &Signature,
    ) -> Result<(), crypto::Error> {
        let secp = Secp256k1::new();
        let message = Message::from_slice(&msg).expect("Hash is always ok");
        secp.verify_ecdsa(&message, sig, key)
            .map_err(crypto::Error::new)
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl EncSign<PublicKey, Sha256dHash, Signature, EncryptedSignature> for KeyManager {
    fn encrypt_sign(
        &mut self,
        signing_key: ArbitratingKeyId,
        encryption_key: &PublicKey,
        msg: Sha256dHash,
    ) -> Result<EncryptedSignature, crypto::Error> {
        let secret_key = self.get_or_derive_bitcoin_key(signing_key)?;

        let engine = Adaptor::<Transcript, NonceGen>::default();
        // FIXME
        // let secret_signing_key = Scalar::from(secret_key);
        let secret_signing_key = Scalar::from_slice(&secret_key[..])
            .unwrap()
            .mark::<NonZero>()
            .expect("SecretKey is never zero");
        // FIXME
        // let encryption_key = Point::from(*encryption_key);
        let encryption_key = Point::from_bytes(encryption_key.serialize()).unwrap();
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
        // FIXME
        // let verification_key = Point::from(*signing_key);
        // let encryption_key = Point::from(*encryption_key);
        let verification_key = Point::from_bytes(signing_key.serialize()).unwrap();
        let encryption_key = Point::from_bytes(encryption_key.serialize()).unwrap();
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
        // FIXME
        // let decryption_key = Scalar::from(secret_key);
        let decryption_key = Scalar::from_slice(&secret_key[..])
            .unwrap()
            .mark::<NonZero>()
            .expect("SecretKey is never zero");

        // FIXME
        // Ok(adaptor.decrypt_signature(&decryption_key, sig).into())
        Ok(Signature::from_compact(
            adaptor
                .decrypt_signature(&decryption_key, sig)
                .to_bytes()
                .as_ref(),
        )
        .unwrap())
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl RecoverSecret<PublicKey, SecretKey, Signature, EncryptedSignature> for KeyManager {
    fn recover_secret_key(
        &self,
        encrypted_sig: EncryptedSignature,
        encryption_key: &PublicKey,
        sig: Signature,
    ) -> SecretKey {
        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        // FIXME
        // let encryption_key = Point::from(*encryption_key);
        //let signature = ecdsa_fun::Signature::from(sig);
        let encryption_key = Point::from_bytes(encryption_key.serialize()).unwrap();
        let signature = ecdsa_fun::Signature::from_bytes(sig.serialize_compact()).unwrap();

        match adaptor.recover_decryption_key(&encryption_key, &signature, &encrypted_sig) {
            // FIXME
            // Some(decryption_key) => decryption_key.into(),
            Some(decryption_key) => {
                SecretKey::from_slice(decryption_key.to_bytes().as_ref()).unwrap()
            }
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
        proof.verify(
            public_spend
                .point
                .decompress()
                .expect("Valid point to decompress"),
            // FIXME
            //ecdsa_fun::fun::Point::from(*encryption_key),
            Point::from_bytes(encryption_key.serialize()).unwrap(),
        )
    }
}

#[test]
fn test_keymanager_consensus_encoding() {
    let key_manager = KeyManager::new([0; 32], 1).unwrap();
    let mut encoder = Vec::new();
    key_manager.consensus_encode(&mut encoder).unwrap();
    KeyManager::consensus_decode(&mut std::io::Cursor::new(encoder)).unwrap();
}

#[test]
fn test_keymanager_restore_index() {
    let key_manager = KeyManager::new([0; 32], 42).unwrap();
    let mut encoder = Vec::new();
    key_manager.consensus_encode(&mut encoder).unwrap();
    let restore = KeyManager::consensus_decode(&mut std::io::Cursor::new(encoder)).unwrap();
    assert_eq!(
        restore.swap_index,
        ChildNumber::from_hardened_idx(42).unwrap()
    );
}

#[test]
fn test_keymanager_restore_bitcoin_key() {
    let mut key_manager = KeyManager::new([0; 32], 1).unwrap();
    let orig_key = key_manager
        .get_or_derive_bitcoin_key(ArbitratingKeyId::Lock)
        .unwrap();
    let mut encoder = Vec::new();
    key_manager.consensus_encode(&mut encoder).unwrap();
    let mut restore = KeyManager::consensus_decode(&mut std::io::Cursor::new(encoder)).unwrap();
    let restored_key = restore
        .get_or_derive_bitcoin_key(ArbitratingKeyId::Lock)
        .unwrap();
    assert_eq!(orig_key, restored_key);
}

#[test]
fn test_keymanager_restore_monero_key() {
    let mut key_manager = KeyManager::new([0; 32], 1).unwrap();
    let orig_key = key_manager
        .get_or_derive_monero_key(AccordantKeyId::Spend)
        .unwrap();
    let mut encoder = Vec::new();
    key_manager.consensus_encode(&mut encoder).unwrap();
    let mut restore = KeyManager::consensus_decode(&mut std::io::Cursor::new(encoder)).unwrap();
    let restored_key = restore
        .get_or_derive_monero_key(AccordantKeyId::Spend)
        .unwrap();
    assert_eq!(orig_key, restored_key);
}
