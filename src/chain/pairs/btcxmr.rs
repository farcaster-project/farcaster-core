use crate::chain::monero::{self as xmr};
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{
    self, AccordantKeyId, ArbitratingKeyId, Commit, Commitment, GenerateKey, GenerateSharedKey,
    ProveCrossGroupDleq, SharedKeyId,
};
#[cfg(feature = "experimental")]
use crate::{chain::bitcoin::BitcoinSegwitV0, chain::monero::Monero, crypto::Sign, swap::Swap};

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

use bitcoin::secp256k1::key::SecretKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};

use std::str::FromStr;

#[cfg(feature = "experimental")]
type Transcript = HashTranscript<Sha256, ChaCha20Rng>;

#[cfg(feature = "experimental")]
type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>;

pub const SHARED_KEY_BITS: usize = 252;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcXmr;

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl Swap for BtcXmr {
    /// The arbitrating blockchain
    type Ar = BitcoinSegwitV0;

    /// The accordant blockchain
    type Ac = Monero;

    /// The proof system to link both cryptographic groups
    type Proof = RingProof;
}

impl Commitment for BtcXmr {
    type Commitment = Hash;
}

impl CanonicalBytes for Hash {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(Self::from_slice(bytes))
    }
}

#[derive(Clone, Debug)]
pub struct RingProof;

impl CanonicalBytes for RingProof {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        vec![0u8]
    }

    fn from_canonical_bytes(_: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(Self)
    }
}

#[derive(Clone, Debug)]
pub struct Wallet {
    seed: Option<[u8; 32]>,
}

impl Wallet {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed: Some(seed) }
    }

    pub fn new_keyless() -> Self {
        Self { seed: None }
    }

    pub fn get_btc_privkey(
        &self,
        key_id: ArbitratingKeyId,
    ) -> Result<bitcoin::PrivateKey, crypto::Error> {
        let secp = Secp256k1::new();
        if let Some(seed) = self.seed {
            let master_key = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
                .map_err(|e| crypto::Error::new(e))?;
            let key =
                match key_id {
                    ArbitratingKeyId::Fund => master_key
                        .derive_priv(&secp, &DerivationPath::from_str("m/0/1'/1").unwrap()),
                    ArbitratingKeyId::Buy => master_key
                        .derive_priv(&secp, &DerivationPath::from_str("m/0/1'/2").unwrap()),
                    ArbitratingKeyId::Cancel => master_key
                        .derive_priv(&secp, &DerivationPath::from_str("m/0/1'/3").unwrap()),
                    ArbitratingKeyId::Refund => master_key
                        .derive_priv(&secp, &DerivationPath::from_str("m/0/1'/4").unwrap()),
                    ArbitratingKeyId::Punish => master_key
                        .derive_priv(&secp, &DerivationPath::from_str("m/0/1'/5").unwrap()),
                    ArbitratingKeyId::Extra(_) => Err(crypto::Error::UnsupportedKey)?,
                };
            Ok(key.map_err(|e| crypto::Error::new(e))?.private_key)
        } else {
            Err(crypto::Error::UnsupportedKey)
        }
    }

    pub fn get_btc_privkey_by_pub(
        &self,
        pubkey: &bitcoin::PublicKey,
    ) -> Result<bitcoin::PrivateKey, crypto::Error> {
        let secp = Secp256k1::new();
        let all_keys = vec![
            ArbitratingKeyId::Fund,
            ArbitratingKeyId::Buy,
            ArbitratingKeyId::Cancel,
            ArbitratingKeyId::Refund,
            ArbitratingKeyId::Punish,
        ];
        // This is very ineficient as we generate all keys (known) each time
        all_keys
            .into_iter()
            .filter_map(|id| self.get_btc_privkey(id).ok())
            .find(|privkey| bitcoin::PublicKey::from_private_key(&secp, privkey) == *pubkey)
            .or_else(|| {
                let secp = Secp256k1::new();
                let spend = self.private_spend_from_seed().ok()?;
                let bytes = spend.to_bytes();
                let adaptor = SecretKey::from_slice(&bytes).ok()?;
                let key = bitcoin::PrivateKey {
                    compressed: true,
                    network: bitcoin::Network::Bitcoin,
                    key: adaptor,
                };
                if bitcoin::PublicKey::from_private_key(&secp, &key) == *pubkey {
                    Some(key)
                } else {
                    None
                }
            })
            .ok_or(crypto::Error::UnsupportedKey)
    }

    pub fn private_spend_from_seed(&self) -> Result<monero::PrivateKey, crypto::Error> {
        if let Some(seed) = self.seed {
            let mut bytes = Vec::from(b"farcaster_priv_spend".as_ref());
            bytes.extend_from_slice(&seed);

            let mut key = Hash::hash(&bytes).to_fixed_bytes();
            key[31] &= 0b0000_1111; // Chop off bits that might be greater than the curve modulus

            monero::PrivateKey::from_slice(&key).map_err(|e| crypto::Error::new(e))
        } else {
            Err(crypto::Error::UnsupportedKey)
        }
    }
}

impl GenerateKey<monero::PublicKey, AccordantKeyId> for Wallet {
    fn get_pubkey(&self, key_id: AccordantKeyId) -> Result<monero::PublicKey, crypto::Error> {
        match key_id {
            AccordantKeyId::Spend => Ok(monero::PublicKey::from_private_key(
                &self.private_spend_from_seed()?,
            )),
            AccordantKeyId::Extra(_) => Err(crypto::Error::UnsupportedKey),
        }
    }
}

impl GenerateSharedKey<monero::PrivateKey> for Wallet {
    fn get_shared_key(&self, key_id: SharedKeyId) -> Result<monero::PrivateKey, crypto::Error> {
        if let Some(seed) = self.seed {
            match key_id.id() {
                xmr::SHARED_VIEW_KEY_ID => {
                    let mut bytes = Vec::from(b"farcaster_priv_view".as_ref());
                    bytes.extend_from_slice(&seed);
                    Ok(Hash::hash(&bytes).as_scalar())
                }
                _ => Err(crypto::Error::UnsupportedKey),
            }
        } else {
            Err(crypto::Error::UnsupportedKey)
        }
    }
}

impl GenerateKey<bitcoin::PublicKey, ArbitratingKeyId> for Wallet {
    fn get_pubkey(&self, key_id: ArbitratingKeyId) -> Result<bitcoin::PublicKey, crypto::Error> {
        let secp = Secp256k1::new();
        Ok(self.get_btc_privkey(key_id)?.public_key(&secp))
    }
}

impl GenerateSharedKey<bitcoin::PrivateKey> for Wallet {
    fn get_shared_key(&self, _key_id: SharedKeyId) -> Result<bitcoin::PrivateKey, crypto::Error> {
        // No shared key for bitcoin
        Err(crypto::Error::UnsupportedKey)
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl Sign<bitcoin::PublicKey, bitcoin::PrivateKey, Sha256dHash, Signature, EncryptedSignature>
    for Wallet
{
    fn sign_with_key(
        &self,
        key: &bitcoin::PublicKey,
        msg: Sha256dHash,
    ) -> Result<Signature, crypto::Error> {
        let secret_key = Scalar::from(self.get_btc_privkey_by_pub(key)?.key);
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
        let ecdsa = ECDSA::new(nonce_gen);

        Ok(ecdsa.sign(&secret_key, &message_hash).into())
    }

    fn verify_signature(
        &self,
        key: &bitcoin::PublicKey,
        msg: Sha256dHash,
        sig: &Signature,
    ) -> Result<(), crypto::Error> {
        let secp = Secp256k1::new();
        let message = Message::from_slice(&msg).expect("Hash is always ok");
        secp.verify(&message, &sig, &key.key)
            .map_err(|e| crypto::Error::new(e))
    }

    fn adaptor_sign_with_key(
        &self,
        signing_key: &bitcoin::PublicKey,
        adaptor_key: &bitcoin::PublicKey,
        msg: Sha256dHash,
    ) -> Result<EncryptedSignature, crypto::Error> {
        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        let secret_signing_key = Scalar::from(self.get_btc_privkey_by_pub(signing_key)?.key);
        let encryption_key = Point::from(adaptor_key.key);
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        Ok(adaptor.encrypted_sign(&secret_signing_key, &encryption_key, &message_hash))
    }

    fn verify_adaptor_signature(
        &self,
        signing_key: &bitcoin::PublicKey,
        adaptor_key: &bitcoin::PublicKey,
        msg: Sha256dHash,
        adaptor_sig: &EncryptedSignature,
    ) -> Result<(), crypto::Error> {
        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        let verification_key = Point::from(signing_key.key);
        let encryption_key = Point::from(adaptor_key.key);
        let message_hash: &[u8; 32] = {
            use bitcoin::hashes::Hash;
            msg.as_inner()
        };

        match adaptor.verify_encrypted_signature(
            &verification_key,
            &encryption_key,
            &message_hash,
            &adaptor_sig,
        ) {
            true => Ok(()),
            false => Err(crypto::Error::InvalidAdaptorSignature),
        }
    }

    fn adapt_signature(
        &self,
        adaptor_key: &bitcoin::PublicKey,
        adaptor_sig: EncryptedSignature,
    ) -> Result<Signature, crypto::Error> {
        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        let decryption_key = Scalar::from(self.get_btc_privkey_by_pub(adaptor_key)?.key);

        Ok(adaptor
            .decrypt_signature(&decryption_key, adaptor_sig.clone())
            .into())
    }

    fn recover_key(
        &self,
        adaptor_key: &bitcoin::PublicKey,
        sig: Signature,
        adapted_sig: EncryptedSignature,
    ) -> bitcoin::PrivateKey {
        let adaptor = Adaptor::<Transcript, NonceGen>::default();
        let encryption_key = Point::from(adaptor_key.key);
        let signature = ecdsa_fun::Signature::from(sig);

        match adaptor.recover_decryption_key(&encryption_key, &signature, &adapted_sig) {
            Some(decryption_key) => {
                bitcoin::PrivateKey::new(decryption_key.into(), bitcoin::Network::Bitcoin)
            }
            None => panic!("signature is not the decryption of our original encrypted signature"),
        }
    }
}

impl Commit<Hash> for Wallet {
    fn commit_to<T: AsRef<[u8]>>(&self, value: T) -> Hash {
        Hash::hash(value.as_ref())
    }
}

impl ProveCrossGroupDleq<bitcoin::PublicKey, monero::PublicKey, RingProof> for Wallet {
    /// Generate the proof and the two public keys: the arbitrating public key, also called the
    /// adaptor public key, and the accordant public spend key.
    fn generate(
        &self,
    ) -> Result<(monero::PublicKey, bitcoin::PublicKey, RingProof), crypto::Error> {
        let spend = self.private_spend_from_seed()?;
        let adaptor = self.project_over()?;

        Ok((
            monero::PublicKey::from_private_key(&spend),
            adaptor,
            // TODO
            RingProof,
        ))
    }

    /// Project the accordant sepnd secret key over the arbitrating curve to get the public key
    /// used as the adaptor public key.
    fn project_over(&self) -> Result<bitcoin::PublicKey, crypto::Error> {
        let secp = Secp256k1::new();
        let spend = self.private_spend_from_seed()?;
        let bytes = spend.to_bytes(); // FIXME warn this copy the priv key
        let adaptor = SecretKey::from_slice(&bytes).map_err(|e| crypto::Error::new(e))?;

        Ok(bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::Network::Bitcoin,
            key: adaptor,
        }
        .public_key(&secp))
    }

    /// Verify the proof given the two public keys: the accordant spend public key and the
    /// arbitrating adaptor public key.
    fn verify(
        &self,
        _public_spend: &monero::PublicKey,
        _adaptor: &bitcoin::PublicKey,
        _proof: RingProof,
    ) -> Result<(), crypto::Error> {
        todo!()
    }
}
