use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{
    self, AccordantKeyId, ArbitratingKeyId, Commit, Commitment, GenerateKey, GenerateSharedKey,
    ProveCrossGroupDleq, SharedKeyId, Sign,
};
use crate::swap::Swap;

use crate::chain::bitcoin::transaction::sign_hash;
use crate::chain::bitcoin::{Bitcoin, SegwitV0};
use crate::chain::monero::{self as xmr, Monero};

use monero::cryptonote::hash::Hash;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::key::SecretKey;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::Signature;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};

use std::str::FromStr;

pub const SHARED_KEY_BITS: usize = 252;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcXmr;

impl Swap for BtcXmr {
    /// The arbitrating blockchain
    type Ar = Bitcoin<SegwitV0>;

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

impl Sign<bitcoin::PublicKey, bitcoin::PrivateKey, Sha256dHash, Signature, Signature> for Wallet {
    fn sign_with_key(
        &self,
        key: &bitcoin::PublicKey,
        msg: Sha256dHash,
    ) -> Result<Signature, crypto::Error> {
        sign_hash(msg, &self.get_btc_privkey_by_pub(key)?.key).map_err(|e| crypto::Error::new(e))
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
        key: &bitcoin::PublicKey,
        _adaptor: &bitcoin::PublicKey,
        msg: Sha256dHash,
    ) -> Result<Signature, crypto::Error> {
        // FIXME this ignore the adaptor
        sign_hash(msg, &self.get_btc_privkey_by_pub(key)?.key).map_err(|e| crypto::Error::new(e))
    }

    fn verify_adaptor_signature(
        &self,
        key: &bitcoin::PublicKey,
        _adaptor: &bitcoin::PublicKey,
        msg: Sha256dHash,
        sig: &Signature,
    ) -> Result<(), crypto::Error> {
        // FIXME this ignore the adaptor
        let secp = Secp256k1::new();
        let message = Message::from_slice(&msg).expect("Hash is always ok");
        secp.verify(&message, &sig, &key.key)
            .map_err(|e| crypto::Error::new(e))
    }

    fn adapt_signature(
        &self,
        _key: &bitcoin::PublicKey,
        sig: Signature,
    ) -> Result<Signature, crypto::Error> {
        Ok(sig)
    }

    fn recover_key(&self, _sig: Signature, _adapted_sig: Signature) -> bitcoin::PrivateKey {
        todo!()
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
