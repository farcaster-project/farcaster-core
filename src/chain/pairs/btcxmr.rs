use strict_encoding::{StrictDecode, StrictEncode};

use crate::crypto::{self, AccordantKey, Commitment, DleqProof};
use crate::swap::Swap;

use crate::chain::bitcoin::Bitcoin;
use crate::chain::monero::{self as xmr, Monero};

use monero::cryptonote::hash::Hash;

use bitcoin::secp256k1::key::SecretKey;
use bitcoin::secp256k1::Secp256k1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcXmr;

impl Swap for BtcXmr {
    /// The arbitrating blockchain
    type Ar = Bitcoin;

    /// The accordant blockchain
    type Ac = Monero;

    /// The proof system to link both cryptographic groups
    type Proof = RingProof;
}

impl Commitment for BtcXmr {
    type Commitment = Hash;

    fn commit_to<T: AsRef<[u8]>>(value: T) -> Hash {
        Hash::hash(value.as_ref())
    }
}

#[derive(Clone, Debug)]
pub struct RingProof;

impl DleqProof<Bitcoin, Monero> for RingProof {
    fn project_over(ac_engine: &xmr::Wallet) -> Result<bitcoin::PublicKey, crypto::Error> {
        let secp = Secp256k1::new();
        let spend = ac_engine.get_privkey(AccordantKey::Spend)?;
        let bytes = spend.to_bytes(); // FIXME warn this copy the priv key
        let adaptor = SecretKey::from_slice(&bytes).map_err(|e| crypto::Error::new(e))?;

        Ok(bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::Network::Bitcoin,
            key: adaptor,
        }
        .public_key(&secp))
    }

    fn generate(
        ac_engine: &xmr::Wallet,
    ) -> Result<(monero::PublicKey, bitcoin::PublicKey, Self), crypto::Error> {
        let spend = ac_engine.get_privkey(AccordantKey::Spend)?;
        let adaptor = Self::project_over(&ac_engine)?;

        Ok((
            monero::PublicKey::from_private_key(&spend),
            adaptor,
            // TODO
            Self,
        ))
    }

    fn verify(
        _spend: &monero::PublicKey,
        _adaptor: &bitcoin::PublicKey,
        _proof: Self,
    ) -> Result<(), crypto::Error> {
        Ok(())
    }
}

impl StrictEncode for RingProof {
    fn strict_encode<E: std::io::Write>(&self, mut _e: E) -> Result<usize, strict_encoding::Error> {
        Ok(0)
    }
}

impl StrictDecode for RingProof {
    fn strict_decode<D: std::io::Read>(mut _d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self)
    }
}
