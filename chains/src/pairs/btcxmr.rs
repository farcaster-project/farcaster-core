use strict_encoding::{StrictDecode, StrictEncode};

use farcaster_core::crypto::{self, DleqProof};
use farcaster_core::swap::Swap;

use crate::bitcoin::Bitcoin;
use crate::monero::{private_spend_from_seed, Monero};

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

#[derive(Clone, Debug)]
pub struct RingProof;

impl DleqProof<Bitcoin, Monero> for RingProof {
    fn generate(ac_seed: &[u8; 32]) -> (monero::PublicKey, bitcoin::PublicKey, Self) {
        let secp = Secp256k1::new();

        let spend = private_spend_from_seed(&ac_seed);
        let bytes = spend.to_bytes(); // warn this copy the priv key
        let adaptor = SecretKey::from_slice(&bytes).unwrap();

        (
            monero::PublicKey::from_private_key(&spend),
            bitcoin::PublicKey::from_private_key(
                &secp,
                &bitcoin::PrivateKey {
                    compressed: true,
                    network: bitcoin::Network::Bitcoin,
                    key: adaptor,
                },
            ),
            // TODO
            Self,
        )
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
