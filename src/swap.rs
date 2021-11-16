//! Defines the high level of a swap between a Arbitrating blockchain and a Accordant blockchain
//! and its concrete instances of swaps.

use std::fmt::{self, Debug};
use std::io;
#[cfg(feature = "serde")]
use std::str::FromStr;

use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};
#[cfg(feature = "serde")]
use crate::hash::HashString;
use crate::role::{Accordant, Arbitrating};

use lightning_encoding::strategies::AsStrict;
#[cfg(feature = "serde")]
use serde_crate::{de, Deserialize, Deserializer, Serialize, Serializer};

pub mod btcxmr;

fixed_hash::construct_fixed_hash!(
    /// A unique swap identifier represented as an 32 bytes hash.
    pub struct SwapId(32);
);

#[cfg(feature = "serde")]
impl Serialize for SwapId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{:#x}", self).as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SwapId {
    fn deserialize<D>(deserializer: D) -> Result<SwapId, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            SwapId::from_str(&deserializer.deserialize_string(HashString)?)
                .map_err(de::Error::custom)?,
        )
    }
}

impl Encodable for SwapId {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for SwapId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(Self::from_slice(&bytes))
    }
}

impl_strict_encoding!(SwapId);

impl lightning_encoding::Strategy for SwapId {
    type Strategy = AsStrict;
}

/// Specify the context of a swap, fixing the arbitrating blockchain, the accordant blockchain and
/// the link between them.
pub trait Swap: Debug + Clone {
    /// The arbitrating blockchain concrete implementation used for the swap.
    type Ar: Arbitrating;

    /// The accordant blockchain concrete implementation used for the swap.
    type Ac: Accordant;

    /// The proof type used to link both blockchain cryptographic groups to ensure correct secret
    /// transmition.
    type Proof: Clone + Debug + CanonicalBytes;

    /// Commitment type used in the commit/reveal scheme during swap setup.
    type Commitment: Clone + PartialEq + Eq + Debug + fmt::Display + CanonicalBytes;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use super::*;

    #[test]
    #[cfg(feature = "serde")]
    fn serialize_swapid_in_yaml() {
        let swap_id =
            SwapId::from_str("0x1baf1b36075de25a0f8e914b36759cac6f5d825622f8ccee597d87d4850c0d38")
                .expect("Valid hex string");
        let s = serde_yaml::to_string(&swap_id).expect("Encode swap id in yaml");
        assert_eq!(
            "---\n\"0x1baf1b36075de25a0f8e914b36759cac6f5d825622f8ccee597d87d4850c0d38\"\n",
            s
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn deserialize_swapid_from_yaml() {
        let s = "---\n\"0x1baf1b36075de25a0f8e914b36759cac6f5d825622f8ccee597d87d4850c0d38\"\n";
        let swap_id = serde_yaml::from_str(&s).expect("Decode swap id from yaml");
        assert_eq!(
            SwapId::from_str("0x1baf1b36075de25a0f8e914b36759cac6f5d825622f8ccee597d87d4850c0d38")
                .expect("Valid hex string"),
            swap_id
        );
    }
}
