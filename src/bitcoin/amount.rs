use crate::consensus::{self, CanonicalBytes};
use bitcoin::Amount;

impl CanonicalBytes for Amount {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self.as_sat())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(Amount::from_sat(
            bitcoin::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)?,
        ))
    }
}
