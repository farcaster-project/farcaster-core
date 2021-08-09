use crate::consensus::{self, CanonicalBytes};
use bitcoin::Address;

use std::str::{self, FromStr};

impl CanonicalBytes for Address {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_string().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(
            Address::from_str(str::from_utf8(bytes).map_err(consensus::Error::new)?)
                .map_err(consensus::Error::new)?,
        )
    }
}
