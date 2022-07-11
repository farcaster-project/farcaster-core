//! Timelock unit and `OP_CODE` to use in Bitcoin transactions and scripts.

use crate::consensus::{self, CanonicalBytes};

use std::fmt::Debug;
use std::str::FromStr;

impl FromStr for CSVTimelock {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u32>()
            .map_err(|_| consensus::Error::ParseFailed("Failed parsing CSV timelock"))?;
        Ok(CSVTimelock(x))
    }
}

/// An `OP_CSV` value (32-bits integer) to use in transactions and scripts.
#[derive(PartialEq, Eq, PartialOrd, Clone, Debug, Copy, Display, Serialize, Deserialize)]
#[display("{0} blocks")]
pub struct CSVTimelock(u32);

impl CSVTimelock {
    /// Create a new raw check sequence verify timelock of given value.
    pub fn new(timelock: u32) -> Self {
        Self(timelock)
    }

    /// Return the value of the check sequence verify.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Return the value of nSequence that disable `CHECK_SEQUENCE_VERIFY`.
    pub fn disable() -> u32 {
        (1 << 31) as u32
    }
}

impl CanonicalBytes for CSVTimelock {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self.0)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(CSVTimelock(
            bitcoin::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)?,
        ))
    }
}
