use strict_encoding::{StrictDecode, StrictEncode};

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

#[derive(PartialEq, Eq, PartialOrd, Clone, Debug, StrictDecode, StrictEncode, Copy)]
pub struct CSVTimelock(u32);

impl CSVTimelock {
    pub fn new(timelock: u32) -> Self {
        Self(timelock)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
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
