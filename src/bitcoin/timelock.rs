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

//! Timelock unit and `OP_CODE` to use in Bitcoin transactions and scripts.

use crate::consensus::{self, CanonicalBytes};

use std::fmt::Debug;
use std::str::FromStr;

/// An `OP_CSV` value (32-bits integer) to use in transactions and scripts.
#[derive(PartialEq, Eq, PartialOrd, Clone, Debug, Hash, Copy, Display, Serialize, Deserialize)]
#[display("{0} blocks")]
pub struct CSVTimelock(u32);

impl FromStr for CSVTimelock {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u32>()
            .map_err(|_| consensus::Error::ParseFailed("Failed parsing CSV timelock"))?;
        Ok(CSVTimelock(x))
    }
}

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

impl From<u32> for CSVTimelock {
    fn from(u: u32) -> Self {
        Self::new(u)
    }
}

impl From<CSVTimelock> for u32 {
    fn from(ti: CSVTimelock) -> Self {
        ti.as_u32()
    }
}

impl From<u16> for CSVTimelock {
    fn from(u: u16) -> Self {
        Self::new(u as u32)
    }
}

impl From<u8> for CSVTimelock {
    fn from(u: u8) -> Self {
        Self::new(u as u32)
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
