use bitcoin::util::amount;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::consensus::{self, Decodable, Encodable};

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

impl FromStr for Amount {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u64>()
            .map_err(|_| consensus::Error::ParseFailed("Failed to parse amount"))?;
        Ok(Self(amount::Amount::from_sat(x)))
    }
}

/// Bitcoin amount wrapper
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, StrictDecode, StrictEncode)]
pub struct Amount(amount::Amount);

impl Amount {
    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    pub fn from_sat(sat: u64) -> Self {
        Self(amount::Amount::from_sat(sat))
    }

    pub fn checked_mul(&self, other: u64) -> Option<Self> {
        Some(Self(self.0.checked_mul(other)?))
    }

    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        Some(Self(self.0.checked_sub(other.0)?))
    }
}

impl Encodable for Amount {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.as_sat(), writer)
    }
}

impl Decodable for Amount {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let sats: u64 = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin amount parsing failed"))?;
        Ok(Amount::from_sat(sats))
    }
}
