use crate::consensus::{self, Decodable, Encodable};
use strict_encoding::{StrictDecode, StrictEncode};

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

#[derive(Debug, Clone, StrictDecode, StrictEncode)]
pub struct Address(pub bitcoin::Address);

impl From<bitcoin::Address> for Address {
    fn from(address: bitcoin::Address) -> Self {
        Self(address)
    }
}

impl AsRef<bitcoin::Address> for Address {
    fn as_ref(&self) -> &bitcoin::Address {
        &self.0
    }
}

impl Encodable for Address {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.0.to_string(), writer)
    }
}

impl Decodable for Address {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: String = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        let add: bitcoin::Address = FromStr::from_str(&bytes)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        Ok(Address(add))
    }
}
