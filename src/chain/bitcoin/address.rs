use crate::consensus::{self, Decodable, Encodable};
use bitcoin::Address;

use std::io;
use std::str::FromStr;

impl Encodable for Address {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.to_string(), writer)
    }
}

impl Decodable for Address {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: String = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        let add: bitcoin::Address = FromStr::from_str(&bytes)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        Ok(add)
    }
}
