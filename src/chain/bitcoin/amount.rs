use bitcoin::Amount;

use crate::consensus::{self, Decodable, Encodable};

use std::io;

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
