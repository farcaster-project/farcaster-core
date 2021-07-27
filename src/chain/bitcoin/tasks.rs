use crate::consensus::{self, Decodable, Encodable};

use std::io;

pub struct BtcHeightAddendum {}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct BtcAddressAddendum {
    pub address: String,
    pub from_height: u64,
    pub script_pubkey: Vec<u8>,
}

impl Encodable for BtcAddressAddendum {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.address.consensus_encode(s)?;
        len += self.from_height.consensus_encode(s)?;
        Ok(len + self.script_pubkey.consensus_encode(s)?)
    }
}

impl Decodable for BtcAddressAddendum {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            address: String::consensus_decode(d)?,
            from_height: u64::consensus_decode(d)?,
            script_pubkey: <Vec<u8>>::consensus_decode(d)?,
        })
    }
}

#[test]
fn test_ser_de() {
    let addendum = BtcAddressAddendum {
        address: "".to_string(),
        from_height: 0,
        script_pubkey: vec![0],
    };
    let serialized = consensus::serialize(&addendum);
    let mut res = std::io::Cursor::new(serialized);
    let add = BtcAddressAddendum::consensus_decode(&mut res).unwrap();
    assert_eq!(add.from_height, addendum.from_height);
    assert_eq!(add.script_pubkey, addendum.script_pubkey);
}
