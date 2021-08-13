//! Addendum structures carried through tasks needed by Bitcoin syncers to handle them in the
//! Bitcoin blockchain context.

use crate::consensus::{self, Decodable, Encodable};

use std::io;

/// Empty addendum type for Bitcoin syncer height task.
pub struct BtcHeightAddendum {}

/// Addendum for Bitcoin syncer address task.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct BtcAddressAddendum {
    /// The address the syncer will watch and query.
    pub address: String,
    /// The blockchain height where to start the query.
    pub from_height: u64,
    /// The associated script pubkey used by server like Electrum.
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
