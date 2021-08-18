//! Extra data carried through tasks specific to Monero.

use crate::consensus::{self, Decodable, Encodable};

use std::io;

/// Empty addendum for height watching task.
pub struct XmrHeightAddendum {}

/// Keys and height required to watch and parse transactions linked to some address.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct XmrAddressAddendum {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub from_height: u64,
}

impl Encodable for XmrAddressAddendum {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.spend_key.consensus_encode(s)?;
        len += self.view_key.consensus_encode(s)?;
        Ok(len + self.from_height.consensus_encode(s)?)
    }
}

impl Decodable for XmrAddressAddendum {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            spend_key: <[u8; 32]>::consensus_decode(d)?,
            view_key: <[u8; 32]>::consensus_decode(d)?,
            from_height: u64::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(XmrAddressAddendum);

#[test]
fn test_ser_de() {
    let addendum = XmrAddressAddendum {
        spend_key: [0; 32],
        view_key: [0; 32],
        from_height: 0,
    };
    let serialized = consensus::serialize(&addendum);
    let mut res = std::io::Cursor::new(serialized);
    let add = XmrAddressAddendum::consensus_decode(&mut res).unwrap();
    assert_eq!(add.from_height, addendum.from_height);
    assert_eq!(add.spend_key, [0; 32]);
}
