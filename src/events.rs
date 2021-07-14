use std::io;

use crate::consensus::{self, Decodable, Encodable};

pub trait EventCore {
    fn id(&self) -> i32;
}

#[derive(Debug, Clone)]
pub struct HeightChanged {
    pub id: i32,
    pub block: Vec<u8>,
    pub height: u64,
}

impl Encodable for HeightChanged {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.block.consensus_encode(s)?;
        Ok(len + self.height.consensus_encode(s)?)
    }
}

impl Decodable for HeightChanged {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            block: Vec::<u8>::consensus_decode(d)?,
            height: u64::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(HeightChanged);

impl EventCore for HeightChanged {
    fn id(&self) -> i32 {
        self.id
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    HeightChanged,
}
