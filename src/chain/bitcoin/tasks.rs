#![allow(unused_variables)]

pub struct BtcHeightAddendum {}
pub struct BtcAddressAddendum {
    pub address: String,
    pub from_height: u64,
}

impl BtcAddressAddendum {
    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    pub fn deserialize(data_vec: Vec<u8>) -> Result<BtcAddressAddendum, std::io::Error> {
        todo!()
    }
}
