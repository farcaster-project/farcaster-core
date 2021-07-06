use std::io;

pub struct XmrHeightAddendum {}

pub struct XmrAddressAddendum {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub from_height: u64,
}

impl XmrAddressAddendum {
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = self.spend_key.to_vec();
        res.extend(self.view_key.to_vec());
        res.extend(self.from_height.to_le_bytes().to_vec());
        res
    }

    pub fn deserialize(data_vec: Vec<u8>) -> Result<XmrAddressAddendum, io::Error> {
        if data_vec.len() != 32 + 32 + 8 {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Not a serialized pair of keys and u64",
            ))?
        }

        let mut spend_key = [0; 32];
        for i in 0..32 {
            spend_key[i] = data_vec[i];
        }

        let mut view_key = [0; 32];
        for i in 0..32 {
            view_key[i] = data_vec[32 + i];
        }

        let mut height = [0; 8];
        for i in 0..8 {
            height[i] = data_vec[58 + i];
        }

        Ok(XmrAddressAddendum {
            spend_key,
            view_key,
            from_height: u64::from_le_bytes(height),
        })
    }
}
