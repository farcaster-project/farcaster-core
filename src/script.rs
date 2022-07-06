//! Data structures used in scripts to create the arbitration engine on a blockchain.

use std::fmt;

/// Store public keys for swap participants, one public key per [`SwapRole`] in the protocol.
///
/// [`SwapRole`]: crate::role::SwapRole
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DoubleKeys<PublicKey> {
    /// Public key associated to Alice swap role.
    pub alice: PublicKey,
    /// Public key associated to Bob swap role.
    pub bob: PublicKey,
}

impl<PublicKey> DoubleKeys<PublicKey> {
    /// Store public keys for swap participant.
    pub fn new(alice: PublicKey, bob: PublicKey) -> Self {
        Self { alice, bob }
    }
}

impl<PublicKey> fmt::Display for DoubleKeys<PublicKey>
where
    PublicKey: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Alice: {}, Bob: {}", self.alice, self.bob)
    }
}

/// Define the path selected for a failable script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, Serialize, Deserialize)]
#[display(Debug)]
pub enum ScriptPath {
    /// The success path in the script.
    Success,
    /// The success path in the script.
    Failure,
}

/// Store Alice and Bob public keys for the sucessful and failure paths and the timelock value used
/// to create a lock and remove the double spending problem and create a mutually agreed refundable
/// path used in [`Buyable`].
///
/// [`Buyable`]: crate::transaction::Buyable
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DataLock<Timelock, PublicKey> {
    pub timelock: Timelock,
    pub success: DoubleKeys<PublicKey>,
    pub failure: DoubleKeys<PublicKey>,
}

impl<Timelock, PublicKey> fmt::Display for DataLock<Timelock, PublicKey>
where
    Timelock: fmt::Display,
    PublicKey: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Timelock: {}, Success: <{}>, Failure: <{}>",
            self.timelock, self.success, self.failure
        )
    }
}

/// Store Alice and Bob public keys for the sucessful and failure paths and the timelock value used
/// to create a lock and remove the double spending problem and create an unilateral punishment
/// mechanisms in [`Cancelable`].
///
/// [`Cancelable`]: crate::transaction::Cancelable
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DataPunishableLock<Timelock, PublicKey> {
    pub timelock: Timelock,
    pub success: DoubleKeys<PublicKey>,
    pub failure: PublicKey,
}

impl<Timelock, PublicKey> fmt::Display for DataPunishableLock<Timelock, PublicKey>
where
    Timelock: fmt::Display,
    PublicKey: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Timelock: {}, Success: <{}>, Failure: {}",
            self.timelock, self.success, self.failure
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::PublicKey;

    #[test]
    fn serde_serialize_double_keys() {
        let public_key = PublicKey::from_slice(&[
            0x02, 0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55, 0xaf, 0x58, 0x05, 0x98, 0x9d,
            0xa9, 0xfb, 0xf8, 0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c, 0x3a, 0x17, 0x10,
            0xc9, 0x62, 0x67, 0x90, 0x63,
        ])
        .expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
        let double_key = DoubleKeys::<PublicKey>::new(public_key, public_key);
        let s = serde_yaml::to_string(&double_key).unwrap();
        let yml = r#"---
alice: 02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063
bob: 02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063
"#;
        assert_eq!(yml, s);
    }
}
