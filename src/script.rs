//! Data structures used in scripts to create the arbitration engine on a blockchain.

use serde::Serialize;

use crate::blockchain::Timelock;
use crate::crypto::Keys;

/// Store public keys for swap participants, one public key per [`SwapRole`] in the protocol.
///
/// [`SwapRole`]: crate::role::SwapRole
#[derive(Debug, Clone, Display, Serialize)]
#[display("Alice: {alice}, Bob: {bob}")]
#[serde(bound(serialize = "&'a T::PublicKey: Serialize"))]
pub struct DoubleKeys<'a, T>
where
    T: Keys,
{
    /// Public key associated to Alice swap role.
    pub alice: &'a T::PublicKey,
    /// Public key associated to Bob swap role.
    pub bob: &'a T::PublicKey,
}

impl<'a, T> DoubleKeys<'a, T>
where
    T: Keys,
{
    /// Store public keys for swap participant.
    pub fn new(alice: &'a T::PublicKey, bob: &'a T::PublicKey) -> Self {
        Self { alice, bob }
    }
}

/// Define the path selected for a failable script.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Display)]
#[display("Timelock: {timelock}, Success: <{success}>, Failure: <{failure}>")]
pub struct DataLock<'a, T>
where
    T: Timelock + Keys,
{
    pub timelock: T::Timelock,
    pub success: DoubleKeys<'a, T>,
    pub failure: DoubleKeys<'a, T>,
}

/// Store Alice and Bob public keys for the sucessful and failure paths and the timelock value used
/// to create a lock and remove the double spending problem and create an unilateral punishment
/// mechanisms in [`Cancelable`].
///
/// [`Cancelable`]: crate::transaction::Cancelable
#[derive(Debug, Clone, Display)]
#[display("Timelock: {timelock}, Success: <{success}>, Failure: {failure}")]
pub struct DataPunishableLock<'a, T>
where
    T: Timelock + Keys,
{
    pub timelock: T::Timelock,
    pub success: DoubleKeys<'a, T>,
    pub failure: &'a T::PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::BitcoinSegwitV0;

    #[test]
    fn serde_serialize_double_keys() {
        let public_key = bitcoin::secp256k1::PublicKey::from_slice(&[
            0x02, 0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55, 0xaf, 0x58, 0x05, 0x98, 0x9d,
            0xa9, 0xfb, 0xf8, 0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c, 0x3a, 0x17, 0x10,
            0xc9, 0x62, 0x67, 0x90, 0x63,
        ])
        .expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
        let double_key = DoubleKeys::<'_, BitcoinSegwitV0>::new(&public_key, &public_key);
        let s = serde_yaml::to_string(&double_key).unwrap();
        let yml = r#"---
alice: 02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063
bob: 02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063
"#;
        assert_eq!(yml, s);
    }
}
