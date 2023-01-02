// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

//! Data structures used in scripts to create the arbitration engine on a blockchain.

use std::fmt;

/// Store public keys for swap participants, one public key per [`SwapRole`] in the protocol.
///
/// [`SwapRole`]: crate::role::SwapRole
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SwapRoleKeys<Pk> {
    /// Public key associated to Alice swap role.
    pub alice: Pk,
    /// Public key associated to Bob swap role.
    pub bob: Pk,
}

impl<Pk> SwapRoleKeys<Pk> {
    /// Store public keys for swap participant.
    pub fn new(alice: Pk, bob: Pk) -> Self {
        Self { alice, bob }
    }
}

impl<Pk> fmt::Display for SwapRoleKeys<Pk>
where
    Pk: fmt::Display,
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
pub struct DataLock<Ti, Pk> {
    pub timelock: Ti,
    pub success: SwapRoleKeys<Pk>,
    pub failure: SwapRoleKeys<Pk>,
}

impl<Ti, Pk> fmt::Display for DataLock<Ti, Pk>
where
    Ti: fmt::Display,
    Pk: fmt::Display,
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
pub struct DataPunishableLock<Ti, Pk> {
    pub timelock: Ti,
    pub success: SwapRoleKeys<Pk>,
    pub failure: Pk,
}

impl<Ti, Pk> fmt::Display for DataPunishableLock<Ti, Pk>
where
    Ti: fmt::Display,
    Pk: fmt::Display,
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
        let double_key = SwapRoleKeys::<PublicKey>::new(public_key, public_key);
        let s = serde_yaml::to_string(&double_key).unwrap();
        let yml = r#"---
alice: 02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063
bob: 02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063
"#;
        assert_eq!(yml, s);
    }
}
