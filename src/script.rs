//! Data structures used in scripts to create the arbitration engine on a blockchain.

use crate::blockchain::Timelock;
use crate::crypto::Keys;

/// Store public keys for swap participants, one public key per [`SwapRole`] in the protocol.
///
/// [`SwapRole`]: crate::role::SwapRole
#[derive(Debug, Clone, Display)]
#[display("Alice: {alice}, Bob: {bob}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct DoubleKeys<T>
where
    T: Keys,
{
    /// Public key associated to Alice swap role.
    pub alice: T::PublicKey,
    /// Public key associated to Bob swap role.
    pub bob: T::PublicKey,
}

impl<T> DoubleKeys<T>
where
    T: Keys,
{
    /// Store public keys for swap participant.
    pub fn new(alice: T::PublicKey, bob: T::PublicKey) -> Self {
        Self { alice, bob }
    }
}

/// Define the path selected for a failable script.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
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
pub struct DataLock<T>
where
    T: Timelock + Keys,
{
    pub timelock: T::Timelock,
    pub success: DoubleKeys<T>,
    pub failure: DoubleKeys<T>,
}

/// Store Alice and Bob public keys for the sucessful and failure paths and the timelock value used
/// to create a lock and remove the double spending problem and create an unilateral punishment
/// mechanisms in [`Cancelable`].
///
/// [`Cancelable`]: crate::transaction::Cancelable
#[derive(Debug, Clone, Display)]
#[display("Timelock: {timelock}, Success: <{success}>, Failure: {failure}")]
pub struct DataPunishableLock<T>
where
    T: Timelock + Keys,
{
    pub timelock: T::Timelock,
    pub success: DoubleKeys<T>,
    pub failure: T::PublicKey,
}
