//! Script mechanism used to create the arbitration on one blockchain

use crate::blockchain::Timelock;
use crate::crypto::Keys;

/// Represent a public key-pair, one key per swap role in the system.
#[derive(Debug, Clone)]
pub struct DoubleKeys<T>
where
    T: Keys,
{
    pub alice: T::PublicKey,
    pub bob: T::PublicKey,
}

impl<T> DoubleKeys<T>
where
    T: Keys,
{
    /// Create a new key pair
    pub fn new(alice: T::PublicKey, bob: T::PublicKey) -> Self {
        Self { alice, bob }
    }
}

/// Define the path in a script with its associated data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptPath {
    /// The success path in the script.
    Success,
    /// The success path in the script.
    Failure,
}

/// The data used to create a lock and remove the double spending problem and create a mutually
/// agreed refundable path.
#[derive(Debug, Clone)]
pub struct DataLock<T>
where
    T: Timelock + Keys,
{
    pub timelock: T::Timelock,
    pub success: DoubleKeys<T>,
    pub failure: DoubleKeys<T>,
}

/// The data used to create a lock and remove the double spending problem and create an unilateral
/// punishment mechanism.
#[derive(Debug, Clone)]
pub struct DataPunishableLock<T>
where
    T: Timelock + Keys,
{
    pub timelock: T::Timelock,
    pub success: DoubleKeys<T>,
    pub failure: T::PublicKey,
}
