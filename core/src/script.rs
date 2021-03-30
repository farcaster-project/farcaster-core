//! Script mechanism used to create the arbitration on one blockchain

use crate::crypto::Keys;
use crate::role::Arbitrating;

/// Represent a public key-pair, one key per swap role in the system.
#[derive(Clone)]
pub struct DoubleKeys<Ar>
where
    Ar: Keys,
{
    pub alice: Ar::PublicKey,
    pub bob: Ar::PublicKey,
}

impl<Ar> DoubleKeys<Ar>
where
    Ar: Keys,
{
    /// Create a new key pair
    pub fn new(alice: Ar::PublicKey, bob: Ar::PublicKey) -> Self {
        Self { alice, bob }
    }
}

/// Define the path in a script with its associated data.
#[derive(Debug, PartialEq)]
pub enum ScriptPath {
    Success,
    Failure,
}

/// The data used to create a lock and remove the double spending problem and create a mutually
/// agreed refundable path.
#[derive(Clone)]
pub struct DataLock<Ar>
where
    Ar: Arbitrating,
{
    pub timelock: Ar::Timelock,
    pub success: DoubleKeys<Ar>,
    pub failure: DoubleKeys<Ar>,
}

/// The data used to create a lock and remove the double spending problem and create an unilateral
/// punishment mechanism.
#[derive(Clone)]
pub struct DataPunishableLock<Ar>
where
    Ar: Arbitrating,
{
    pub timelock: Ar::Timelock,
    pub success: DoubleKeys<Ar>,
    pub failure: Ar::PublicKey,
}
