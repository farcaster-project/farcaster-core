//! Script mechanism used to create the arbitration on one blockchain

use crate::crypto::Keys;
use crate::role::Arbitrating;

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
    /// Create a new double key pair
    pub fn new(alice: Ar::PublicKey, bob: Ar::PublicKey) -> Self {
        Self { alice, bob }
    }
}

/// The data used to create a lock and remove the double spending problem and create a mutually
/// agreed refundable path.
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
pub struct DataPunishableLock<Ar>
where
    Ar: Arbitrating,
{
    pub timelock: Ar::Timelock,
    pub success: DoubleKeys<Ar>,
    pub failure: Ar::PublicKey,
}
