//! Script mechanism used to create the arbitration on one blockchain

use crate::role::Arbitrating;

pub struct DoubleKeys<Ar>
where
    Ar: Arbitrating,
{
    pub alice: Ar::PublicKey,
    pub bob: Ar::PublicKey,
}

impl<Ar> DoubleKeys<Ar>
where
    Ar: Arbitrating,
{
    pub fn new(alice: Ar::PublicKey, bob: Ar::PublicKey) -> Self {
        Self { alice, bob }
    }
}

/// The lock data used to remove the double spending problem and create a refundable path
/// This lock can be used for 2-party interaction, one timelock only.
pub struct Lock<Ar>
where
    Ar: Arbitrating,
{
    pub timelock: Ar::Timelock,
    pub success: DoubleKeys<Ar>,
    pub failure: DoubleKeys<Ar>,
}
