//! Negotiation Phase utilities

use crate::blockchains::Blockchain;
use crate::roles::{Accordant, Arbitrating};

use crate::roles::SwapRole;

pub struct Offer<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub arbitrating: Ar,
    pub accordant: Ac,
    pub arbitrating_assets: Ar::AssetUnit,
    pub accordant_assets: Ac::AssetUnit,
    pub cancel_timelock: u64,
    pub punish_timelock: u64,
}

pub struct PublicOffer<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub offer: Offer<Ar, Ac>,
    pub maker_role: SwapRole,
    pub daemon_service: String,
}
