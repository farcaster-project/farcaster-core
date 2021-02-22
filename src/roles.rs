//! Protocol roles

use crate::blockchains::Blockchain;

pub enum NegotiationRole {
    Maker,
    Taker,
}

pub struct Maker {}

pub struct Taker {}

pub trait Role {}

pub enum SwapRole {
    Alice,
    Bob,
}

pub struct Alice {}

impl Role for Alice {}

pub struct Bob {}

impl Role for Bob {}

pub enum BlockchainRole {
    Arbitrating,
    Accordant,
}

pub trait Arbitrating: Blockchain {}
pub trait Accordant: Blockchain {}
