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

pub trait Arbitrating: Blockchain {
    /// Defines the address format for the arbitrating blockchain
    type Address;
    /// Defines the transaction format for the arbitrating blockchain
    type Transaction;
}

pub trait Accordant: Blockchain {
    /// Private key type for the blockchain
    type PrivateKey;
    /// Public key type for the blockchain
    type PublicKey;
    /// Commitment type for the blockchain
    type Commitment;
}
