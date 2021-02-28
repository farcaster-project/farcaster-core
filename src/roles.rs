//! Protocol roles

use crate::blockchains::Blockchain;

/// Three network that need to be defined for every blockchains
pub trait Network: Copy {}

/// Mainnet works with real assets
#[derive(Clone, Copy)]
pub struct Mainnet;

impl Network for Mainnet {}

/// Testnet works with decentralized testing network for both chains
#[derive(Clone, Copy)]
pub struct Testnet;

impl Network for Testnet {}

/// Local works with local blockchains for both chains
#[derive(Clone, Copy)]
pub struct Local;

impl Network for Local {}

pub enum NegotiationRole {
    Maker,
    Taker,
}

pub struct Maker;

pub struct Taker;

pub trait Role {}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SwapRole {
    Alice,
    Bob,
}

pub struct Alice;

impl Role for Alice {}

pub struct Bob;

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

    //// Defines the type of timelock used for the arbitrating transactions
    type Timelock: Copy;

    /// Return if the blockchain implements the Arbitrating role, returns true
    fn can_play_arbitrating_role(&self) -> bool {
        true
    }
}

pub trait Accordant: Blockchain {
    /// Private key type for the blockchain
    type PrivateKey;

    /// Public key type for the blockchain
    type PublicKey;

    /// Commitment type for the blockchain
    type Commitment;

    /// Return if the blockchain implements the Accordant role, returns true
    fn can_play_accordant_role(&self) -> bool {
        true
    }
}
