//! Protocol roles

use crate::blockchains::Blockchain;

/// Three network that need to be defined for every blockchains
pub trait Network {}

/// Mainnet works with real assets
pub struct Mainnet;

impl Network for Mainnet {}

/// Testnet works with decentralized testing network for both chains
pub struct Testnet;

impl Network for Testnet {}

/// Local works with local blockchains for both chains
pub struct Local;

impl Network for Local {}

pub enum NegotiationRole {
    Maker,
    Taker,
}

pub struct Maker;

pub struct Taker;

pub trait Role {}

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
    type Timelock;
}

pub trait Accordant: Blockchain {
    /// Private key type for the blockchain
    type PrivateKey;

    /// Public key type for the blockchain
    type PublicKey;

    /// Commitment type for the blockchain
    type Commitment;
}