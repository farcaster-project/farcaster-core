//! Roles during negotiation and swap phases, blockchain roles, and network definitions.

use crate::blockchain::{Blockchain, Onchain};
use crate::crypto::{Commitment, Curve, Keys, Script, Signatures};

/// Defines all possible negociation roles: maker and taker.
pub enum NegotiationRole {
    Maker,
    Taker,
}

/// A maker is one that creates and share a public offer and start his daemon in listening mode so
/// one taker can connect and start interacting with him.
pub struct Maker;

/// A taker parses offers and, if interested, connects to the peer registred in the offer.
pub struct Taker;

/// Definition of a swap role.
pub trait Role {}

/// Defines all possible swap roles: alice and bob.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SwapRole {
    Alice,
    Bob,
}

/// Alice, the swap role, is the role starting with accordant blockchain assets and exchange them
/// for arbitrating blockchain assets.
pub struct Alice;

impl Role for Alice {}

/// Bob, the swap role, is the role starting with arbitrating blockchain assets and exchange them
/// for accordant blockchain assets.
pub struct Bob;

impl Role for Bob {}

/// Defines all possible blockchain roles: arbitrating and accordant.
pub enum BlockchainRole {
    Arbitrating,
    Accordant,
}

/// An arbitrating is the blockchain which will act as the decision engine, the arbitrating
/// blockchain will use transaction to transfer the funds on both blockchains.
pub trait Arbitrating:
    Blockchain + Keys + Commitment + Signatures + Curve + Script + Onchain
{
    /// Defines the address format for the arbitrating blockchain
    type Address;

    //// Defines the type of timelock used for the arbitrating transactions
    type Timelock: Copy;
}

/// An accordant is the blockchain which does not need transaction inside the protocol nor
/// timelocks, it is the blockchain with the less requirements for an atomic swap.
pub trait Accordant: Blockchain + Keys + Curve + Commitment {}
