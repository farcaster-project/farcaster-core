//! Roles during negotiation and swap phases, blockchain roles, and network definitions.

use std::fmt::Debug;
use std::io;

use crate::blockchain::{Blockchain, Fee, Onchain};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{Commitment, Keys, ShareablePrivateKeys, Signatures};
use strict_encoding::{StrictDecode, StrictEncode};

/// Defines all possible negociation roles: maker and taker.
pub enum NegotiationRole {
    /// The maker role create the public offer during the negotiation phase and waits for incoming
    /// connections.
    Maker,
    /// The taker role parses public offers and choose to connect to a maker node to start
    /// swapping.
    Taker,
}

/// A maker is one that creates and share a public offer and start his daemon in listening mode so
/// one taker can connect and start interacting with him.
pub struct Maker;

/// A taker parses offers and, if interested, connects to the peer registred in the offer.
pub struct Taker;

/// Definition of a swap role.
pub trait Role {}

impl std::str::FromStr for SwapRole {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Alice" => Ok(SwapRole::Alice),
            "Bob" => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::ParseFailed("Bob or Alice valid")),
        }
    }
}

/// Defines all possible swap roles: alice and bob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapRole {
    /// Alice or the AccordantSeller
    Alice,
    /// Bob or the ArbitratingSeller
    Bob,
}

impl Encodable for SwapRole {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            SwapRole::Alice => 0x01u8.consensus_encode(writer),
            SwapRole::Bob => 0x02u8.consensus_encode(writer),
        }
    }
}

impl Decodable for SwapRole {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(SwapRole::Alice),
            0x02u8 => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::UnknownType),
        }
    }
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
    /// The arbitrating blockchain is used to conduct the swap as a decision engine and to
    /// guarentee the refund process.
    Arbitrating,
    /// The accordant blockchain is the blockchain with no on-chain features, such as e.g.
    /// timelocks or hashlocks, needed to complete the swap.
    Accordant,
}

/// An arbitrating is the blockchain which will act as the decision engine, the arbitrating
/// blockchain will use transaction to transfer the funds on both blockchains.
pub trait Arbitrating:
    Blockchain + Keys + Commitment + Signatures + Onchain + Fee + Clone + Eq
{
    /// Defines the address format for the arbitrating blockchain
    type Address: Clone + Debug + StrictEncode + StrictDecode;
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock: Copy + Debug + Encodable + Decodable + PartialEq + Eq;

    /// Returns the blockchain role
    fn role(&self) -> BlockchainRole {
        BlockchainRole::Arbitrating
    }
}

/// An accordant is the blockchain which does not need transaction inside the protocol nor
/// timelocks, it is the blockchain with the less requirements for an atomic swap.
pub trait Accordant: Blockchain + Keys + Commitment + Clone + ShareablePrivateKeys + Eq {
    /// Returns the blockchain role
    fn role(&self) -> BlockchainRole {
        BlockchainRole::Accordant
    }
}
