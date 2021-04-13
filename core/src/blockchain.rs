//! Defines the interface a blockchain must implement
//!
//! A blockchain must identify the block chain (or equivalent), e.g. with the genesis hash, and the
//! asset, e.g. for Etherum blockchain assets can be eth or dai.

use std::fmt::Debug;
use std::io;
use std::ops::Range;
use std::str::FromStr;

use strict_encoding::{StrictDecode, StrictEncode};

use thiserror::Error;

use crate::consensus::{self, Decodable, Encodable};

/// Defines the asset identifier for a blockchain and its associated asset unit type.
pub trait Asset: Copy + Debug + Encodable + Decodable {
    /// Type for the traded asset unit
    type AssetUnit: Copy + Debug + Encodable + Decodable;

    /// Create a new blockchain
    fn new() -> Self;

    /// Parse an 32 bits identifier as defined in [SLIP
    /// 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044)
    /// and return a blockchain if existant
    fn from_u32(bytes: u32) -> Option<Self>;

    /// Return the 32 bits identifier for the blockchain as defined in [SLIP
    /// 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044)
    fn to_u32(&self) -> u32;
}

impl<T: Asset> Encodable for T {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.to_u32().consensus_encode(writer)
    }
}

impl<T: Asset> Decodable for T {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let identifier: u32 = Decodable::consensus_decode(d)?;
        // Follows Farcaster RFC 10
        if identifier == 0x80000001 {
            return Err(consensus::Error::UnknownType);
        }
        Self::from_u32(identifier).ok_or(consensus::Error::UnknownType)
    }
}

/// Defines the types a blockchain needs to interact onchain, i.e. the transaction types.
pub trait Onchain {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction: Clone + Debug + StrictEncode + StrictDecode;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction;
}

impl<T> FromStr for FeeStrategy<T>
where
    T: Clone
        + PartialOrd
        + PartialEq
        + Encodable
        + Decodable
        + StrictEncode
        + StrictDecode
        + FromStr,
{
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // range parsing not implemented
        match s.parse::<T>() {
            Ok(x) => Ok(Self::Fixed(x)),
            Err(_) => Err(consensus::Error::ParseFailed("Failed parsing FeeStrategy")),
        }
    }
}

/// A fee strategy to be applied on an arbitrating transaction. As described in the specifications
/// a fee strategy can be: fixed or range.
///
/// A fee strategy is included in an offer, so Alice and Bob can verify that transactions are valid
/// upon reception by the other participant.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + Encodable + Decodable,
{
    /// A fixed strategy with the exact amount to set
    Fixed(T),
    /// A range with a minimum and maximum (inclusive) possible fees
    Range(Range<T>),
}

impl<T> Encodable for FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + Encodable + Decodable,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            FeeStrategy::Fixed(t) => {
                0x01u8.consensus_encode(writer)?;
                Ok(wrap_in_vec!(wrap t in writer) + 1)
            }
            FeeStrategy::Range(Range { start, end }) => {
                0x02u8.consensus_encode(writer)?;
                let len = wrap_in_vec!(wrap start in writer);
                Ok(wrap_in_vec!(wrap end in writer) + len + 1)
            }
        }
    }
}

impl<T> Decodable for FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + Encodable + Decodable,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(FeeStrategy::Fixed(unwrap_from_vec!(d))),
            0x02u8 => {
                let start = unwrap_from_vec!(d);
                let end = unwrap_from_vec!(d);
                Ok(FeeStrategy::Range(Range { start, end }))
            }
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// Define the type of errors a fee strategy can encounter during calculation, application, and
/// validation of fees on a partial transaction.
#[derive(Error, Debug, PartialEq)]
pub enum FeeStrategyError {
    /// Missing metadata inputs
    #[error("Missing metadata inputs")]
    MissingInputsMetadata,
    /// Fee amount is too high
    #[error("Fee amount is too high")]
    AmountOfFeeTooHigh,
    /// Not enough assets to cover the fees
    #[error("Not enough assets to cover the fees")]
    NotEnoughAssets,
    /// Multi-input transaction is not supported
    #[error("Multi-input transaction is not supported")]
    MultiOutputUnsupported,
}

/// Defines how to set the fees when a strategy allows multiple possibilities.
#[derive(Debug, Clone, Copy)]
pub enum FeePolitic {
    /// Set the fees at the minimum allowed by the strategy
    Aggressive,
    /// Set the fees at the maximum allowed by the strategy
    Conservative,
}

/// Enable fee management for an arbitrating blockchain. This trait require implementing the
/// Onchain role to have access to transaction associated type and to specify the concrete fee
/// strategy type to use.
pub trait Fee: Onchain + Asset {
    /// Type for describing the fees of a blockchain
    type FeeUnit: Clone + Debug + PartialOrd + PartialEq + Encodable + Decodable + PartialEq + Eq;

    /// Calculates and sets the fees on the given transaction and return the amount of fees set in
    /// the blockchain native amount format.
    fn set_fees(
        tx: &mut Self::PartialTransaction,
        strategy: &FeeStrategy<Self::FeeUnit>,
        politic: FeePolitic,
    ) -> Result<Self::AssetUnit, FeeStrategyError>;

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(
        tx: &Self::PartialTransaction,
        strategy: &FeeStrategy<Self::FeeUnit>,
        politic: FeePolitic,
    ) -> Result<bool, FeeStrategyError>;
}

impl FromStr for Network {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Mainnet" => Ok(Network::Mainnet),
            "Testnet" => Ok(Network::Testnet),
            "Local" => Ok(Network::Local),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// Defines a blockchain network, identifies in which context the system interacts with the
/// blockchain.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
pub enum Network {
    /// Represents a real asset on his valuable network
    Mainnet,
    /// Represents non-valuable assets on test networks
    Testnet,
    /// Local and private testnets
    Local,
}

impl Encodable for Network {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            Network::Mainnet => 0x01u8.consensus_encode(writer),
            Network::Testnet => 0x02u8.consensus_encode(writer),
            Network::Local => 0x03u8.consensus_encode(writer),
        }
    }
}

impl Decodable for Network {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(Network::Mainnet),
            0x02u8 => Ok(Network::Testnet),
            0x03u8 => Ok(Network::Local),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}
