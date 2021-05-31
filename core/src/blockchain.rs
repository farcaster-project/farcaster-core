//! Defines the interface a blockchain must implement
//!
//! A blockchain must identify the block chain (or equivalent), e.g. with the genesis hash, and the
//! asset, e.g. for Etherum blockchain assets can be eth or dai.

use std::error;
use std::fmt::Debug;
use std::io;
use std::ops::Range;
use std::str::FromStr;

use strict_encoding::{StrictDecode, StrictEncode};

use thiserror::Error;

use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{Keys, Signatures};
use crate::transaction::{Buyable, Cancelable, Fundable, Lockable, Punishable, Refundable};

/// Defines the type for a blockchain address, this type is used when manipulating transactions.
pub trait Address {
    /// Defines the address format for the arbitrating blockchain.
    type Address: Clone + Debug + StrictEncode + StrictDecode;

    fn as_bytes(data: &Self::Address) -> Result<Vec<u8>, io::Error>;

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self::Address, consensus::Error>;
}

/// Defines the type for a blockchain timelock, this type is used when manipulating transactions
/// and is carried in the [Offer](crate::negotiation::Offer) to fix the two timelocks.
pub trait Timelock {
    /// Defines the type of timelock used for the arbitrating transactions.
    type Timelock: Copy + PartialEq + Eq + Debug;

    fn as_bytes(data: &Self::Timelock) -> Result<Vec<u8>, io::Error>;

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self::Timelock, consensus::Error>;
}

/// Defines the asset identifier for a blockchain and its associated asset unit type, it is carried
/// in the [Offer](crate::negotiation::Offer) to fix exchanged amounts.
pub trait Asset: Copy + Debug {
    /// Type for the traded asset unit for a blockchain.
    type AssetUnit: Copy + Eq + Debug + Encodable + Decodable;

    /// Create a new blockchain.
    fn new() -> Self;

    /// Parse an 32 bits identifier as defined in [SLIP
    /// 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044)
    /// and return a blockchain if existant.
    fn from_u32(bytes: u32) -> Option<Self>;

    /// Return the 32 bits identifier for the blockchain as defined in [SLIP
    /// 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044).
    fn to_u32(&self) -> u32;
}

/// Defines the types a blockchain needs to interact onchain, i.e. the transaction types.
pub trait Onchain {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction: Clone + Debug + StrictEncode + StrictDecode;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction: Clone + Debug + StrictEncode + StrictDecode;

    fn partial_as_bytes(data: &Self::PartialTransaction) -> Result<Vec<u8>, io::Error>;

    fn partial_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self::PartialTransaction, consensus::Error>;

    fn tx_as_bytes(data: &Self::Transaction) -> Result<Vec<u8>, io::Error>;

    fn tx_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self::Transaction, consensus::Error>;
}

/// Fix the types for all arbitrating transactions needed for the swap: [Fundable], [Lockable],
/// [Buyable], [Cancelable], [Refundable], and [Punishable] transactions.
pub trait Transactions: Timelock + Address + Fee + Keys + Signatures + Sized {
    /// The returned type of the consumable output and the `base_on` transaction method, used to
    /// reference the funds and chain other transactions on it. This must contain all necessary
    /// data to latter create a valid unlocking witness for the output and identify the funds.
    type Metadata: Eq;

    /// Defines the type for the `funding (a)` transaction
    type Funding: Fundable<Self, Self::Metadata>;
    /// Defines the type for the `lock (b)` transaction
    type Lock: Lockable<Self, Self::Metadata>;
    /// Defines the type for the `buy (c)` transaction
    type Buy: Buyable<Self, Self::Metadata>;
    /// Defines the type for the `cancel (d)` transaction
    type Cancel: Cancelable<Self, Self::Metadata>;
    /// Defines the type for the `refund (e)` transaction
    type Refund: Refundable<Self, Self::Metadata>;
    /// Defines the type for the `punish (f)` transaction
    type Punish: Punishable<Self, Self::Metadata>;
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
#[derive(Error, Debug)]
pub enum FeeStrategyError {
    /// Missing metadata on inputs to retreive the amount of asset available.
    #[error("Missing metadata inputs to retreive available amount")]
    MissingInputsMetadata,
    /// Fee amount is too low and does not match the fee strategy requirements.
    #[error("Fee amount is too low")]
    AmountOfFeeTooLow,
    /// Fee amount is too high and does not match the fee strategy requirements.
    #[error("Fee amount is too high")]
    AmountOfFeeTooHigh,
    /// Not enough assets to cover the fees.
    #[error("Not enough assets to cover the fees")]
    NotEnoughAssets,
    /// Any fee strategy error not part of this list.
    #[error("Other: {0}")]
    Other(Box<dyn error::Error + Sync + Send>),
}

impl FeeStrategyError {
    /// Creates a new fee strategy error of type other with an arbitrary payload.
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::Other(error.into())
    }

    /// Consumes the `FeeStrategyError`, returning its inner error (if any).
    ///
    /// If this [`FeeStrategyError`] was constructed via [`new`] then this function will return [`Some`],
    /// otherwise it will return [`None`].
    ///
    /// [`new`]: FeeStrategyError::new
    ///
    pub fn into_inner(self) -> Option<Box<dyn error::Error + Send + Sync>> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

/// Defines how to set the fee when a strategy allows multiple possibilities.
#[derive(Debug, Clone, Copy)]
pub enum FeePolitic {
    /// Set the fee at the minimum allowed by the strategy
    Aggressive,
    /// Set the fee at the maximum allowed by the strategy
    Conservative,
}

/// Enable fee management for an arbitrating blockchain. This trait require implementing the
/// [Onchain] trait to have access to transaction associated type and the [Asset] trait for
/// returning the amount of fee set on a transaction. The fee is carried in the
/// [Offer](crate::negotiation::Offer) through a [FeeStrategy] to fix the strategy to apply on
/// transactions.
pub trait Fee: Onchain + Asset {
    /// Type for describing the fee of a blockchain
    type FeeUnit: Clone + Debug + PartialOrd + PartialEq + Encodable + Decodable + PartialEq + Eq;

    /// Calculates and sets the fee on the given transaction and return the amount of fee set in
    /// the blockchain native amount format.
    fn set_fee(
        tx: &mut Self::PartialTransaction,
        strategy: &FeeStrategy<Self::FeeUnit>,
        politic: FeePolitic,
    ) -> Result<Self::AssetUnit, FeeStrategyError>;

    /// Validates that the fee for the given transaction are set accordingly to the strategy.
    fn validate_fee(
        tx: &Self::PartialTransaction,
        strategy: &FeeStrategy<Self::FeeUnit>,
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
