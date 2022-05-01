//! Defines types used to characterize a swap and behaviours a blockchain must implement to
//! participate in a swap, either as an arbitrating or an accordant blockchain.
//!
//! A blockchain must identify itself with a 32 bits indetifier as defined in [SLIP
//! 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044)
//! or must not conflict with any registered entity.

use std::error;
use std::fmt::{self, Debug, Display};
use std::io;
use std::str::FromStr;

use thiserror::Error;

use crate::consensus::{self, deserialize, serialize, CanonicalBytes, Decodable, Encodable};
use crate::crypto::{Keys, Signatures};
use crate::transaction::{Buyable, Cancelable, Fundable, Lockable, Punishable, Refundable};

pub enum Blockchain {
    Bitcoin,
    Monero,
}

/// Defines the type for a blockchain address, this type is used when manipulating transactions.
pub trait Address {
    /// Defines the address format for the arbitrating blockchain.
    type Address: Clone + Debug + CanonicalBytes;
}

/// Defines the type for a blockchain timelock, this type is used when manipulating transactions
/// and is carried in the [`Offer`](crate::negotiation::Offer) to fix the two timelocks.
pub trait Timelock {
    /// Defines the type of timelock used for the arbitrating transactions.
    type Timelock: Copy + PartialEq + Eq + Debug + Display + CanonicalBytes;
}

/// Defines the asset identifier for a blockchain and its associated asset unit type, it is carried
/// in the [`Offer`](crate::negotiation::Offer) to fix exchanged amounts.
pub trait Asset: Copy + Debug {
    /// Type for the traded asset unit for a blockchain.
    type AssetUnit: Copy + Eq + Debug + Display + CanonicalBytes;

    /// Parse an 32 bits identifier as defined in [SLIP
    /// 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044)
    /// and return a blockchain if existant.
    fn from_u32(bytes: u32) -> Option<Self>;

    /// Return the 32 bits identifier for the blockchain as defined in [SLIP
    /// 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044).
    fn to_u32(&self) -> u32;
}

/// Defines the types a blockchain needs to interact on-chain, i.e. the transaction exchanged
/// between participants and used over the network.
pub trait Onchain {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain.
    type PartialTransaction: Clone + Debug + CanonicalBytes;

    /// Defines the finalized transaction format for the arbitrating blockchain.
    type Transaction: Clone + Debug + CanonicalBytes;
}

/// Fix the types for all arbitrating transactions needed for the swap: [`Fundable`], [`Lockable`],
/// [`Buyable`], [`Cancelable`], [`Refundable`], and [`Punishable`] transactions.
pub trait Transactions: Timelock + Address + Fee + Keys + Signatures + Sized {
    /// The returned type of the consumable output and the `base_on` transaction method, used to
    /// reference the funds and chain other transactions on it. This must contain all necessary
    /// data to latter create a valid unlocking witness for the output and identify the funds.
    type Metadata: Clone + Eq + Debug;

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
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes + FromStr,
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
/// a fee strategy can be: fixed or range. When the fee strategy allows multiple possibilities, a
/// [`FeePriority`] is used to determine what to apply.
///
/// A fee strategy is included in an offer, so Alice and Bob can verify that transactions are valid
/// upon reception by the other participant.
#[derive(Debug, Clone, Eq, PartialEq, Display)]
#[display(fee_strategy_fmt)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes,
{
    /// A fixed strategy with the exact amount to set.
    Fixed(T),
    /// A range with a minimum and maximum (inclusive) possible fees.
    Range { min_inc: T, max_inc: T },
}

impl<T> FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes,
{
    pub fn check(&self, value: &T) -> bool {
        match self {
            Self::Fixed(fee_strat) => value == fee_strat,
            // Check in range including min and max bounds
            Self::Range { min_inc, max_inc } => value >= min_inc && value <= max_inc,
        }
    }
}

fn fee_strategy_fmt<T>(strategy: &FeeStrategy<T>) -> String
where
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes,
{
    match strategy {
        FeeStrategy::Fixed(t) => format!("Fixed: {}", t),
        FeeStrategy::Range { min_inc, max_inc } => {
            format!("Range: from {} to {} (inclusive)", min_inc, max_inc)
        }
    }
}

impl<T> Encodable for FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            FeeStrategy::Fixed(t) => {
                0x01u8.consensus_encode(writer)?;
                Ok(t.as_canonical_bytes().consensus_encode(writer)? + 1)
            }
            FeeStrategy::Range { min_inc, max_inc } => {
                let mut len = 0x02u8.consensus_encode(writer)?;
                len += min_inc.as_canonical_bytes().consensus_encode(writer)?;
                Ok(len + max_inc.as_canonical_bytes().consensus_encode(writer)?)
            }
        }
    }
}

impl<T> Decodable for FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(FeeStrategy::Fixed(T::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?)),
            0x02u8 => {
                let min_inc = T::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?;
                let max_inc = T::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?;
                Ok(FeeStrategy::Range { min_inc, max_inc })
            }
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl<T> CanonicalBytes for FeeStrategy<T>
where
    T: Clone + PartialOrd + PartialEq + Debug + fmt::Display + CanonicalBytes,
{
    fn as_canonical_bytes(&self) -> Vec<u8> {
        serialize(self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        deserialize(bytes)
    }
}

impl_strict_encoding!(
    FeeStrategy<T>,
    T: Clone + PartialOrd + PartialEq + fmt::Display + CanonicalBytes
);

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
    pub fn into_inner(self) -> Option<Box<dyn error::Error + Sync + Send>> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

/// Defines how to set the fee when a [`FeeStrategy`] allows multiple possibilities.
#[derive(Debug, Clone, Copy, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum FeePriority {
    /// Set the fee at the minimum allowed by the strategy.
    Low,
    /// Set the fee at the maximum allowed by the strategy.
    High,
}

impl Decodable for FeePriority {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(FeePriority::Low),
            0x02u8 => Ok(FeePriority::High),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl Encodable for FeePriority {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            FeePriority::Low => 0x01u8.consensus_encode(writer),
            FeePriority::High => 0x02u8.consensus_encode(writer),
        }
    }
}

impl FromStr for FeePriority {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Low" | "low" => Ok(FeePriority::Low),
            "High" | "high" => Ok(FeePriority::High),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// Enable fee management for an arbitrating blockchain. This trait require implementing the
/// [`Onchain`] trait to have access to transaction associated type and the [`Asset`] trait for
/// returning the amount of fee set on a transaction. The fee is carried in the
/// [`Offer`](crate::negotiation::Offer) through a [`FeeStrategy`] to fix the strategy to apply on
/// transactions.
pub trait Fee: Onchain + Asset {
    /// Type for describing the fee of a blockchain.
    type FeeUnit: Clone + PartialOrd + PartialEq + Eq + Display + Debug + CanonicalBytes;

    /// Calculates and sets the fee on the given transaction and return the amount of fee set in
    /// the blockchain native amount format.
    fn set_fee(
        tx: &mut Self::PartialTransaction,
        strategy: &FeeStrategy<Self::FeeUnit>,
        politic: FeePriority,
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
            "Mainnet" | "mainnet" => Ok(Network::Mainnet),
            "Testnet" | "testnet" => Ok(Network::Testnet),
            "Local" | "local" => Ok(Network::Local),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// Defines a blockchain network, identifies in which context the system interacts with the
/// blockchain.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum Network {
    /// Represents a real asset on his valuable network.
    Mainnet,
    /// Represents non-valuable assets on test networks.
    Testnet,
    /// Local and private testnets.
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

impl_strict_encoding!(Network);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::fee::SatPerVByte;

    #[test]
    fn parse_fee_politic() {
        for s in ["High", "high", "Low", "low"].iter() {
            let parse = FeePriority::from_str(s);
            assert!(parse.is_ok());
        }
    }

    #[test]
    fn parse_network() {
        for s in ["Mainnet", "mainnet", "Testnet", "testnet", "Local", "local"].iter() {
            let parse = Network::from_str(s);
            assert!(parse.is_ok());
        }
    }

    #[test]
    fn display_fee_strategy() {
        let strategy = FeeStrategy::Fixed(SatPerVByte::from_sat(100));
        assert_eq!(&format!("{}", strategy), "Fixed: 100 satoshi/vByte");
        let strategy = FeeStrategy::Range {
            min_inc: SatPerVByte::from_sat(50),
            max_inc: SatPerVByte::from_sat(150),
        };
        assert_eq!(
            &format!("{}", strategy),
            "Range: from 50 satoshi/vByte to 150 satoshi/vByte (inclusive)"
        )
    }

    #[test]
    fn check_range_fee_strategy() {
        let strategy = FeeStrategy::Range {
            min_inc: SatPerVByte::from_sat(50),
            max_inc: SatPerVByte::from_sat(150),
        };
        assert!(!strategy.check(&SatPerVByte::from_sat(49)));
        assert!(strategy.check(&SatPerVByte::from_sat(50)));
        assert!(strategy.check(&SatPerVByte::from_sat(150)));
        assert!(!strategy.check(&SatPerVByte::from_sat(151)));
    }
}
