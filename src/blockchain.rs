// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

//! Defines types used to characterize a swap and behaviours a blockchain must implement to
//! participate in a swap, either as an arbitrating or an accordant blockchain.
//!
//! A blockchain must identify itself with a 32 bits indetifier as defined in [SLIP
//! 44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md#slip-0044--registered-coin-types-for-bip-0044)
//! or must not conflict with any registered entity.

use std::error;
use std::fmt::{self, Debug};
use std::io;
use std::str::FromStr;

use strict_encoding::{StrictDecode, StrictEncode};
use thiserror::Error;

use crate::consensus::{self, deserialize, serialize, CanonicalBytes, Decodable, Encodable};
use crate::transaction::{Buyable, Cancelable, Fundable, Lockable, Punishable, Refundable};

/// The list of supported blockchains (coins) by this library.
#[derive(
    Debug,
    Clone,
    Copy,
    Hash,
    PartialEq,
    Eq,
    Parser,
    Display,
    Serialize,
    Deserialize,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
pub enum Blockchain {
    /// The Bitcoin (BTC) blockchain.
    Bitcoin,
    /// The Monero (XMR) blockchain.
    Monero,
}

impl FromStr for Blockchain {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Bitcoin" | "bitcoin" | "btc" | "BTC" => Ok(Blockchain::Bitcoin),
            "Monero" | "monero" | "xmr" | "XMR" => Ok(Blockchain::Monero),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl Decodable for Blockchain {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x80000000u32 => Ok(Blockchain::Bitcoin),
            0x80000080u32 => Ok(Blockchain::Monero),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl Encodable for Blockchain {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            Blockchain::Bitcoin => 0x80000000u32.consensus_encode(writer),
            Blockchain::Monero => 0x80000080u32.consensus_encode(writer),
        }
    }
}

/// Fix the types for all arbitrating transactions needed for the swap: [`Fundable`], [`Lockable`],
/// [`Buyable`], [`Cancelable`], [`Refundable`], and [`Punishable`] transactions.
///
/// This injects concrete types to manage all the transactions.
pub trait Transactions {
    type Addr;
    type Amt;
    type Tx;
    type Px;
    type Out: Eq;
    type Ti;
    type Ms;
    type Pk;
    type Si;

    /// Defines the type for the `funding (a)` transaction
    type Funding: Fundable<Self::Tx, Self::Out, Self::Addr, Self::Pk>;
    /// Defines the type for the `lock (b)` transaction
    type Lock: Lockable<
        Self::Addr,
        Self::Tx,
        Self::Px,
        Self::Out,
        Self::Amt,
        Self::Ti,
        Self::Ms,
        Self::Pk,
        Self::Si,
    >;
    /// Defines the type for the `buy (c)` transaction
    type Buy: Buyable<
        Self::Addr,
        Self::Tx,
        Self::Px,
        Self::Out,
        Self::Amt,
        Self::Ti,
        Self::Ms,
        Self::Pk,
        Self::Si,
    >;
    /// Defines the type for the `cancel (d)` transaction
    type Cancel: Cancelable<
        Self::Addr,
        Self::Tx,
        Self::Px,
        Self::Out,
        Self::Amt,
        Self::Ti,
        Self::Ms,
        Self::Pk,
        Self::Si,
    >;
    /// Defines the type for the `refund (e)` transaction
    type Refund: Refundable<
        Self::Addr,
        Self::Tx,
        Self::Px,
        Self::Out,
        Self::Amt,
        Self::Ti,
        Self::Ms,
        Self::Pk,
        Self::Si,
    >;
    /// Defines the type for the `punish (f)` transaction
    type Punish: Punishable<
        Self::Addr,
        Self::Tx,
        Self::Px,
        Self::Out,
        Self::Amt,
        Self::Ti,
        Self::Ms,
        Self::Pk,
        Self::Si,
    >;
}

/// A fee strategy to be applied on an arbitrating transaction. As described in the specifications
/// a fee strategy can be: fixed or range. When the fee strategy allows multiple possibilities, a
/// [`FeePriority`] is used to determine what to apply.
///
/// A fee strategy is included in an offer, so Alice and Bob can verify that transactions are valid
/// upon reception by the other participant.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum FeeStrategy<T> {
    /// A fixed strategy with the exact amount to set.
    Fixed(T),
    /// A range with a minimum and maximum (inclusive) possible fees.
    Range { min_inc: T, max_inc: T },
}

impl<T> FeeStrategy<T>
where
    T: PartialEq + PartialOrd,
{
    pub fn check(&self, value: &T) -> bool {
        match self {
            Self::Fixed(fee_strat) => value == fee_strat,
            // Check in range including min and max bounds
            Self::Range { min_inc, max_inc } => value >= min_inc && value <= max_inc,
        }
    }
}

impl<T> FromStr for FeeStrategy<T>
where
    T: FromStr,
{
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts: Vec<&str> = s.split('-').collect();
        match parts.len() {
            1 => match s.parse::<T>() {
                Ok(x) => Ok(Self::Fixed(x)),
                Err(_) => Err(consensus::Error::ParseFailed("Failed parsing FeeStrategy")),
            },
            2 => {
                let max_inc = parts
                    .pop()
                    .expect("lenght is checked")
                    .parse::<T>()
                    .map_err(|_| consensus::Error::ParseFailed("Failed parsing FeeStrategy"))?;
                let min_inc = parts
                    .pop()
                    .expect("lenght is checked")
                    .parse::<T>()
                    .map_err(|_| consensus::Error::ParseFailed("Failed parsing FeeStrategy"))?;
                Ok(Self::Range { min_inc, max_inc })
            }
            _ => Err(consensus::Error::ParseFailed("Failed parsing FeeStrategy")),
        }
    }
}

impl<T> fmt::Display for FeeStrategy<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FeeStrategy::Fixed(t) => write!(f, "{}", t),
            FeeStrategy::Range { min_inc, max_inc } => {
                write!(f, "{}-{}", min_inc, max_inc)
            }
        }
    }
}

impl<T> Encodable for FeeStrategy<T>
where
    T: CanonicalBytes,
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
    T: CanonicalBytes,
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
    T: CanonicalBytes,
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

impl_strict_encoding!(FeeStrategy<T>, T: CanonicalBytes);

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
#[derive(Debug, Clone, Copy, Display, Serialize, Deserialize)]
#[display(Debug)]
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

/// Enable fee management for an arbitrating blockchain. The [`Fee`] trait declares a fee unit used
/// in fee strategies and an amount used in transactions. Implementing this trait allow to set and
/// verify fees on transactions given a strategy and a priority.
///
/// The fee to apply on transactions is carried in the [`Trade`](crate::trade::Trade) through
/// a [`FeeStrategy`], in case the fee strategy allow multiple values a [`FeePriority`] is used to
/// fix the amount.
///
/// ```
/// use bitcoin::Amount;
/// use bitcoin::util::psbt::PartiallySignedTransaction;
/// use farcaster_core::crypto::SharedKeyId;
/// use farcaster_core::blockchain::{Fee, FeeStrategy, FeePriority, FeeStrategyError};
///
/// pub struct Psbt(PartiallySignedTransaction);
/// pub struct SatPerBytes(f32);
///
/// impl Fee for Psbt {
///     type FeeUnit = SatPerBytes;
///     type Amount = Amount;
///
///     fn set_fee(
///         &mut self, strategy:
///         &FeeStrategy<SatPerBytes>,
///         politic: FeePriority
///     ) -> Result<Self::Amount, FeeStrategyError> {
///         todo!()
///     }
///
///     fn validate_fee(
///         &self,
///         strategy: &FeeStrategy<SatPerBytes>
///     ) -> Result<bool, FeeStrategyError> {
///         todo!()
///     }
/// }
/// ```
pub trait Fee {
    /// Type for describing the fee rate of a blockchain.
    type FeeUnit;

    /// Type of asset quantity.
    type Amount;

    /// Calculates and sets the fee on the given transaction and return the amount of fee set in
    /// the blockchain native amount format.
    fn set_fee(
        &mut self,
        strategy: &FeeStrategy<Self::FeeUnit>,
        politic: FeePriority,
    ) -> Result<Self::Amount, FeeStrategyError>;

    /// Validates that the fee for the given transaction are set accordingly to the strategy.
    fn validate_fee(&self, strategy: &FeeStrategy<Self::FeeUnit>)
        -> Result<bool, FeeStrategyError>;
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
///
/// When adding support for a new blockchain in the library a [`From`] implementation must be
/// provided such that it is possible to know what blockchain network to use for each of the three
/// generic contexts: `mainnet`, `testnet`, and `local`.
///
/// ```rust
/// use farcaster_core::blockchain::Network;
///
/// pub enum MyNet {
///     MyNet,
///     Test,
///     Regtest,
/// }
///
/// impl From<Network> for MyNet {
///     fn from(net: Network) -> Self {
///         match net {
///             Network::Mainnet => Self::MyNet,
///             Network::Testnet => Self::Test,
///             Network::Local => Self::Regtest,
///         }
///     }
/// }
/// ```
#[derive(
    Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug, Display, Serialize, Deserialize,
)]
#[display(Debug)]
pub enum Network {
    /// Valuable, real, assets on its production network.
    Mainnet,
    /// Non-valuable assets on its online test networks.
    Testnet,
    /// Non-valuable assets on offline test network.
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
    fn bitcoin_network_conversion() {
        assert_eq!(Network::from(bitcoin::Network::Bitcoin), Network::Mainnet);
        assert_eq!(Network::from(bitcoin::Network::Testnet), Network::Testnet);
        assert_eq!(Network::from(bitcoin::Network::Signet), Network::Testnet);
        assert_eq!(Network::from(bitcoin::Network::Regtest), Network::Local);
        assert_eq!(
            bitcoin::Network::from(Network::Mainnet),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            Into::<bitcoin::Network>::into(Network::Mainnet),
            bitcoin::Network::Bitcoin,
        );
        assert_eq!(
            bitcoin::Network::from(Network::Testnet),
            bitcoin::Network::Testnet
        );
        assert_eq!(
            Into::<bitcoin::Network>::into(Network::Testnet),
            bitcoin::Network::Testnet,
        );
        assert_eq!(
            bitcoin::Network::from(Network::Local),
            bitcoin::Network::Regtest
        );
        assert_eq!(
            Into::<bitcoin::Network>::into(Network::Local),
            bitcoin::Network::Regtest,
        );
    }

    #[test]
    fn monero_network_conversion() {
        assert_eq!(
            monero::Network::from(Network::Mainnet),
            monero::Network::Mainnet
        );
        assert_eq!(
            monero::Network::from(Network::Testnet),
            monero::Network::Stagenet
        );
        assert_eq!(
            monero::Network::from(Network::Local),
            monero::Network::Mainnet
        );
    }

    #[test]
    fn fee_strategy_display() {
        let strategy = FeeStrategy::Fixed(SatPerVByte::from_sat(100));
        assert_eq!(&format!("{}", strategy), "100 satoshi/vByte");
        let strategy = FeeStrategy::Range {
            min_inc: SatPerVByte::from_sat(50),
            max_inc: SatPerVByte::from_sat(150),
        };
        assert_eq!(
            &format!("{}", strategy),
            "50 satoshi/vByte-150 satoshi/vByte"
        )
    }

    #[test]
    fn fee_strategy_parse() {
        let strings = ["100 satoshi/vByte", "50 satoshi/vByte-150 satoshi/vByte"];
        let res = [
            FeeStrategy::Fixed(SatPerVByte::from_sat(100)),
            FeeStrategy::Range {
                min_inc: SatPerVByte::from_sat(50),
                max_inc: SatPerVByte::from_sat(150),
            },
        ];
        for (s, r) in strings.iter().zip(res) {
            let strategy = FeeStrategy::<SatPerVByte>::from_str(s);
            assert!(strategy.is_ok());
            assert_eq!(strategy.unwrap(), r);
        }
    }

    #[test]
    fn fee_strategy_to_str_from_str() {
        let strats = [
            FeeStrategy::Fixed(SatPerVByte::from_sat(1)),
            FeeStrategy::Range {
                min_inc: SatPerVByte::from_sat(1),
                max_inc: SatPerVByte::from_sat(7),
            },
        ];
        for strat in strats.iter() {
            assert_eq!(
                FeeStrategy::<SatPerVByte>::from_str(&strat.to_string()).unwrap(),
                *strat
            )
        }
    }

    #[test]
    fn fee_strategy_check_range() {
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
