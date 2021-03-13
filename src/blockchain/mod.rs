//! Defines what a blockchain is and what needs to be implemented

use std::str::FromStr;

use crate::role::Arbitrating;

pub mod bitcoin;
pub mod monero;

/// Base trait for defining a blockchain and its asset type.
pub trait Blockchain: Copy {
    /// Type for the traded asset unit
    type AssetUnit: Copy;

    /// Type of the blockchain identifier
    type Id: FromStr + Into<String>;

    /// Type of the chain identifier
    type ChainId;

    /// Returns the blockchain identifier
    fn id(&self) -> Self::Id;

    /// Returns the chain identifier
    fn chain_id(&self) -> Self::ChainId;

    /// Create a new blockchain
    fn new() -> Self;
}

/// Enable fee management for an arbitrating blockchain.
///
/// This trait require implementing the Arbitrating role to have access to transaction associated
/// type and because in the base protocol transactions for the accordant blockchain are generated
/// outside, thus we don't need this trait on Accordant blockchain.
pub trait Fee<S>: Arbitrating
where
    S: FeeStrategy,
{
    /// Type for describing the fees of a blockchain
    type FeeUnit: Copy;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(tx: &mut Self::Transaction, strategy: &S) -> Self::FeeUnit;

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(tx: &Self::Transaction, strategy: &S) -> bool;
}

/// A fee strategy to be applied on an arbitrating transaction.
///
/// As described in the specifications a fee strategy can be: fixe, range, or more advanced form
/// of fee calculation.
///
/// A fee strategy is included in an offer, so Alice and Bob can verify that transactions are valid
/// upon reception by the other participant.
pub trait FeeStrategy: Copy {}

/// A static fee strategy. Sets a fixed fee on every transactions.
#[derive(Clone, Copy)]
pub struct FixeFee<B>(B::FeeUnit)
where
    B: Fee<Self> + ?Sized;

impl<B> FixeFee<B>
where
    B: Fee<Self> + ?Sized,
{
    /// Creates a new fixed fee stategy, setting the fixed amount of fees on every transaction.
    pub fn new(fee: B::FeeUnit) -> Self {
        Self(fee)
    }
}

impl<B> FeeStrategy for FixeFee<B> where B: Fee<Self> + ?Sized {}

/// A range strategy for setting transactions' fees. Build from lower and upper bounds, the fee on
/// the transaction MUST be within the bounds, lower and upper inclusive.
#[derive(Clone, Copy)]
pub struct RangeFee<B>(B::FeeUnit, B::FeeUnit)
where
    B: Fee<Self> + ?Sized;

impl<B> RangeFee<B>
where
    B: Fee<Self> + ?Sized,
{
    /// Creates a new range fee stategy, fees on every transaction must be within the bounds,
    /// lower and upper inclusive.
    pub fn new(lower_bound: B::FeeUnit, upper_bound: B::FeeUnit) -> Self {
        Self(lower_bound, upper_bound)
    }
}

impl<B> FeeStrategy for RangeFee<B> where B: Fee<Self> + ?Sized {}
