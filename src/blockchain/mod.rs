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
pub trait Fee: Arbitrating + FeeStrategy {
    /// Type for describing the fees of a blockchain
    type FeeUnit: Copy;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(tx: &mut Self::Transaction, strategy: &FeeStrategies<Self>) -> Self::FeeUnit;

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(tx: &Self::Transaction, strategy: &FeeStrategies<Self>) -> bool;
}

/// A fee strategy to be applied on an arbitrating transaction.
///
/// As described in the specifications a fee strategy can be: fixe, range, or more advanced form
/// of fee calculation.
///
/// A fee strategy is included in an offer, so Alice and Bob can verify that transactions are valid
/// upon reception by the other participant.
pub trait FeeStrategy: Copy {
    type FeeStrategy;
}

impl<B: Fee> FeeStrategy for FeeStrategies<B> {
    type FeeStrategy = FeeStrategies<B>;
}

#[derive(Copy, Clone)]
pub enum FeeStrategies<B: Fee> {
    FixedFee(B::FeeUnit),
    RangeFee(B::FeeUnit, B::FeeUnit),
}

impl<B: Fee> FeeStrategies<B> {
    pub fn fixed(fee: B::FeeUnit) -> Self {
        Self::FixedFee(fee)
    }
    pub fn range(fee_low: B::FeeUnit, fee_high: B::FeeUnit) -> Self {
        Self::RangeFee(fee_low, fee_high)
    }
}
