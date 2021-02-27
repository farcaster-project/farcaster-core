//! Defines what a blockchain is and what needs to be implemented

use crate::roles::Arbitrating;

pub mod bitcoin;
pub mod monero;

pub trait Blockchain {
    /// Type for the traded asset unit
    type AssetUnit;

    fn id(&self) -> String;

    fn new() -> Self;
}

/// Enable fee calculation for a blockchain
pub trait Fee<S>: Arbitrating
where
    S: FeeStrategy,
{
    /// Type for describing the fees
    type FeeUnit;

    /// Calculate, set the fees on the given transaction and return the fees set
    fn set_fees(tx: &mut Self::Transaction, strategy: &S) -> Self::FeeUnit;

    /// Validate that the fees for the given transaction are correct
    fn validate_fee(tx: &Self::Transaction, fee: &Self::FeeUnit, strategy: &S) -> bool;
}

pub trait FeeStrategy {}

pub struct StaticFee<B>(B::FeeUnit)
where
    B: Fee<Self> + ?Sized;

impl<B> StaticFee<B>
where
    B: Fee<Self> + ?Sized,
{
    pub fn new(fee: B::FeeUnit) -> Self {
        Self(fee)
    }
}

impl<B> FeeStrategy for StaticFee<B> where B: Fee<Self> + ?Sized {}

pub struct RangeFee<B>(B::FeeUnit, B::FeeUnit)
where
    B: Fee<Self> + ?Sized;

impl<B> FeeStrategy for RangeFee<B> where B: Fee<Self> + ?Sized {}
