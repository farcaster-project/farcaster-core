//! Blockchain utilities

use crate::roles::{Accordant, Arbitrating};

pub trait Blockchain {
    type AssetUnit;

    fn id(&self) -> String;

    fn new() -> Self;
}

pub struct Bitcoin {}

impl Blockchain for Bitcoin {
    type AssetUnit = u64;

    fn id(&self) -> String {
        String::from("btc")
    }

    fn new() -> Self {
        Bitcoin {}
    }
}

impl Arbitrating for Bitcoin {}

pub struct Monero {}

impl Blockchain for Monero {
    type AssetUnit = u64;

    fn id(&self) -> String {
        String::from("xmr")
    }

    fn new() -> Self {
        Monero {}
    }
}

impl Accordant for Monero {}
