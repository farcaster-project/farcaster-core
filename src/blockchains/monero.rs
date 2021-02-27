//! Defines and implements all the traits for Monero

use monero::cryptonote::hash::Hash;
use monero::util::key::PrivateKey;
use monero::util::key::PublicKey;

use crate::blockchains::Blockchain;
use crate::roles::Accordant;

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

impl Accordant for Monero {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Commitment = Hash;
}
