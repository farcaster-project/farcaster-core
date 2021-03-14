//! Pre-session and session living in the daemon.
//! It is possible to create a daemon pre-session and session from a client one through messages
//! exchanged between client and daemon called instructions.

use crate::crypto::{Keys, CryptoEngine};
use crate::role::{Accordant, Arbitrating};

pub struct AliceSessionParameters<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub destination_address: Ar::Address,
    pub buy: Ar::PublicKey,
    pub cancel: Ar::PublicKey,
    pub refund: Ar::PublicKey,
    pub punish: Ar::PublicKey,
    pub spend: Ac::PublicKey,
    /// The monero view key is the only secret key known by the daemon.
    pub view: Ac::PrivateKey,
}

pub struct BobSessionParameters<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub refund_address: Ar::Address,
    pub fund: Ar::PublicKey,
    pub buy: Ar::PublicKey,
    pub cancel: Ar::PublicKey,
    pub refund: Ar::PublicKey,
    pub spend: Ac::PublicKey,
    /// The monero view key is the only secret key known by the daemon.
    pub view: Ac::PrivateKey,
}
