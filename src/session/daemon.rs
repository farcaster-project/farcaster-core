//! Pre-session and session living in the daemon.
//! It is possible to create a daemon pre-session and session from a client one through messages
//! exchanged between client and daemon called instructions.

use secp256k1::key::PublicKey;
use monero::util::key::{PublicKey as MPublicKey, PrivateKey};

pub struct AliceSessionParameters {
    pub destination_address: String,
    pub buy: PublicKey,
    pub cancel: PublicKey,
    pub refund: PublicKey,
    pub punish: PublicKey,
    pub spend: MPublicKey,
    /// The monero view key is the only secret key known by the daemon.
    pub view: PrivateKey,
}

pub struct BobSessionParameters {
    pub refund_address: String,
    pub fund: PublicKey,
    pub buy: PublicKey,
    pub cancel: PublicKey,
    pub refund: PublicKey,
    pub spend: MPublicKey,
    /// The monero view key is the only secret key known by the daemon.
    pub view: PrivateKey,
}
