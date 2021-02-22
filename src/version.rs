//! Farcaster version and flags

pub struct Version(u64);

pub trait Flag {}

pub enum CryptoEngine {
    ECDSAScripts,
    TrSchnorrScripts,
    TrMuSig2,
}

impl Flag for CryptoEngine {}
