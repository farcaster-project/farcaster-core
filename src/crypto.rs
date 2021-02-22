pub trait CryptoEngine {}

pub struct ECDSAScripts {}
impl CryptoEngine for ECDSAScripts {}

pub struct TrSchnorrScripts {}
impl CryptoEngine for TrSchnorrScripts {}

pub struct TrMuSig2 {}
impl CryptoEngine for TrMuSig2 {}

pub trait Crypto<C: CryptoEngine> {
    /// Private key type given the blockchain and the crypto engine
    type PrivateKey;
    /// Public key type given the blockchain and the crypto engine
    type PublicKey;
    /// Commitment type given the blockchain and the crypto engine
    type Commitment;
    /// Defines the signature format for the arbitrating blockchain
    type Signature;
}
