//! Protocol messages exchanged between swap daemons

use crate::crypto::{Crypto, CryptoEngine};
use crate::roles::{Accordant, Arbitrating};

/// Trait for defining inter-daemon communication messages.
pub trait ProtocolMessage {}

/// `commit_alice_session_params` forces Alice to commit to the result of her cryptographic setup
/// before receiving Bob's setup. This is done to remove adaptive behavior.
pub struct CommitAliceSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    /// Commitment to `Ab` curve point
    pub buy: Ar::Commitment,
    /// Commitment to `Ac` curve point
    pub cancel: Ar::Commitment,
    /// Commitment to `Ar` curve point
    pub refund: Ar::Commitment,
    /// Commitment to `Ap` curve point
    pub punish: Ar::Commitment,
    /// Commitment to `Ta` curve point
    pub adaptor: Ar::Commitment,
    /// Commitment to `k_v^a` scalar
    pub spend: Ac::Commitment,
    /// Commitment to `K_s^a` curve point
    pub view: Ac::Commitment,
}

impl<Ar, Ac, C> ProtocolMessage for CommitAliceSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
}

/// `commit_bob_session_params` forces Bob to commit to the result of his cryptographic setup
/// before receiving Alice's setup. This is done to remove adaptive behavior.
pub struct CommitBobSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    /// Commitment to `Bb` curve point
    pub buy: Ar::Commitment,
    /// Commitment to `Bc` curve point
    pub cancel: Ar::Commitment,
    /// Commitment to `Br` curve point
    pub refund: Ar::Commitment,
    /// Commitment to `Tb` curve point
    pub adaptor: Ar::Commitment,
    /// Commitment to `k_v^b` scalar
    pub spend: Ac::Commitment,
    /// Commitment to `K_s^b` curve point
    pub view: Ac::Commitment,
}

impl<Ar, Ac, C> ProtocolMessage for CommitBobSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
}

/// `reveal_alice_session_params` reveals the parameters commited by the
/// `commit_alice_session_params` message.
pub struct RevealAliceSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    /// The buy `Ab` public key
    pub buy: Ar::PublicKey,
    /// The cancel `Ac` public key
    pub cancel: Ar::PublicKey,
    /// The refund `Ar` public key
    pub refund: Ar::PublicKey,
    /// The punish `Ap` public key
    pub punish: Ar::PublicKey,
    /// The `Ta` adaptor public key
    pub adaptor: Ar::PublicKey,
    /// The destination Bitcoin address
    pub address: Ar::Address,
    /// The `K_v^a` view private key
    pub spend: Ac::PublicKey,
    /// The `K_s^a` spend public key
    pub view: Ac::PrivateKey,
    /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Option<String>,
}

impl<Ar, Ac, C> ProtocolMessage for RevealAliceSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
}

/// `reveal_bob_session_params` reveals the parameters commited by the `commit_bob_session_params`
/// message.
pub struct RevealBobSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    /// The buy `Bb` public key
    pub buy: Ar::PublicKey,
    /// The cancel `Bc` public key
    pub cancel: Ar::PublicKey,
    /// The refund `Br` public key
    pub refund: Ar::PublicKey,
    /// The `Tb` adaptor public key
    pub adaptor: Ar::PublicKey,
    /// The refund Bitcoin address
    pub address: Ar::Address,
    /// The `K_v^b` view private key
    pub spend: Ac::PublicKey,
    /// The `K_s^b` spend public key
    pub view: Ac::PrivateKey,
    /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Option<String>,
}

impl<Ar, Ac, C> ProtocolMessage for RevealBobSessionParams<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
}

/// `core_arbitrating_setup` sends the `lock (b)`, `cancel (d)` and `refund (e)` arbritrating
/// transactions from Bob to Alice, as well as Bob's signature for the `cancel (d)` transaction.
pub struct CoreArbitratingSetup<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The arbitrating `lock (b)` transaction
    pub lock: Ar::Transaction,
    /// The arbitrating `cancel (d)` transaction
    pub cancel: Ar::Transaction,
    /// The arbitrating `refund (e)` transaction
    pub refund: Ar::Transaction,
    /// The `Bc` `cancel (d)` signature
    pub cancel_sig: Ar::Signature,
}

impl<Ar, C> ProtocolMessage for CoreArbitratingSetup<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// `refund_procedure_signatures` is intended to transmit Alice's signature for the `cancel (d)`
/// transaction and Alice's adaptor signature for the `refund (e)` transaction. Uppon reception Bob
/// must validate the signatures.
pub struct RefundProcedureSignatures<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The `Ac` `cancel (d)` signature
    pub cancel_sig: Ar::Signature,
    /// The `Ar(Tb)` `refund (e)` adaptor signature
    pub refund_adaptor_sig: Ar::Signature,
}

impl<Ar, C> ProtocolMessage for RefundProcedureSignatures<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// `buy_procedure_signature`is intended to transmit Bob's adaptor signature for the `buy (c)`
/// transaction and the transaction itself. Uppon reception Alice must validate the transaction and
/// the adaptor signature.
pub struct BuyProcedureSignature<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    /// The arbitrating `buy (c)` transaction
    pub buy: Ar::Transaction,
    /// The `Bb(Ta)` `buy (c)` adaptor signature
    pub buy_adaptor_sig: Ar::Signature,
}

impl<Ar, C> ProtocolMessage for BuyProcedureSignature<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
}

/// `abort` is an `OPTIONAL` courtesy message from either swap partner to inform the counterparty
/// that they have aborted the swap with an `OPTIONAL` message body to provide the reason.
pub struct Abort {
    /// OPTIONAL `body`: error code | string
    pub error_body: Option<String>,
}

impl ProtocolMessage for Abort {}
