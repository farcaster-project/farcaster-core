//! Protocol messages exchanged between swap daemons

use crate::crypto::{Commitment, Curve, Proof, Signatures};
use crate::role::{Accordant, Arbitrating};
use strict_encoding::{StrictDecode, StrictEncode};

/// Trait for defining inter-daemon communication messages.
pub trait ProtocolMessage: StrictEncode + StrictDecode {}

/// `commit_alice_session_params` forces Alice to commit to the result of her cryptographic setup
/// before receiving Bob's setup. This is done to remove adaptive behavior.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct CommitAliceSessionParams<Ar, Ac>
where
    Ar: Commitment,
    Ac: Commitment,
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

impl<Ar: Commitment, Ac: Commitment> std::fmt::Display for CommitAliceSessionParams<Ar, Ac> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<Ar, Ac> ProtocolMessage for CommitAliceSessionParams<Ar, Ac>
where
    Ar: Commitment,
    Ac: Commitment,
{
}

/// `commit_bob_session_params` forces Bob to commit to the result of his cryptographic setup
/// before receiving Alice's setup. This is done to remove adaptive behavior.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct CommitBobSessionParams<Ar, Ac>
where
    Ar: Commitment,
    Ac: Commitment,
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

impl<Ar, Ac> ProtocolMessage for CommitBobSessionParams<Ar, Ac>
where
    Ar: Commitment,
    Ac: Commitment,
{
}

/// `reveal_alice_session_params` reveals the parameters commited by the
/// `commit_alice_session_params` message.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct RevealAliceSessionParams<Ar, Ac>
where
    Ar: Arbitrating + Curve,
    Ac: Accordant + Curve,
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
    pub view: Ac::PrivateViewKey,
    /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Proof<Ar, Ac>,
}

impl<Ar, Ac> ProtocolMessage for RevealAliceSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
}

/// `reveal_bob_session_params` reveals the parameters commited by the `commit_bob_session_params`
/// message.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct RevealBobSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
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
    pub view: Ac::PrivateViewKey,
    // /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Proof<Ar, Ac>,
}

impl<Ar, Ac> ProtocolMessage for RevealBobSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
}

/// `core_arbitrating_setup` sends the `lock (b)`, `cancel (d)` and `refund (e)` arbritrating
/// transactions from Bob to Alice, as well as Bob's signature for the `cancel (d)` transaction.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct CoreArbitratingSetup<Ar>
where
    Ar: Arbitrating,
{
    /// The arbitrating `lock (b)` transaction
    pub lock: Ar::PartialTransaction,
    /// The arbitrating `cancel (d)` transaction
    pub cancel: Ar::PartialTransaction,
    /// The arbitrating `refund (e)` transaction
    pub refund: Ar::PartialTransaction,
    /// The `Bc` `cancel (d)` signature
    pub cancel_sig: Ar::Signature,
}

impl<Ar> ProtocolMessage for CoreArbitratingSetup<Ar> where Ar: Arbitrating {}

/// `refund_procedure_signatures` is intended to transmit Alice's signature for the `cancel (d)`
/// transaction and Alice's adaptor signature for the `refund (e)` transaction. Uppon reception Bob
/// must validate the signatures.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct RefundProcedureSignatures<Ar>
where
    Ar: Signatures,
{
    /// The `Ac` `cancel (d)` signature
    pub cancel_sig: Ar::Signature,
    /// The `Ar(Tb)` `refund (e)` adaptor signature
    pub refund_adaptor_sig: Ar::AdaptorSignature,
}

impl<Ar> ProtocolMessage for RefundProcedureSignatures<Ar> where Ar: Arbitrating {}

/// `buy_procedure_signature`is intended to transmit Bob's adaptor signature for the `buy (c)`
/// transaction and the transaction itself. Uppon reception Alice must validate the transaction and
/// the adaptor signature.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct BuyProcedureSignature<Ar>
where
    Ar: Arbitrating,
{
    /// The arbitrating `buy (c)` transaction
    pub buy: Ar::PartialTransaction,
    /// The `Bb(Ta)` `buy (c)` adaptor signature
    pub buy_adaptor_sig: Ar::AdaptorSignature,
}

impl<Ar> ProtocolMessage for BuyProcedureSignature<Ar> where Ar: Arbitrating {}

/// `abort` is an `OPTIONAL` courtesy message from either swap partner to inform the counterparty
/// that they have aborted the swap with an `OPTIONAL` message body to provide the reason.

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct Abort {
    /// OPTIONAL `body`: error code | string
    pub error_body: Option<String>,
}

impl ProtocolMessage for Abort {}
