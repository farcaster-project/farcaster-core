//! Protocol messages exchanged between swap daemons

use strict_encoding::{StrictDecode, StrictEncode};

use crate::blockchain::{Address, Onchain};
use crate::bundle;
use crate::consensus;
use crate::crypto::{Commitment, DleqProof, Keys, SharedPrivateKeys, Signatures};
use crate::datum;
use crate::role::Acc;
use crate::swap::Swap;

/// Trait for defining inter-daemon communication messages.
pub trait ProtocolMessage: StrictEncode + StrictDecode {}

/// `commit_alice_session_params` forces Alice to commit to the result of her cryptographic setup
/// before receiving Bob's setup. This is done to remove adaptive behavior.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct CommitAliceParameters<Ctx: Swap> {
    /// Commitment to `Ab` curve point
    pub buy: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Ac` curve point
    pub cancel: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Ar` curve point
    pub refund: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Ap` curve point
    pub punish: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Ta` curve point
    pub adaptor: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `k_v^a` scalar
    pub spend: <Ctx::Ac as Commitment>::Commitment,
    /// Commitment to `K_s^a` curve point
    pub view: <Ctx::Ac as Commitment>::Commitment,
}

impl<Ctx> std::fmt::Display for CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        write!(f, "{}", self)
    }
}

impl<Ctx> CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    pub fn from_bundle(bundle: &bundle::AliceParameters<Ctx>) -> Self {
        Self {
            buy: <Ctx::Ar as Commitment>::commit_to(bundle.buy.key().as_bytes()),
            cancel: <Ctx::Ar as Commitment>::commit_to(bundle.cancel.key().as_bytes()),
            refund: <Ctx::Ar as Commitment>::commit_to(bundle.refund.key().as_bytes()),
            punish: <Ctx::Ar as Commitment>::commit_to(bundle.punish.key().as_bytes()),
            adaptor: <Ctx::Ar as Commitment>::commit_to(bundle.adaptor.key().as_bytes()),
            spend: <Ctx::Ac as Commitment>::commit_to(bundle.spend.key().as_bytes()),
            view: <Ctx::Ac as Commitment>::commit_to(bundle.view.key().as_bytes()),
        }
    }

    pub fn verify(&self, reveal: &RevealAliceParameters<Ctx>) -> Result<(), consensus::Error> {
        // Check buy commitment
        <Ctx::Ar as Commitment>::validate(
            <Ctx::Ar as Keys>::as_bytes(&reveal.buy),
            self.buy.clone(),
        )?;
        // Check cancel commitment
        <Ctx::Ar as Commitment>::validate(
            <Ctx::Ar as Keys>::as_bytes(&reveal.cancel),
            self.cancel.clone(),
        )?;
        // Check refund commitment
        <Ctx::Ar as Commitment>::validate(
            <Ctx::Ar as Keys>::as_bytes(&reveal.refund),
            self.refund.clone(),
        )?;
        // Check punish commitment
        <Ctx::Ar as Commitment>::validate(
            <Ctx::Ar as Keys>::as_bytes(&reveal.punish),
            self.punish.clone(),
        )?;
        // Check adaptor commitment
        <Ctx::Ar as Commitment>::validate(
            <Ctx::Ar as Keys>::as_bytes(&reveal.adaptor),
            self.adaptor.clone(),
        )?;
        // Check spend commitment
        <Ctx::Ac as Commitment>::validate(
            <Ctx::Ac as Keys>::as_bytes(&reveal.spend),
            self.spend.clone(),
        )?;
        // Check private view commitment
        <Ctx::Ac as Commitment>::validate(
            <Ctx::Ac as SharedPrivateKeys<Acc>>::as_bytes(&reveal.view),
            self.view.clone(),
        )?;

        // Check the Dleq proof
        DleqProof::verify(&reveal.spend, &reveal.adaptor, reveal.proof.clone())?;

        // All validations passed, return ok
        Ok(())
    }

    pub fn verify_then_bundle(
        &self,
        reveal: &RevealAliceParameters<Ctx>,
    ) -> Result<bundle::AliceParameters<Ctx>, consensus::Error> {
        self.verify(reveal)?;
        Ok(reveal.into_bundle())
    }
}

impl<Ctx> From<bundle::AliceParameters<Ctx>> for CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: bundle::AliceParameters<Ctx>) -> Self {
        Self::from_bundle(&bundle)
    }
}

impl<Ctx> ProtocolMessage for CommitAliceParameters<Ctx> where Ctx: Swap {}

/// `commit_bob_session_params` forces Bob to commit to the result of his cryptographic setup
/// before receiving Alice's setup. This is done to remove adaptive behavior.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct CommitBobParameters<Ctx: Swap> {
    /// Commitment to `Bb` curve point
    pub buy: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Bc` curve point
    pub cancel: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Br` curve point
    pub refund: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `Tb` curve point
    pub adaptor: <Ctx::Ar as Commitment>::Commitment,
    /// Commitment to `k_v^b` scalar
    pub spend: <Ctx::Ac as Commitment>::Commitment,
    /// Commitment to `K_s^b` curve point
    pub view: <Ctx::Ac as Commitment>::Commitment,
}

impl<Ctx> ProtocolMessage for CommitBobParameters<Ctx> where Ctx: Swap {}

/// `reveal_alice_session_params` reveals the parameters commited by the
/// `commit_alice_session_params` message.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct RevealAliceParameters<Ctx: Swap> {
    /// The buy `Ab` public key
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    /// The cancel `Ac` public key
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    /// The refund `Ar` public key
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    /// The punish `Ap` public key
    pub punish: <Ctx::Ar as Keys>::PublicKey,
    /// The `Ta` adaptor public key
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    /// The destination Bitcoin address
    pub address: <Ctx::Ar as Address>::Address,
    /// The `K_v^a` view private key
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    /// The `K_s^a` spend public key
    pub view: <Ctx::Ac as SharedPrivateKeys<Acc>>::SharedPrivateKey,
    /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Ctx::Proof,
}

impl<Ctx> RevealAliceParameters<Ctx>
where
    Ctx: Swap,
{
    pub fn from_bundle(bundle: &bundle::AliceParameters<Ctx>) -> Result<Self, consensus::Error> {
        Ok(Self {
            buy: bundle.buy.key().try_into_arbitrating_pubkey()?,
            cancel: bundle.cancel.key().try_into_arbitrating_pubkey()?,
            refund: bundle.refund.key().try_into_arbitrating_pubkey()?,
            punish: bundle.punish.key().try_into_arbitrating_pubkey()?,
            adaptor: bundle.adaptor.key().try_into_arbitrating_pubkey()?,
            address: bundle.destination_address.param().try_into_address()?,
            spend: bundle.spend.key().try_into_accordant_pubkey()?,
            view: bundle.view.key().try_into_shared_private()?,
            proof: bundle.proof.proof().clone(),
        })
    }

    pub fn into_bundle(&self) -> bundle::AliceParameters<Ctx> {
        bundle::AliceParameters {
            buy: datum::Key::new_alice_buy(self.buy.clone()),
            cancel: datum::Key::new_alice_cancel(self.cancel.clone()),
            refund: datum::Key::new_alice_refund(self.refund.clone()),
            punish: datum::Key::new_alice_punish(self.punish.clone()),
            adaptor: datum::Key::new_alice_adaptor(self.adaptor.clone()),
            destination_address: datum::Parameter::new_destination_address(self.address.clone()),
            view: datum::Key::new_alice_private_view(self.view.clone()),
            spend: datum::Key::new_alice_spend(self.spend.clone()),
            proof: datum::Proof::new_cross_group_dleq(self.proof.clone()),
            cancel_timelock: None,
            punish_timelock: None,
            fee_strategy: None,
        }
    }
}

impl<Ctx> Into<bundle::AliceParameters<Ctx>> for RevealAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn into(self) -> bundle::AliceParameters<Ctx> {
        self.into_bundle()
    }
}

impl<Ctx> ProtocolMessage for RevealAliceParameters<Ctx> where Ctx: Swap {}

/// `reveal_bob_session_params` reveals the parameters commited by the `commit_bob_session_params`
/// message.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct RevealBobParameters<Ctx: Swap> {
    /// The buy `Bb` public key
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    /// The cancel `Bc` public key
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    /// The refund `Br` public key
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    /// The `Tb` adaptor public key
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    /// The refund Bitcoin address
    pub address: <Ctx::Ar as Address>::Address,
    /// The `K_v^b` view private key
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    /// The `K_s^b` spend public key
    pub view: <Ctx::Ac as SharedPrivateKeys<Acc>>::SharedPrivateKey,
    /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Ctx::Proof,
}

impl<Ctx> ProtocolMessage for RevealBobParameters<Ctx> where Ctx: Swap {}

/// `core_arbitrating_setup` sends the `lock (b)`, `cancel (d)` and `refund (e)` arbritrating
/// transactions from Bob to Alice, as well as Bob's signature for the `cancel (d)` transaction.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct CoreArbitratingSetup<Ctx: Swap> {
    /// The arbitrating `lock (b)` transaction
    pub lock: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The arbitrating `cancel (d)` transaction
    pub cancel: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The arbitrating `refund (e)` transaction
    pub refund: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The `Bc` `cancel (d)` signature
    pub cancel_sig: <Ctx::Ar as Signatures>::Signature,
}

impl<Ctx> ProtocolMessage for CoreArbitratingSetup<Ctx> where Ctx: Swap {}

/// `refund_procedure_signatures` is intended to transmit Alice's signature for the `cancel (d)`
/// transaction and Alice's adaptor signature for the `refund (e)` transaction. Uppon reception Bob
/// must validate the signatures.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct RefundProcedureSignatures<Ctx: Swap> {
    /// The `Ac` `cancel (d)` signature
    pub cancel_sig: <Ctx::Ar as Signatures>::Signature,
    /// The `Ar(Tb)` `refund (e)` adaptor signature
    pub refund_adaptor_sig: <Ctx::Ar as Signatures>::AdaptorSignature,
}

impl<Ctx> ProtocolMessage for RefundProcedureSignatures<Ctx> where Ctx: Swap {}

/// `buy_procedure_signature`is intended to transmit Bob's adaptor signature for the `buy (c)`
/// transaction and the transaction itself. Uppon reception Alice must validate the transaction and
/// the adaptor signature.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct BuyProcedureSignature<Ctx: Swap> {
    /// The arbitrating `buy (c)` transaction
    pub buy: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The `Bb(Ta)` `buy (c)` adaptor signature
    pub buy_adaptor_sig: <Ctx::Ar as Signatures>::AdaptorSignature,
}

impl<Ctx> ProtocolMessage for BuyProcedureSignature<Ctx> where Ctx: Swap {}

/// `abort` is an `OPTIONAL` courtesy message from either swap partner to inform the counterparty
/// that they have aborted the swap with an `OPTIONAL` message body to provide the reason.
#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct Abort {
    /// OPTIONAL `body`: error code | string
    pub error_body: Option<String>,
}

impl ProtocolMessage for Abort {}
