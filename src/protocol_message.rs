//! Protocol messages exchanged between swap daemons

use std::convert::TryInto;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::blockchain::{Address, Onchain};
use crate::bundle;
use crate::consensus::AsCanonicalBytes;
use crate::crypto::{
    self, Commit, Keys, SharedKeyId, SharedPrivateKeys, Signatures, TaggedElement,
};
use crate::role::SwapRole;
use crate::swap::Swap;
use crate::transaction::TxId;
use crate::Error;

fn commit_to_vec<T: Clone + Eq, K: AsCanonicalBytes, C: Clone + Eq>(
    wallet: &impl Commit<C>,
    keys: &Vec<TaggedElement<T, K>>,
) -> Vec<TaggedElement<T, C>> {
    keys.into_iter()
        .map(|tagged_key| {
            TaggedElement::new(
                tagged_key.tag().clone(),
                wallet.commit_to(tagged_key.elem().as_canonical_bytes()),
            )
        })
        .collect()
}

fn verify_vec_of_commitments<T: Eq, K: AsCanonicalBytes, C: Clone + Eq>(
    wallet: &impl Commit<C>,
    keys: Vec<TaggedElement<T, K>>,
    commitments: &Vec<TaggedElement<T, C>>,
) -> Result<(), Error> {
    keys.into_iter()
        .flat_map(|tagged_key| {
            commitments
                .iter()
                .find(|tagged_commitment| tagged_commitment.tag() == tagged_key.tag())
                .map(|tagged_commitment| {
                    wallet
                        .validate(
                            tagged_key.elem().as_canonical_bytes(),
                            tagged_commitment.elem().clone(),
                        )
                        .map_err(|e| Error::Crypto(e))
                })
        })
        .collect::<Result<(), Error>>()
}

/// `commit_alice_session_params` forces Alice to commit to the result of her cryptographic setup
/// before receiving Bob's setup. This is done to remove adaptive behavior.
#[derive(Clone, Debug)]
pub struct CommitAliceParameters<Ctx: Swap> {
    /// Commitment to the buy public key
    pub buy: Ctx::Commitment,
    /// Commitment to the cancel public key
    pub cancel: Ctx::Commitment,
    /// Commitment to the refund public key
    pub refund: Ctx::Commitment,
    /// Commitment to the punish public key
    pub punish: Ctx::Commitment,
    /// Commitment to the adaptor public key
    pub adaptor: Ctx::Commitment,
    /// Commitments to the extra arbitrating public keys
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the arbitrating shared keys
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
    /// Commitment to the spend public key
    pub spend: Ctx::Commitment,
    /// Commitments to the extra accordant public keys
    pub extra_accordant_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the accordant shared keys
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
}

impl<Ctx> CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    pub fn commit_to_bundle(
        wallet: &impl Commit<Ctx::Commitment>,
        bundle: bundle::AliceParameters<Ctx>,
    ) -> Self {
        Self {
            buy: wallet.commit_to(bundle.buy.as_canonical_bytes()),
            cancel: wallet.commit_to(bundle.cancel.as_canonical_bytes()),
            refund: wallet.commit_to(bundle.refund.as_canonical_bytes()),
            punish: wallet.commit_to(bundle.punish.as_canonical_bytes()),
            adaptor: wallet.commit_to(bundle.adaptor.as_canonical_bytes()),
            extra_arbitrating_keys: commit_to_vec(wallet, &bundle.extra_arbitrating_keys),
            arbitrating_shared_keys: commit_to_vec(wallet, &bundle.arbitrating_shared_keys),
            spend: wallet.commit_to(bundle.spend.as_canonical_bytes()),
            extra_accordant_keys: commit_to_vec(wallet, &bundle.extra_accordant_keys),
            accordant_shared_keys: commit_to_vec(wallet, &bundle.accordant_shared_keys),
        }
    }

    pub fn verify_with_reveal(
        &self,
        wallet: &impl Commit<Ctx::Commitment>,
        reveal: RevealAliceParameters<Ctx>,
    ) -> Result<(), Error> {
        wallet.validate(reveal.buy.as_canonical_bytes(), self.buy.clone())?;
        wallet.validate(reveal.cancel.as_canonical_bytes(), self.cancel.clone())?;
        wallet.validate(reveal.refund.as_canonical_bytes(), self.refund.clone())?;
        wallet.validate(reveal.punish.as_canonical_bytes(), self.punish.clone())?;
        wallet.validate(reveal.adaptor.as_canonical_bytes(), self.adaptor.clone())?;
        verify_vec_of_commitments(
            wallet,
            reveal.extra_arbitrating_keys,
            &self.extra_arbitrating_keys,
        )?;
        verify_vec_of_commitments(
            wallet,
            reveal.arbitrating_shared_keys,
            &self.arbitrating_shared_keys,
        )?;
        wallet.validate(reveal.spend.as_canonical_bytes(), self.spend.clone())?;
        verify_vec_of_commitments(
            wallet,
            reveal.extra_accordant_keys,
            &self.extra_accordant_keys,
        )?;
        verify_vec_of_commitments(
            wallet,
            reveal.accordant_shared_keys,
            &self.accordant_shared_keys,
        )
    }
}

/// `commit_bob_session_params` forces Bob to commit to the result of his cryptographic setup
/// before receiving Alice's setup. This is done to remove adaptive behavior.
#[derive(Clone, Debug)]
pub struct CommitBobParameters<Ctx: Swap> {
    /// Commitment to the buy public key
    pub buy: Ctx::Commitment,
    /// Commitment to the cancel public key
    pub cancel: Ctx::Commitment,
    /// Commitment to the refund public key
    pub refund: Ctx::Commitment,
    /// Commitment to the adaptor public key
    pub adaptor: Ctx::Commitment,
    /// Commitments to the extra arbitrating public keys
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the arbitrating shared keys
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
    /// Commitment to the spend public key
    pub spend: Ctx::Commitment,
    /// Commitments to the extra accordant public keys
    pub extra_accordant_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the accordant shared keys
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
}

impl<Ctx> CommitBobParameters<Ctx>
where
    Ctx: Swap,
{
    pub fn commit_to_bundle(
        wallet: &impl Commit<Ctx::Commitment>,
        bundle: bundle::BobParameters<Ctx>,
    ) -> Self {
        Self {
            buy: wallet.commit_to(bundle.buy.as_canonical_bytes()),
            cancel: wallet.commit_to(bundle.cancel.as_canonical_bytes()),
            refund: wallet.commit_to(bundle.refund.as_canonical_bytes()),
            adaptor: wallet.commit_to(bundle.adaptor.as_canonical_bytes()),
            extra_arbitrating_keys: commit_to_vec(wallet, &bundle.extra_arbitrating_keys),
            arbitrating_shared_keys: commit_to_vec(wallet, &bundle.arbitrating_shared_keys),
            spend: wallet.commit_to(bundle.spend.as_canonical_bytes()),
            extra_accordant_keys: commit_to_vec(wallet, &bundle.extra_accordant_keys),
            accordant_shared_keys: commit_to_vec(wallet, &bundle.accordant_shared_keys),
        }
    }

    pub fn verify_with_reveal(
        &self,
        wallet: &impl Commit<Ctx::Commitment>,
        reveal: RevealBobParameters<Ctx>,
    ) -> Result<(), Error> {
        wallet.validate(reveal.buy.as_canonical_bytes(), self.buy.clone())?;
        wallet.validate(reveal.cancel.as_canonical_bytes(), self.cancel.clone())?;
        wallet.validate(reveal.refund.as_canonical_bytes(), self.refund.clone())?;
        wallet.validate(reveal.adaptor.as_canonical_bytes(), self.adaptor.clone())?;
        verify_vec_of_commitments(
            wallet,
            reveal.extra_arbitrating_keys,
            &self.extra_arbitrating_keys,
        )?;
        verify_vec_of_commitments(
            wallet,
            reveal.arbitrating_shared_keys,
            &self.arbitrating_shared_keys,
        )?;
        wallet.validate(reveal.spend.as_canonical_bytes(), self.spend.clone())?;
        verify_vec_of_commitments(
            wallet,
            reveal.extra_accordant_keys,
            &self.extra_accordant_keys,
        )?;
        verify_vec_of_commitments(
            wallet,
            reveal.accordant_shared_keys,
            &self.accordant_shared_keys,
        )
    }
}

// TODO: Add more common data to reveal, e.g. help to ensure that both node uses the same value for
// fee

/// `reveal_alice_session_params` reveals the parameters commited by the
/// `commit_alice_session_params` message.
#[derive(Clone, Debug)]
pub struct RevealAliceParameters<Ctx: Swap> {
    /// Reveal the buy public key
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the cancel public key
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the refund public key
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the punish public key
    pub punish: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the adaptor public key
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the vector of extra arbitrating public keys
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    /// Reveal the vector of extra arbitrating shared keys
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey>>,
    /// Reveal the spend public key
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    /// Reveal the vector of extra accordant public keys
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    /// Reveal the vector of extra accordant shared keys
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey>>,
    /// Reveal the destination address
    pub address: <Ctx::Ar as Address>::Address,
    /// Reveal the cross-group discrete logarithm zero-knowledge proof
    pub proof: Ctx::Proof,
}

impl<Ctx> From<bundle::AliceParameters<Ctx>> for RevealAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: bundle::AliceParameters<Ctx>) -> Self {
        Self {
            buy: bundle.buy,
            cancel: bundle.cancel,
            refund: bundle.refund,
            punish: bundle.punish,
            adaptor: bundle.adaptor,
            extra_arbitrating_keys: bundle.extra_arbitrating_keys,
            arbitrating_shared_keys: bundle.arbitrating_shared_keys,
            spend: bundle.spend,
            extra_accordant_keys: bundle.extra_accordant_keys,
            accordant_shared_keys: bundle.accordant_shared_keys,
            address: bundle.destination_address,
            proof: bundle.proof,
        }
    }
}

/// `reveal_bob_session_params` reveals the parameters commited by the `commit_bob_session_params`
/// message.
#[derive(Clone, Debug)]
pub struct RevealBobParameters<Ctx: Swap> {
    /// Reveal the buy public key
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the cancel public key
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the refund public key
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the adaptor public key
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the vector of extra arbitrating public keys
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    /// Reveal the vector of extra arbitrating shared keys
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey>>,
    /// Reveal the spend public key
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    /// Reveal the vector of extra accordant public keys
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    /// Reveal the vector of extra accordant shared keys
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey>>,
    /// The refund Bitcoin address
    pub address: <Ctx::Ar as Address>::Address,
    /// The cross-group discrete logarithm zero-knowledge proof
    pub proof: Ctx::Proof,
}

impl<Ctx> From<bundle::BobParameters<Ctx>> for RevealBobParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: bundle::BobParameters<Ctx>) -> Self {
        Self {
            buy: bundle.buy,
            cancel: bundle.cancel,
            refund: bundle.refund,
            adaptor: bundle.adaptor,
            extra_arbitrating_keys: bundle.extra_arbitrating_keys,
            arbitrating_shared_keys: bundle.arbitrating_shared_keys,
            spend: bundle.spend,
            extra_accordant_keys: bundle.extra_accordant_keys,
            accordant_shared_keys: bundle.accordant_shared_keys,
            address: bundle.refund_address,
            proof: bundle.proof,
        }
    }
}

/// `core_arbitrating_setup` sends the `lock (b)`, `cancel (d)` and `refund (e)` arbritrating
/// transactions from Bob to Alice, as well as Bob's signature for the `cancel (d)` transaction.
#[derive(Clone, Debug)]
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

impl<Ctx>
    From<(
        bundle::CoreArbitratingTransactions<Ctx::Ar>,
        bundle::CosignedArbitratingCancel<Ctx::Ar>,
    )> for CoreArbitratingSetup<Ctx>
where
    Ctx: Swap,
{
    fn from(
        bundles: (
            bundle::CoreArbitratingTransactions<Ctx::Ar>,
            bundle::CosignedArbitratingCancel<Ctx::Ar>,
        ),
    ) -> Self {
        Self {
            lock: bundles.0.lock,
            cancel: bundles.0.cancel,
            refund: bundles.0.refund,
            cancel_sig: bundles.1.cancel_sig,
        }
    }
}

/// `refund_procedure_signatures` is intended to transmit Alice's signature for the `cancel (d)`
/// transaction and Alice's adaptor signature for the `refund (e)` transaction. Uppon reception Bob
/// must validate the signatures.
#[derive(Clone, Debug)]
pub struct RefundProcedureSignatures<Ctx: Swap> {
    /// The `Ac` `cancel (d)` signature
    pub cancel_sig: <Ctx::Ar as Signatures>::Signature,
    /// The `Ar(Tb)` `refund (e)` adaptor signature
    pub refund_adaptor_sig: <Ctx::Ar as Signatures>::AdaptorSignature,
}

impl<Ctx>
    From<(
        bundle::CosignedArbitratingCancel<Ctx::Ar>,
        bundle::SignedAdaptorRefund<Ctx::Ar>,
    )> for RefundProcedureSignatures<Ctx>
where
    Ctx: Swap,
{
    fn from(
        bundles: (
            bundle::CosignedArbitratingCancel<Ctx::Ar>,
            bundle::SignedAdaptorRefund<Ctx::Ar>,
        ),
    ) -> Self {
        Self {
            cancel_sig: bundles.0.cancel_sig.clone(),
            refund_adaptor_sig: bundles.1.refund_adaptor_sig.clone(),
        }
    }
}

/// `buy_procedure_signature`is intended to transmit Bob's adaptor signature for the `buy (c)`
/// transaction and the transaction itself. Uppon reception Alice must validate the transaction and
/// the adaptor signature.
#[derive(Clone, Debug)]
pub struct BuyProcedureSignature<Ctx: Swap> {
    /// The arbitrating `buy (c)` transaction
    pub buy: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The `Bb(Ta)` `buy (c)` adaptor signature
    pub buy_adaptor_sig: <Ctx::Ar as Signatures>::AdaptorSignature,
}

impl<Ctx> From<bundle::SignedAdaptorBuy<Ctx::Ar>> for BuyProcedureSignature<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: bundle::SignedAdaptorBuy<Ctx::Ar>) -> Self {
        Self {
            buy: bundle.buy.clone(),
            buy_adaptor_sig: bundle.buy_adaptor_sig.clone(),
        }
    }
}

/// `abort` is an `OPTIONAL` courtesy message from either swap partner to inform the counterparty
/// that they have aborted the swap with an `OPTIONAL` message body to provide the reason.
#[derive(Clone, Debug)]
pub struct Abort {
    /// OPTIONAL `body`: error code | string
    pub error_body: Option<String>,
}
