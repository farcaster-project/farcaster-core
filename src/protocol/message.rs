//! Protocol messages exchanged between swap daemons at each step of the swap protocol. These
//! messages are untrusted and must be validated uppon reception by each swap participant.

use std::io;

use crate::blockchain::{Address, Onchain};
use crate::bundle;
use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};
use crate::crypto::{
    self, Commit, Keys, SharedKeyId, SharedSecretKeys, Signatures, TaggedElement, TaggedElements,
};
use crate::swap::{Swap, SwapId};
use crate::Error;

use lightning_encoding::{strategies::AsStrict, Strategy};

fn commit_to_vec<T: Clone + Eq, K: CanonicalBytes, C: Clone + Eq>(
    wallet: &impl Commit<C>,
    keys: &[TaggedElement<T, K>],
) -> TaggedElements<T, C> {
    keys.iter()
        .map(|tagged_key| {
            TaggedElement::new(
                tagged_key.tag().clone(),
                wallet.commit_to(tagged_key.elem().as_canonical_bytes()),
            )
        })
        .collect()
}

fn verify_vec_of_commitments<T: Eq, K: CanonicalBytes, C: Clone + Eq>(
    wallet: &impl Commit<C>,
    keys: Vec<TaggedElement<T, K>>,
    commitments: &[TaggedElement<T, C>],
) -> Result<(), Error> {
    keys.into_iter()
        .map(|tagged_key| {
            commitments
                .iter()
                .find(|tagged_commitment| tagged_commitment.tag() == tagged_key.tag())
                .map(|tagged_commitment| {
                    wallet
                        .validate(
                            tagged_key.elem().as_canonical_bytes(),
                            tagged_commitment.elem().clone(),
                        )
                        .map_err(Error::Crypto)
                })
                .ok_or(Error::Crypto(crypto::Error::InvalidCommitment))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|_| ())
}

// CommitAliceParameters

/// Forces Alice to commit to the result of her cryptographic setup before receiving Bob's setup.
/// This is done to remove adaptive behavior in the cryptographic parameters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitAliceParameters<C> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Commitment to the buy public key.
    pub buy: C,
    /// Commitment to the cancel public key.
    pub cancel: C,
    /// Commitment to the refund public key.
    pub refund: C,
    /// Commitment to the punish public key.
    pub punish: C,
    /// Commitment to the adaptor public key.
    pub adaptor: C,
    /// Commitments to the extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, C>>,
    /// Commitments to the arbitrating shared keys.
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, C>>,
    /// Commitment to the spend public key.
    pub spend: C,
    /// Commitments to the extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, C>>,
    /// Commitments to the accordant shared keys.
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, C>>,
}

// TODO impl Display

// FIXME
//impl<C> CommitAliceParameters<C>
//where
//    C: CanonicalBytes,
//{
//    pub fn commit_to_bundle(
//        swap_id: SwapId,
//        wallet: &impl Commit<C>,
//        bundle: bundle::AliceParameters<Ctx>,
//    ) -> Self {
//        Self {
//            swap_id,
//            buy: wallet.commit_to(bundle.buy.as_canonical_bytes()),
//            cancel: wallet.commit_to(bundle.cancel.as_canonical_bytes()),
//            refund: wallet.commit_to(bundle.refund.as_canonical_bytes()),
//            punish: wallet.commit_to(bundle.punish.as_canonical_bytes()),
//            adaptor: wallet.commit_to(bundle.adaptor.as_canonical_bytes()),
//            extra_arbitrating_keys: commit_to_vec(wallet, &bundle.extra_arbitrating_keys),
//            arbitrating_shared_keys: commit_to_vec(wallet, &bundle.arbitrating_shared_keys),
//            spend: wallet.commit_to(bundle.spend.as_canonical_bytes()),
//            extra_accordant_keys: commit_to_vec(wallet, &bundle.extra_accordant_keys),
//            accordant_shared_keys: commit_to_vec(wallet, &bundle.accordant_shared_keys),
//        }
//    }
//
//    pub fn verify_with_reveal(
//        &self,
//        wallet: &impl Commit<C>,
//        reveal: RevealAliceParameters<Ctx>,
//    ) -> Result<(), Error> {
//        wallet.validate(reveal.buy.as_canonical_bytes(), self.buy.clone())?;
//        wallet.validate(reveal.cancel.as_canonical_bytes(), self.cancel.clone())?;
//        wallet.validate(reveal.refund.as_canonical_bytes(), self.refund.clone())?;
//        wallet.validate(reveal.punish.as_canonical_bytes(), self.punish.clone())?;
//        wallet.validate(reveal.adaptor.as_canonical_bytes(), self.adaptor.clone())?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.extra_arbitrating_keys,
//            &self.extra_arbitrating_keys,
//        )?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.arbitrating_shared_keys,
//            &self.arbitrating_shared_keys,
//        )?;
//        wallet.validate(reveal.spend.as_canonical_bytes(), self.spend.clone())?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.extra_accordant_keys,
//            &self.extra_accordant_keys,
//        )?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.accordant_shared_keys,
//            &self.accordant_shared_keys,
//        )
//    }
//}

impl<C> Encodable for CommitAliceParameters<C>
where
    C: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.buy.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        len += self.punish.as_canonical_bytes().consensus_encode(s)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_arbitrating_keys.consensus_encode(s)?;
        len += self.arbitrating_shared_keys.consensus_encode(s)?;
        len += self.spend.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_accordant_keys.consensus_encode(s)?;
        Ok(len + self.accordant_shared_keys.consensus_encode(s)?)
    }
}

impl<C> Decodable for CommitAliceParameters<C>
where
    C: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(CommitAliceParameters<C>, C: CanonicalBytes);

impl<C> Strategy for CommitAliceParameters<C> {
    type Strategy = AsStrict;
}

// CommitBobParameters

/// Forces Bob to commit to the result of his cryptographic setup before receiving Alice's setup.
/// This is done to remove adaptive behavior in the cryptographic parameters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBobParameters<C> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Commitment to the buy public key.
    pub buy: C,
    /// Commitment to the cancel public key.
    pub cancel: C,
    /// Commitment to the refund public key.
    pub refund: C,
    /// Commitment to the adaptor public key.
    pub adaptor: C,
    /// Commitments to the extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, C>>,
    /// Commitments to the arbitrating shared keys.
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, C>>,
    /// Commitment to the spend public key.
    pub spend: C,
    /// Commitments to the extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, C>>,
    /// Commitments to the accordant shared keys.
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, C>>,
}

// TODO impl Display

// FIXME
//impl<Ctx> CommitBobParameters<Ctx>
//where
//    Ctx: Swap,
//{
//    pub fn commit_to_bundle(
//        swap_id: SwapId,
//        wallet: &impl Commit<Ctx::Commitment>,
//        bundle: bundle::BobParameters<Ctx>,
//    ) -> Self {
//        Self {
//            swap_id,
//            buy: wallet.commit_to(bundle.buy.as_canonical_bytes()),
//            cancel: wallet.commit_to(bundle.cancel.as_canonical_bytes()),
//            refund: wallet.commit_to(bundle.refund.as_canonical_bytes()),
//            adaptor: wallet.commit_to(bundle.adaptor.as_canonical_bytes()),
//            extra_arbitrating_keys: commit_to_vec(wallet, &bundle.extra_arbitrating_keys),
//            arbitrating_shared_keys: commit_to_vec(wallet, &bundle.arbitrating_shared_keys),
//            spend: wallet.commit_to(bundle.spend.as_canonical_bytes()),
//            extra_accordant_keys: commit_to_vec(wallet, &bundle.extra_accordant_keys),
//            accordant_shared_keys: commit_to_vec(wallet, &bundle.accordant_shared_keys),
//        }
//    }
//
//    pub fn verify_with_reveal(
//        &self,
//        wallet: &impl Commit<Ctx::Commitment>,
//        reveal: RevealBobParameters<Ctx>,
//    ) -> Result<(), Error> {
//        wallet.validate(reveal.buy.as_canonical_bytes(), self.buy.clone())?;
//        wallet.validate(reveal.cancel.as_canonical_bytes(), self.cancel.clone())?;
//        wallet.validate(reveal.refund.as_canonical_bytes(), self.refund.clone())?;
//        wallet.validate(reveal.adaptor.as_canonical_bytes(), self.adaptor.clone())?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.extra_arbitrating_keys,
//            &self.extra_arbitrating_keys,
//        )?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.arbitrating_shared_keys,
//            &self.arbitrating_shared_keys,
//        )?;
//        wallet.validate(reveal.spend.as_canonical_bytes(), self.spend.clone())?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.extra_accordant_keys,
//            &self.extra_accordant_keys,
//        )?;
//        verify_vec_of_commitments(
//            wallet,
//            reveal.accordant_shared_keys,
//            &self.accordant_shared_keys,
//        )
//    }
//}

impl<C> Encodable for CommitBobParameters<C>
where
    C: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.buy.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_arbitrating_keys.consensus_encode(s)?;
        len += self.arbitrating_shared_keys.consensus_encode(s)?;
        len += self.spend.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_accordant_keys.consensus_encode(s)?;
        Ok(len + self.accordant_shared_keys.consensus_encode(s)?)
    }
}

impl<C> Decodable for CommitBobParameters<C>
where
    C: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: C::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(CommitBobParameters<C>, C: CanonicalBytes);

impl<C> Strategy for CommitBobParameters<C> {
    type Strategy = AsStrict;
}

// RevealProof

/// Reveals the zero-knowledge proof for the discrete logarithm across curves.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealProof<P> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Reveal the cross-group discrete logarithm zero-knowledge proof.
    pub proof: P,
}

// TODO impl Display

impl<P> Encodable for RevealProof<P>
where
    P: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.swap_id.consensus_encode(s)?;
        Ok(len + self.proof.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<P> Decodable for RevealProof<P>
where
    P: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            proof: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(RevealProof<P>, P: CanonicalBytes);

impl<P> Strategy for RevealProof<P> {
    type Strategy = AsStrict;
}

// FIXME
//impl<Ctx> From<(SwapId, bundle::Proof<Ctx>)> for RevealProof<Ctx>
//where
//    Ctx: Swap,
//{
//    fn from(bundle: (SwapId, bundle::Proof<Ctx>)) -> Self {
//        Self {
//            swap_id: bundle.0,
//            proof: bundle.1.proof,
//        }
//    }
//}

// RevealAliceParameters

/// Reveals the parameters commited by the [`CommitAliceParameters`] protocol message.
///
/// - `A` the arbitrating address type
/// - `P` the arbitrating Public Key type
/// - `R` the arbitrating Shared Secret Key type
/// - `Q` the accordant Public Key type
/// - `S` the accordant Shared Secret Key type
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealAliceParameters<P, Q, R, S, A> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Reveal the buy public key.
    pub buy: P,
    /// Reveal the cancel public key.
    pub cancel: P,
    /// Reveal the refund public key.
    pub refund: P,
    /// Reveal the punish public key.
    pub punish: P,
    /// Reveal the adaptor public key.
    pub adaptor: P,
    /// Reveal the vector of extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, P>>,
    /// Reveal the vector of extra arbitrating shared keys.
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, R>>,
    /// Reveal the spend public key.
    pub spend: Q,
    /// Reveal the vector of extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, Q>>,
    /// Reveal the vector of extra accordant shared keys.
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, S>>,
    /// Reveal the destination address.
    pub address: A,
}

// TODO impl Display

impl<P, Q, R, S, A> Encodable for RevealAliceParameters<P, Q, R, S, A>
where
    P: CanonicalBytes,
    Q: CanonicalBytes,
    R: CanonicalBytes,
    S: CanonicalBytes,
    A: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.buy.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        len += self.punish.as_canonical_bytes().consensus_encode(s)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_arbitrating_keys.consensus_encode(s)?;
        len += self.arbitrating_shared_keys.consensus_encode(s)?;
        // this can go?
        len += self.spend.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_accordant_keys.consensus_encode(s)?;
        len += self.accordant_shared_keys.consensus_encode(s)?;
        Ok(len + self.address.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<P, Q, R, S, A> Decodable for RevealAliceParameters<P, Q, R, S, A>
where
    P: CanonicalBytes,
    Q: CanonicalBytes,
    R: CanonicalBytes,
    S: CanonicalBytes,
    A: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: Q::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            address: A::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(RevealAliceParameters<P, Q, R, S, A>, P: CanonicalBytes, Q: CanonicalBytes, R: CanonicalBytes, S: CanonicalBytes, A: CanonicalBytes);

impl<P, Q, R, S, A> Strategy for RevealAliceParameters<P, Q, R, S, A> {
    type Strategy = AsStrict;
}

// FIXME
//impl<Ctx> From<(SwapId, bundle::AliceParameters<Ctx>)> for RevealAliceParameters<Ctx>
//where
//    Ctx: Swap,
//{
//    fn from(bundle: (SwapId, bundle::AliceParameters<Ctx>)) -> Self {
//        Self {
//            swap_id: bundle.0,
//            buy: bundle.1.buy,
//            cancel: bundle.1.cancel,
//            refund: bundle.1.refund,
//            punish: bundle.1.punish,
//            adaptor: bundle.1.adaptor,
//            extra_arbitrating_keys: bundle.1.extra_arbitrating_keys,
//            arbitrating_shared_keys: bundle.1.arbitrating_shared_keys,
//            spend: bundle.1.spend,
//            extra_accordant_keys: bundle.1.extra_accordant_keys,
//            accordant_shared_keys: bundle.1.accordant_shared_keys,
//            address: bundle.1.destination_address,
//        }
//    }
//}

/// Reveals the parameters commited by the [`CommitBobParameters`] protocol message.
///
/// - `A` the arbitrating address type
/// - `P` the arbitrating Public Key type
/// - `R` the arbitrating Shared Secret Key type
/// - `Q` the accordant Public Key type
/// - `S` the accordant Shared Secret Key type
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealBobParameters<P, Q, R, S, A> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Reveal the buy public key.
    pub buy: P,
    /// Reveal the cancel public key.
    pub cancel: P,
    /// Reveal the refund public key.
    pub refund: P,
    /// Reveal the adaptor public key.
    pub adaptor: P,
    /// Reveal the vector of extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, P>>,
    /// Reveal the vector of extra arbitrating shared keys.
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, R>>,
    /// Reveal the spend public key.
    pub spend: Q,
    /// Reveal the vector of extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, Q>>,
    /// Reveal the vector of extra accordant shared keys.
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, S>>,
    /// The refund Bitcoin address.
    pub address: A,
}

// TODO impl Display

impl<P, Q, R, S, A> Encodable for RevealBobParameters<P, Q, R, S, A>
where
    P: CanonicalBytes,
    Q: CanonicalBytes,
    R: CanonicalBytes,
    S: CanonicalBytes,
    A: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.buy.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_arbitrating_keys.consensus_encode(s)?;
        len += self.arbitrating_shared_keys.consensus_encode(s)?;
        len += self.spend.as_canonical_bytes().consensus_encode(s)?;
        len += self.extra_accordant_keys.consensus_encode(s)?;
        len += self.accordant_shared_keys.consensus_encode(s)?;
        Ok(len + self.address.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<P, Q, R, S, A> Decodable for RevealBobParameters<P, Q, R, S, A>
where
    P: CanonicalBytes,
    Q: CanonicalBytes,
    R: CanonicalBytes,
    S: CanonicalBytes,
    A: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: P::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: Q::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            address: A::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(RevealBobParameters<P, Q, R, S, A>, P: CanonicalBytes, Q: CanonicalBytes, R: CanonicalBytes, S: CanonicalBytes, A: CanonicalBytes);

impl<P, Q, R, S, A> Strategy for RevealBobParameters<P, Q, R, S, A> {
    type Strategy = AsStrict;
}

// FIXME
//impl<Ctx> From<(SwapId, bundle::BobParameters<Ctx>)> for RevealBobParameters<Ctx>
//where
//    Ctx: Swap,
//{
//    fn from(bundle: (SwapId, bundle::BobParameters<Ctx>)) -> Self {
//        Self {
//            swap_id: bundle.0,
//            buy: bundle.1.buy,
//            cancel: bundle.1.cancel,
//            refund: bundle.1.refund,
//            adaptor: bundle.1.adaptor,
//            extra_arbitrating_keys: bundle.1.extra_arbitrating_keys,
//            arbitrating_shared_keys: bundle.1.arbitrating_shared_keys,
//            spend: bundle.1.spend,
//            extra_accordant_keys: bundle.1.extra_accordant_keys,
//            accordant_shared_keys: bundle.1.accordant_shared_keys,
//            address: bundle.1.refund_address,
//        }
//    }
//}

/// Sends the [`Lockable`], [`Cancelable`] and [`Refundable`] arbritrating transactions from
/// [`SwapRole::Bob`] to [`SwapRole::Alice`], as well as Bob's signature for the [`Cancelable`]
/// transaction.
///
/// [`SwapRole::Alice`]: crate::role::SwapRole::Alice
/// [`SwapRole::Bob`]: crate::role::SwapRole::Bob
/// [`Lockable`]: crate::transaction::Lockable
/// [`Cancelable`]: crate::transaction::Cancelable
/// [`Refundable`]: crate::transaction::Refundable
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreArbitratingSetup<PartialTx, Sig> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The arbitrating `lock (b)` transaction.
    pub lock: PartialTx,
    /// The arbitrating `cancel (d)` transaction.
    pub cancel: PartialTx,
    /// The arbitrating `refund (e)` transaction.
    pub refund: PartialTx,
    /// The `Bc` `cancel (d)` signature.
    pub cancel_sig: Sig,
}

// TODO impl Display

impl<PartialTx, Sig> Encodable for CoreArbitratingSetup<PartialTx, Sig>
where
    PartialTx: CanonicalBytes,
    Sig: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.lock.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        Ok(len + self.cancel_sig.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<PartialTx, Sig> Decodable for CoreArbitratingSetup<PartialTx, Sig>
where
    PartialTx: CanonicalBytes,
    Sig: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            lock: PartialTx::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: PartialTx::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: PartialTx::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel_sig: Sig::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(CoreArbitratingSetup<PartialTx, Sig>, PartialTx: CanonicalBytes, Sig: CanonicalBytes);

impl<PartialTx, Sig> Strategy for CoreArbitratingSetup<PartialTx, Sig> {
    type Strategy = AsStrict;
}

// FIXME
//impl<Ctx>
//    From<(
//        SwapId,
//        bundle::CoreArbitratingTransactions<Ctx::Ar>,
//        bundle::CosignedArbitratingCancel<Ctx::Ar>,
//    )> for CoreArbitratingSetup<Ctx>
//where
//    Ctx: Swap,
//{
//    fn from(
//        bundles: (
//            SwapId,
//            bundle::CoreArbitratingTransactions<Ctx::Ar>,
//            bundle::CosignedArbitratingCancel<Ctx::Ar>,
//        ),
//    ) -> Self {
//        Self {
//            swap_id: bundles.0,
//            lock: bundles.1.lock,
//            cancel: bundles.1.cancel,
//            refund: bundles.1.refund,
//            cancel_sig: bundles.2.cancel_sig,
//        }
//    }
//}

/// Protocol message is intended to transmit [`SwapRole::Alice`]'s signature for the [`Cancelable`]
/// transaction and Alice's adaptor signature for the [`Refundable`] transaction. Uppon reception
/// [`SwapRole::Bob`] must validate the signatures.
///
/// [`SwapRole::Alice`]: crate::role::SwapRole::Alice
/// [`SwapRole::Bob`]: crate::role::SwapRole::Bob
/// [`Cancelable`]: crate::transaction::Cancelable
/// [`Refundable`]: crate::transaction::Refundable
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundProcedureSignatures<Sig, EncSig> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The `Ac` `cancel (d)` signature.
    pub cancel_sig: Sig,
    /// The `Ar(Tb)` `refund (e)` adaptor signature.
    pub refund_adaptor_sig: EncSig,
}

// TODO impl Display

impl<Sig, EncSig> Encodable for RefundProcedureSignatures<Sig, EncSig>
where
    Sig: CanonicalBytes,
    EncSig: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.cancel_sig.as_canonical_bytes().consensus_encode(s)?;
        Ok(len
            + self
                .refund_adaptor_sig
                .as_canonical_bytes()
                .consensus_encode(s)?)
    }
}

impl<Sig, EncSig> Decodable for RefundProcedureSignatures<Sig, EncSig>
where
    Sig: CanonicalBytes,
    EncSig: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            cancel_sig: Sig::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund_adaptor_sig: EncSig::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(RefundProcedureSignatures<Sig, EncSig>, Sig: CanonicalBytes, EncSig: CanonicalBytes);

impl<Sig, EncSig> Strategy for RefundProcedureSignatures<Sig, EncSig> {
    type Strategy = AsStrict;
}

// FIXME: needs bundle change
//impl<Ctx>
//    From<(
//        SwapId,
//        bundle::CosignedArbitratingCancel<Ctx::Ar>,
//        bundle::SignedAdaptorRefund<Ctx::Ar>,
//    )> for RefundProcedureSignatures<Ctx>
//where
//    Ctx: Swap,
//{
//    fn from(
//        bundles: (
//            SwapId,
//            bundle::CosignedArbitratingCancel<Ctx::Ar>,
//            bundle::SignedAdaptorRefund<Ctx::Ar>,
//        ),
//    ) -> Self {
//        Self {
//            swap_id: bundles.0,
//            cancel_sig: bundles.1.cancel_sig.clone(),
//            refund_adaptor_sig: bundles.2.refund_adaptor_sig,
//        }
//    }
//}

/// Protocol message intended to transmit [`SwapRole::Bob`]'s adaptor signature for the [`Buyable`]
/// transaction and the transaction itself. Uppon reception Alice must validate the transaction and
/// the adaptor signature.
///
/// [`SwapRole::Bob`]: crate::role::SwapRole::Bob
/// [`Buyable`]: crate::transaction::Buyable
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyProcedureSignature<PartialTx, EncSig> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The arbitrating `buy (c)` transaction.
    pub buy: PartialTx,
    /// The `Bb(Ta)` `buy (c)` adaptor signature.
    pub buy_adaptor_sig: EncSig,
}

// TODO impl Display

impl<PartialTx, EncSig> Encodable for BuyProcedureSignature<PartialTx, EncSig>
where
    PartialTx: CanonicalBytes,
    EncSig: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.buy.as_canonical_bytes().consensus_encode(s)?;
        Ok(len
            + self
                .buy_adaptor_sig
                .as_canonical_bytes()
                .consensus_encode(s)?)
    }
}

impl<PartialTx, EncSig> Decodable for BuyProcedureSignature<PartialTx, EncSig>
where
    PartialTx: CanonicalBytes,
    EncSig: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: PartialTx::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            buy_adaptor_sig: EncSig::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(BuyProcedureSignature<PartialTx, EncSig>, PartialTx: consensus::CanonicalBytes, EncSig: consensus::CanonicalBytes);

impl<PartialTx, EncSig> Strategy for BuyProcedureSignature<PartialTx, EncSig> {
    type Strategy = AsStrict;
}

// FIXME needs bundle change
//impl<PartialTx, EncSig> From<(SwapId, bundle::SignedAdaptorBuy<Ctx::Ar>)> for BuyProcedureSignature<PartialTx, EncSig>
////where
////    Ctx: Swap,
//{
//    fn from(bundle: (SwapId, bundle::SignedAdaptorBuy<Ctx::Ar>)) -> Self {
//        Self {
//            swap_id: bundle.0,
//            buy: bundle.1.buy.clone(),
//            buy_adaptor_sig: bundle.1.buy_adaptor_sig,
//        }
//    }
//}

/// Optional courtesy message from either [`SwapRole`] to inform the counterparty
/// that they have aborted the swap with an `OPTIONAL` message body to provide the reason.
///
/// [`SwapRole`]: crate::role::SwapRole
#[derive(Clone, Debug, Hash, Display)]
#[display(Debug)]
pub struct Abort {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// OPTIONAL `body`: error string.
    pub error_body: Option<String>,
}

impl Encodable for Abort {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.swap_id.consensus_encode(s)?;
        Ok(len + self.error_body.consensus_encode(s)?)
    }
}

impl Decodable for Abort {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            error_body: Option::<String>::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(Abort);

impl Strategy for Abort {
    type Strategy = AsStrict;
}
