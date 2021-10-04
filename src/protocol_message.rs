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
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct CommitAliceParameters<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Commitment to the buy public key.
    pub buy: Ctx::Commitment,
    /// Commitment to the cancel public key.
    pub cancel: Ctx::Commitment,
    /// Commitment to the refund public key.
    pub refund: Ctx::Commitment,
    /// Commitment to the punish public key.
    pub punish: Ctx::Commitment,
    /// Commitment to the adaptor public key.
    pub adaptor: Ctx::Commitment,
    /// Commitments to the extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the arbitrating shared keys.
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
    /// Commitment to the spend public key.
    pub spend: Ctx::Commitment,
    /// Commitments to the extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the accordant shared keys.
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
}

impl<Ctx> CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    pub fn commit_to_bundle(
        swap_id: SwapId,
        wallet: &impl Commit<Ctx::Commitment>,
        bundle: bundle::AliceParameters<Ctx>,
    ) -> Self {
        Self {
            swap_id,
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

impl<Ctx> Encodable for CommitAliceParameters<Ctx>
where
    Ctx: Swap,
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

impl<Ctx> Decodable for CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(CommitAliceParameters<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for CommitAliceParameters<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

// CommitAliceProof

/// Forces Alice to commit to the result of her cryptographic setup before receiving Bob's setup.
/// This is done to remove adaptive behavior in the cryptographic parameters.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct CommitAliceProof<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Commitment to the proof.
    pub proof: Ctx::Commitment,
}

impl<Ctx> CommitAliceProof<Ctx>
where
    Ctx: Swap,
{
    pub fn commit_to_bundle(
        swap_id: SwapId,
        wallet: &impl Commit<Ctx::Commitment>,
        bundle: bundle::AliceProof<Ctx>,
    ) -> Self {
        Self {
            swap_id,
            proof: wallet.commit_to(bundle.proof.as_canonical_bytes()),
        }
    }

    pub fn verify_with_reveal(
        &self,
        wallet: &impl Commit<Ctx::Commitment>,
        reveal: RevealAliceProof<Ctx>,
    ) -> Result<(), crypto::Error> {
        wallet.validate(reveal.proof.as_canonical_bytes(), self.proof.clone())
    }
}

impl<Ctx> Encodable for CommitAliceProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.swap_id.consensus_encode(s)?;
        Ok(len + self.proof.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for CommitAliceProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            proof: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(CommitAliceProof<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for CommitAliceProof<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

// CommitBobParameters

/// Forces Bob to commit to the result of his cryptographic setup before receiving Alice's setup.
/// This is done to remove adaptive behavior in the cryptographic parameters.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct CommitBobParameters<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Commitment to the buy public key.
    pub buy: Ctx::Commitment,
    /// Commitment to the cancel public key.
    pub cancel: Ctx::Commitment,
    /// Commitment to the refund public key.
    pub refund: Ctx::Commitment,
    /// Commitment to the adaptor public key.
    pub adaptor: Ctx::Commitment,
    /// Commitments to the extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the arbitrating shared keys.
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
    /// Commitment to the spend public key.
    pub spend: Ctx::Commitment,
    /// Commitments to the extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, Ctx::Commitment>>,
    /// Commitments to the accordant shared keys.
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, Ctx::Commitment>>,
}

impl<Ctx> CommitBobParameters<Ctx>
where
    Ctx: Swap,
{
    pub fn commit_to_bundle(
        swap_id: SwapId,
        wallet: &impl Commit<Ctx::Commitment>,
        bundle: bundle::BobParameters<Ctx>,
    ) -> Self {
        Self {
            swap_id,
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

impl<Ctx> Encodable for CommitBobParameters<Ctx>
where
    Ctx: Swap,
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

impl<Ctx> Decodable for CommitBobParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(CommitBobParameters<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for CommitBobParameters<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

// CommitBobProof

/// Forces Bob to commit to the result of his cryptographic setup before receiving Alice's setup.
/// This is done to remove adaptive behavior in the cryptographic parameters.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct CommitBobProof<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Commitment to the proof.
    pub proof: Ctx::Commitment,
}

impl<Ctx> CommitBobProof<Ctx>
where
    Ctx: Swap,
{
    pub fn commit_to_bundle(
        swap_id: SwapId,
        wallet: &impl Commit<Ctx::Commitment>,
        bundle: bundle::BobProof<Ctx>,
    ) -> Self {
        Self {
            swap_id,
            proof: wallet.commit_to(bundle.proof.as_canonical_bytes()),
        }
    }

    pub fn verify_with_reveal(
        &self,
        wallet: &impl Commit<Ctx::Commitment>,
        reveal: RevealBobProof<Ctx>,
    ) -> Result<(), crypto::Error> {
        wallet.validate(reveal.proof.as_canonical_bytes(), self.proof.clone())
    }
}

impl<Ctx> Encodable for CommitBobProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.swap_id.consensus_encode(s)?;
        Ok(len + self.proof.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for CommitBobProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            proof: Ctx::Commitment::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(CommitBobProof<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for CommitBobProof<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

// RevealAliceProof

/// Reveals the parameters commited by the [`CommitAliceParameters`] protocol message.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct RevealAliceProof<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Reveal the cross-group discrete logarithm zero-knowledge proof.
    pub proof: Ctx::Proof,
}

impl<Ctx> Encodable for RevealAliceProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.swap_id.consensus_encode(s)?;
        Ok(len + self.proof.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for RevealAliceProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            proof: Ctx::Proof::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(RevealAliceProof<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for RevealAliceProof<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx> From<(SwapId, bundle::AliceProof<Ctx>)> for RevealAliceProof<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: (SwapId, bundle::AliceProof<Ctx>)) -> Self {
        Self {
            swap_id: bundle.0,
            proof: bundle.1.proof,
        }
    }
}

// RevealAliceParameters

/// Reveals the parameters commited by the [`CommitAliceParameters`] protocol message.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct RevealAliceParameters<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Reveal the buy public key.
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the cancel public key.
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the refund public key.
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the punish public key.
    pub punish: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the adaptor public key.
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the vector of extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    /// Reveal the vector of extra arbitrating shared keys.
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedSecretKeys>::SharedSecretKey>>,
    /// Reveal the spend public key.
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    /// Reveal the vector of extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    /// Reveal the vector of extra accordant shared keys.
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedSecretKeys>::SharedSecretKey>>,
    /// Reveal the destination address.
    pub address: <Ctx::Ar as Address>::Address,
}

impl<Ctx> Encodable for RevealAliceParameters<Ctx>
where
    Ctx: Swap,
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
        len += self.accordant_shared_keys.consensus_encode(s)?;
        Ok(len + self.address.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for RevealAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            refund: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            punish: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            adaptor: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: <Ctx::Ac as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            address: <Ctx::Ar as Address>::Address::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(RevealAliceParameters<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for RevealAliceParameters<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx> From<(SwapId, bundle::AliceParameters<Ctx>)> for RevealAliceParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: (SwapId, bundle::AliceParameters<Ctx>)) -> Self {
        Self {
            swap_id: bundle.0,
            buy: bundle.1.buy,
            cancel: bundle.1.cancel,
            refund: bundle.1.refund,
            punish: bundle.1.punish,
            adaptor: bundle.1.adaptor,
            extra_arbitrating_keys: bundle.1.extra_arbitrating_keys,
            arbitrating_shared_keys: bundle.1.arbitrating_shared_keys,
            spend: bundle.1.spend,
            extra_accordant_keys: bundle.1.extra_accordant_keys,
            accordant_shared_keys: bundle.1.accordant_shared_keys,
            address: bundle.1.destination_address,
        }
    }
}

// RevealBobProof

/// Reveals the proof commited by the [`CommitBobParameters`] protocol message.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct RevealBobProof<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The cross-group discrete logarithm zero-knowledge proof.
    pub proof: Ctx::Proof,
}

/// Reveals the parameters commited by the [`CommitBobParameters`] protocol message.
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct RevealBobParameters<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// Reveal the buy public key.
    pub buy: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the cancel public key.
    pub cancel: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the refund public key.
    pub refund: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the adaptor public key.
    pub adaptor: <Ctx::Ar as Keys>::PublicKey,
    /// Reveal the vector of extra arbitrating public keys.
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
    /// Reveal the vector of extra arbitrating shared keys.
    pub arbitrating_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedSecretKeys>::SharedSecretKey>>,
    /// Reveal the spend public key.
    pub spend: <Ctx::Ac as Keys>::PublicKey,
    /// Reveal the vector of extra accordant public keys.
    pub extra_accordant_keys: Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
    /// Reveal the vector of extra accordant shared keys.
    pub accordant_shared_keys:
        Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedSecretKeys>::SharedSecretKey>>,
    /// The refund Bitcoin address.
    pub address: <Ctx::Ar as Address>::Address,
}

impl<Ctx> Encodable for RevealBobParameters<Ctx>
where
    Ctx: Swap,
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

impl<Ctx> Encodable for RevealBobProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.swap_id.consensus_encode(s)?;
        Ok(len + self.proof.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for RevealBobParameters<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            refund: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            adaptor: <Ctx::Ar as Keys>::PublicKey::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: <Ctx::Ac as Keys>::PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            address: <Ctx::Ar as Address>::Address::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl<Ctx> Decodable for RevealBobProof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            proof: Ctx::Proof::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
        })
    }
}

impl_strict_encoding!(RevealBobParameters<Ctx>, Ctx: Swap);
impl_strict_encoding!(RevealBobProof<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for RevealBobParameters<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx> Strategy for RevealBobProof<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx> From<(SwapId, bundle::BobParameters<Ctx>)> for RevealBobParameters<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: (SwapId, bundle::BobParameters<Ctx>)) -> Self {
        Self {
            swap_id: bundle.0,
            buy: bundle.1.buy,
            cancel: bundle.1.cancel,
            refund: bundle.1.refund,
            adaptor: bundle.1.adaptor,
            extra_arbitrating_keys: bundle.1.extra_arbitrating_keys,
            arbitrating_shared_keys: bundle.1.arbitrating_shared_keys,
            spend: bundle.1.spend,
            extra_accordant_keys: bundle.1.extra_accordant_keys,
            accordant_shared_keys: bundle.1.accordant_shared_keys,
            address: bundle.1.refund_address,
        }
    }
}

impl<Ctx> From<(SwapId, bundle::BobProof<Ctx>)> for RevealBobProof<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: (SwapId, bundle::BobProof<Ctx>)) -> Self {
        Self {
            swap_id: bundle.0,
            proof: bundle.1.proof,
        }
    }
}

/// Sends the [`Lockable`], [`Cancelable`] and [`Refundable`] arbritrating transactions from
/// [`SwapRole::Bob`] to [`SwapRole::Alice`], as well as Bob's signature for the [`Cancelable`]
/// transaction.
///
/// [`SwapRole::Alice`]: crate::role::SwapRole::Alice
/// [`SwapRole::Bob`]: crate::role::SwapRole::Bob
/// [`Lockable`]: crate::transaction::Lockable
/// [`Cancelable`]: crate::transaction::Cancelable
/// [`Refundable`]: crate::transaction::Refundable
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct CoreArbitratingSetup<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The arbitrating `lock (b)` transaction.
    pub lock: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The arbitrating `cancel (d)` transaction.
    pub cancel: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The arbitrating `refund (e)` transaction.
    pub refund: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The `Bc` `cancel (d)` signature.
    pub cancel_sig: <Ctx::Ar as Signatures>::Signature,
}

impl<Ctx> Encodable for CoreArbitratingSetup<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.swap_id.consensus_encode(s)?;
        len += self.lock.as_canonical_bytes().consensus_encode(s)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(s)?;
        len += self.refund.as_canonical_bytes().consensus_encode(s)?;
        Ok(len + self.cancel_sig.as_canonical_bytes().consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for CoreArbitratingSetup<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            lock: <Ctx::Ar as Onchain>::PartialTransaction::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            cancel: <Ctx::Ar as Onchain>::PartialTransaction::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            refund: <Ctx::Ar as Onchain>::PartialTransaction::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            cancel_sig: <Ctx::Ar as Signatures>::Signature::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(CoreArbitratingSetup<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for CoreArbitratingSetup<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx>
    From<(
        SwapId,
        bundle::CoreArbitratingTransactions<Ctx::Ar>,
        bundle::CosignedArbitratingCancel<Ctx::Ar>,
    )> for CoreArbitratingSetup<Ctx>
where
    Ctx: Swap,
{
    fn from(
        bundles: (
            SwapId,
            bundle::CoreArbitratingTransactions<Ctx::Ar>,
            bundle::CosignedArbitratingCancel<Ctx::Ar>,
        ),
    ) -> Self {
        Self {
            swap_id: bundles.0,
            lock: bundles.1.lock,
            cancel: bundles.1.cancel,
            refund: bundles.1.refund,
            cancel_sig: bundles.2.cancel_sig,
        }
    }
}

/// Protocol message is intended to transmit [`SwapRole::Alice`]'s signature for the [`Cancelable`]
/// transaction and Alice's adaptor signature for the [`Refundable`] transaction. Uppon reception
/// [`SwapRole::Bob`] must validate the signatures.
///
/// [`SwapRole::Alice`]: crate::role::SwapRole::Alice
/// [`SwapRole::Bob`]: crate::role::SwapRole::Bob
/// [`Cancelable`]: crate::transaction::Cancelable
/// [`Refundable`]: crate::transaction::Refundable
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct RefundProcedureSignatures<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The `Ac` `cancel (d)` signature.
    pub cancel_sig: <Ctx::Ar as Signatures>::Signature,
    /// The `Ar(Tb)` `refund (e)` adaptor signature.
    pub refund_adaptor_sig: <Ctx::Ar as Signatures>::EncryptedSignature,
}

impl<Ctx> Encodable for RefundProcedureSignatures<Ctx>
where
    Ctx: Swap,
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

impl<Ctx> Decodable for RefundProcedureSignatures<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            cancel_sig: <Ctx::Ar as Signatures>::Signature::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            refund_adaptor_sig: <Ctx::Ar as Signatures>::EncryptedSignature::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(RefundProcedureSignatures<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for RefundProcedureSignatures<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx>
    From<(
        SwapId,
        bundle::CosignedArbitratingCancel<Ctx::Ar>,
        bundle::SignedAdaptorRefund<Ctx::Ar>,
    )> for RefundProcedureSignatures<Ctx>
where
    Ctx: Swap,
{
    fn from(
        bundles: (
            SwapId,
            bundle::CosignedArbitratingCancel<Ctx::Ar>,
            bundle::SignedAdaptorRefund<Ctx::Ar>,
        ),
    ) -> Self {
        Self {
            swap_id: bundles.0,
            cancel_sig: bundles.1.cancel_sig.clone(),
            refund_adaptor_sig: bundles.2.refund_adaptor_sig,
        }
    }
}

/// Protocol message intended to transmit [`SwapRole::Bob`]'s adaptor signature for the [`Buyable`]
/// transaction and the transaction itself. Uppon reception Alice must validate the transaction and
/// the adaptor signature.
///
/// [`SwapRole::Bob`]: crate::role::SwapRole::Bob
/// [`Buyable`]: crate::transaction::Buyable
#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct BuyProcedureSignature<Ctx: Swap> {
    /// The swap identifier related to this message.
    pub swap_id: SwapId,
    /// The arbitrating `buy (c)` transaction.
    pub buy: <Ctx::Ar as Onchain>::PartialTransaction,
    /// The `Bb(Ta)` `buy (c)` adaptor signature.
    pub buy_adaptor_sig: <Ctx::Ar as Signatures>::EncryptedSignature,
}

impl<Ctx> Encodable for BuyProcedureSignature<Ctx>
where
    Ctx: Swap,
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

impl<Ctx> Decodable for BuyProcedureSignature<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            swap_id: Decodable::consensus_decode(d)?,
            buy: <Ctx::Ar as Onchain>::PartialTransaction::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            buy_adaptor_sig: <Ctx::Ar as Signatures>::EncryptedSignature::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(BuyProcedureSignature<Ctx>, Ctx: Swap);

impl<Ctx> Strategy for BuyProcedureSignature<Ctx>
where
    Ctx: Swap,
{
    type Strategy = AsStrict;
}

impl<Ctx> From<(SwapId, bundle::SignedAdaptorBuy<Ctx::Ar>)> for BuyProcedureSignature<Ctx>
where
    Ctx: Swap,
{
    fn from(bundle: (SwapId, bundle::SignedAdaptorBuy<Ctx::Ar>)) -> Self {
        Self {
            swap_id: bundle.0,
            buy: bundle.1.buy.clone(),
            buy_adaptor_sig: bundle.1.buy_adaptor_sig,
        }
    }
}

/// Optional courtesy message from either [`SwapRole`] to inform the counterparty
/// that they have aborted the swap with an `OPTIONAL` message body to provide the reason.
///
/// [`SwapRole`]: crate::role::SwapRole
#[derive(Clone, Debug, Display)]
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
