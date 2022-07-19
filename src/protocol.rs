// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

//! Protocol execution and messages exchanged between peers.

// For this file we allow having complex types
#![allow(clippy::type_complexity)]

use std::io;

use crate::blockchain::{Fee, FeePriority, FeeStrategy, Transactions};
use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};
use crate::crypto::{
    self, AccordantKeyId, ArbitratingKeyId, Commit, DeriveKeys, EncSign, KeyGenerator,
    RecoverSecret, SharedKeyId, Sign, TaggedElement, TaggedElements, TaggedExtraKeys,
    TaggedSharedKeys,
};
use crate::negotiation::PublicOffer;
use crate::protocol::message::{
    BuyProcedureSignature, CommitAliceParameters, CommitBobParameters, CoreArbitratingSetup,
    RevealAliceParameters, RevealBobParameters,
};
use crate::script::{DataLock, DataPunishableLock, DoubleKeys, ScriptPath};
use crate::swap::SwapId;
use crate::transaction::{
    Buyable, Cancelable, Chainable, Fundable, Lockable, Punishable, Refundable, Transaction,
    Witnessable,
};
use crate::{Error, Res};

pub mod message;

struct ValidatedCoreTransactions<Px, Ti, Pk> {
    lock: Px,
    cancel: Px,
    refund: Px,
    punish_lock: DataPunishableLock<Ti, Pk>,
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct CoreArbitratingTransactions<Px> {
    /// Partial transaction raw type representing the lock.
    pub lock: Px,
    /// Partial transaction raw type representing the cancel.
    pub cancel: Px,
    /// Partial transaction raw type representing the refund.
    pub refund: Px,
}

impl<Px> CoreArbitratingTransactions<Px> {
    pub fn into_arbitrating_setup<Sig>(
        self,
        swap_id: SwapId,
        cancel_sig: Sig,
    ) -> CoreArbitratingSetup<Px, Sig> {
        CoreArbitratingSetup {
            swap_id,
            lock: self.lock,
            cancel: self.cancel,
            refund: self.refund,
            cancel_sig,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct ArbitratingParameters<Amt, Ti, F> {
    pub arbitrating_amount: Amt,
    pub cancel_timelock: Ti,
    pub punish_timelock: Ti,
    pub fee_strategy: FeeStrategy<F>,
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct TxSignatures<Sig> {
    pub sig: Sig,
    pub adapted_sig: Sig,
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct FullySignedPunish<Px, Sig> {
    pub punish: Px,
    pub punish_sig: Sig,
}

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr> {
    pub buy: Pk,
    pub cancel: Pk,
    pub refund: Pk,
    pub punish: Option<Pk>,
    pub adaptor: Pk,
    pub extra_arbitrating_keys: Vec<TaggedElement<u16, Pk>>,
    pub arbitrating_shared_keys: Vec<TaggedElement<SharedKeyId, Rk>>,
    pub spend: Qk,
    pub extra_accordant_keys: Vec<TaggedElement<u16, Qk>>,
    pub accordant_shared_keys: Vec<TaggedElement<SharedKeyId, Sk>>,
    pub proof: Option<Pr>,
    pub destination_address: Addr,
    pub cancel_timelock: Option<Ti>,
    pub punish_timelock: Option<Ti>,
    pub fee_strategy: Option<FeeStrategy<F>>,
}

impl<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr> Encodable for Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>
where
    Pk: CanonicalBytes,
    Qk: CanonicalBytes,
    Rk: CanonicalBytes,
    Sk: CanonicalBytes,
    Addr: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
    Pr: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.buy.as_canonical_bytes().consensus_encode(writer)?;
        len += self.cancel.as_canonical_bytes().consensus_encode(writer)?;
        len += self.refund.as_canonical_bytes().consensus_encode(writer)?;
        len += self.punish.as_canonical_bytes().consensus_encode(writer)?;
        len += self.adaptor.as_canonical_bytes().consensus_encode(writer)?;
        len += self.extra_arbitrating_keys.consensus_encode(writer)?;
        len += self.arbitrating_shared_keys.consensus_encode(writer)?;
        len += self.spend.as_canonical_bytes().consensus_encode(writer)?;
        len += self.extra_accordant_keys.consensus_encode(writer)?;
        len += self.accordant_shared_keys.consensus_encode(writer)?;
        len += self.proof.as_canonical_bytes().consensus_encode(writer)?;
        len += self
            .destination_address
            .as_canonical_bytes()
            .consensus_encode(writer)?;
        len += self
            .cancel_timelock
            .as_canonical_bytes()
            .consensus_encode(writer)?;
        len += self
            .punish_timelock
            .as_canonical_bytes()
            .consensus_encode(writer)?;
        Ok(len
            + self
                .fee_strategy
                .as_canonical_bytes()
                .consensus_encode(writer)?)
    }
}

impl<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr> Decodable for Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>
where
    Pk: CanonicalBytes,
    Qk: CanonicalBytes,
    Rk: CanonicalBytes,
    Sk: CanonicalBytes,
    Addr: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
    Pr: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Parameters {
            buy: Pk::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel: Pk::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            refund: Pk::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish: Option::<Pk>::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            adaptor: Pk::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_arbitrating_keys: Decodable::consensus_decode(d)?,
            arbitrating_shared_keys: Decodable::consensus_decode(d)?,
            spend: Qk::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            extra_accordant_keys: Decodable::consensus_decode(d)?,
            accordant_shared_keys: Decodable::consensus_decode(d)?,
            proof: Option::<Pr>::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            destination_address: Addr::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel_timelock: Option::<Ti>::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish_timelock: Option::<Ti>::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            fee_strategy: Option::<FeeStrategy<F>>::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
        })
    }
}

impl_strict_encoding!(Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>, Pk: CanonicalBytes, Qk: CanonicalBytes, Rk: CanonicalBytes, Sk: CanonicalBytes, Addr: CanonicalBytes, Ti: CanonicalBytes, F: CanonicalBytes, Pr: CanonicalBytes);

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

impl<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr> Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>
where
    Pk: Clone + CanonicalBytes,
    Qk: CanonicalBytes,
    Rk: CanonicalBytes,
    Sk: CanonicalBytes,
{
    pub fn commit_alice<C: Clone + Eq>(
        &self,
        swap_id: SwapId,
        wallet: &impl Commit<C>,
    ) -> CommitAliceParameters<C> {
        CommitAliceParameters {
            swap_id,
            buy: wallet.commit_to(self.buy.as_canonical_bytes()),
            cancel: wallet.commit_to(self.cancel.as_canonical_bytes()),
            refund: wallet.commit_to(self.refund.as_canonical_bytes()),
            punish: wallet.commit_to(
                self.punish
                    .clone()
                    .expect("Alice has punish")
                    .as_canonical_bytes(),
            ),
            adaptor: wallet.commit_to(self.adaptor.as_canonical_bytes()),
            extra_arbitrating_keys: commit_to_vec(wallet, &self.extra_arbitrating_keys),
            arbitrating_shared_keys: commit_to_vec(wallet, &self.arbitrating_shared_keys),
            spend: wallet.commit_to(self.spend.as_canonical_bytes()),
            extra_accordant_keys: commit_to_vec(wallet, &self.extra_accordant_keys),
            accordant_shared_keys: commit_to_vec(wallet, &self.accordant_shared_keys),
        }
    }

    pub fn reveal_alice(self, swap_id: SwapId) -> RevealAliceParameters<Pk, Qk, Rk, Sk, Addr> {
        RevealAliceParameters {
            swap_id,
            buy: self.buy,
            cancel: self.cancel,
            refund: self.refund,
            punish: self.punish.expect("Alice has punish"),
            adaptor: self.adaptor,
            extra_arbitrating_keys: self.extra_arbitrating_keys,
            arbitrating_shared_keys: self.arbitrating_shared_keys,
            spend: self.spend,
            extra_accordant_keys: self.extra_accordant_keys,
            accordant_shared_keys: self.accordant_shared_keys,
            address: self.destination_address,
        }
    }

    pub fn commit_bob<C: Clone + Eq>(
        &self,
        swap_id: SwapId,
        wallet: &impl Commit<C>,
    ) -> CommitBobParameters<C> {
        CommitBobParameters {
            swap_id,
            buy: wallet.commit_to(self.buy.as_canonical_bytes()),
            cancel: wallet.commit_to(self.cancel.as_canonical_bytes()),
            refund: wallet.commit_to(self.refund.as_canonical_bytes()),
            adaptor: wallet.commit_to(self.adaptor.as_canonical_bytes()),
            extra_arbitrating_keys: commit_to_vec(wallet, &self.extra_arbitrating_keys),
            arbitrating_shared_keys: commit_to_vec(wallet, &self.arbitrating_shared_keys),
            spend: wallet.commit_to(self.spend.as_canonical_bytes()),
            extra_accordant_keys: commit_to_vec(wallet, &self.extra_accordant_keys),
            accordant_shared_keys: commit_to_vec(wallet, &self.accordant_shared_keys),
        }
    }

    pub fn reveal_bob(self, swap_id: SwapId) -> RevealBobParameters<Pk, Qk, Rk, Sk, Addr> {
        RevealBobParameters {
            swap_id,
            buy: self.buy,
            cancel: self.cancel,
            refund: self.refund,
            adaptor: self.adaptor,
            extra_arbitrating_keys: self.extra_arbitrating_keys,
            arbitrating_shared_keys: self.arbitrating_shared_keys,
            spend: self.spend,
            extra_accordant_keys: self.extra_accordant_keys,
            accordant_shared_keys: self.accordant_shared_keys,
            address: self.destination_address,
        }
    }
}

/// Alice, a [`SwapRole`], starts with [`Accordant`] blockchain assets and exchange them for
/// [`Arbitrating`] blockchain assets.
#[derive(Debug, Clone)]
pub struct Alice<Addr, Ar, Ac> {
    /// The **arbitrating** blockchain to use during the swap
    pub arbitrating: Ar,
    /// The **accordant** blockchain to use during the swap
    pub accordant: Ac,
    /// An arbitrating address where, if successfully executed, the funds exchanged will be sent to
    pub destination_address: Addr,
    /// The fee politic to apply during the swap fee calculation
    pub fee_politic: FeePriority,
}

impl<Addr, Ar, Ac> Encodable for Alice<Addr, Ar, Ac>
where
    Ar: Encodable,
    Ac: Encodable,
    Addr: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.fee_politic.consensus_encode(writer)?;
        len += self.arbitrating.consensus_encode(writer)?;
        len += self.accordant.consensus_encode(writer)?;
        Ok(len
            + self
                .destination_address
                .as_canonical_bytes()
                .consensus_encode(writer)?)
    }
}

impl<Addr, Ar, Ac> Decodable for Alice<Addr, Ar, Ac>
where
    Ar: Decodable,
    Ac: Decodable,
    Addr: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let fee_politic = FeePriority::consensus_decode(d)?;
        let arbitrating = Decodable::consensus_decode(d)?;
        let accordant = Decodable::consensus_decode(d)?;
        let destination_address = Addr::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?;
        Ok(Alice {
            arbitrating,
            accordant,
            destination_address,
            fee_politic,
        })
    }
}

impl<Addr, Ar, Ac> Alice<Addr, Ar, Ac> {
    /// Create a new role for Alice with the local parameters.
    pub fn new(
        arbitrating: Ar,
        accordant: Ac,
        destination_address: Addr,
        fee_politic: FeePriority,
    ) -> Self {
        Self {
            arbitrating,
            accordant,
            destination_address,
            fee_politic,
        }
    }
}

impl<Addr, Ar, Ac> Alice<Addr, Ar, Ac>
where
    Addr: Clone,
{
    /// Generate Alice's parameters for the protocol execution based on the key generator public
    /// offer agreed upon during the negotiation phase.
    ///
    /// # Safety
    ///
    /// All the data passed to the function are considered trusted and does not require extra
    /// validation.
    ///
    /// The parameters contain:
    ///
    ///  * The public keys used in the arbitrating and accordant blockchains
    ///  * The cryptographic proof
    ///  * The shared private keys (for reading opaque blockchains)
    ///  * The timelock parameters from the public offer
    ///  * The target arbitrating address used by Alice
    ///
    pub fn generate_parameters<Kg, Amt, Bmt, Ti, F, Pk, Qk, Rk, Sk, Pr>(
        &self,
        key_gen: &mut Kg,
        public_offer: &PublicOffer<Amt, Bmt, Ti, F>,
    ) -> Res<Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>>
    where
        Ar: DeriveKeys<PublicKey = Pk, PrivateKey = Rk>,
        Ac: DeriveKeys<PublicKey = Qk, PrivateKey = Sk>,
        Ti: Copy,
        F: Copy,
        Kg: KeyGenerator<Pk, Qk, Rk, Sk, Pr>,
    {
        let extra_arbitrating_keys: Res<TaggedExtraKeys<Pk>> = Ar::extra_public_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_pubkey(ArbitratingKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let arbitrating_shared_keys: Res<TaggedSharedKeys<Rk>> = Ar::extra_shared_private_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let extra_accordant_keys: Res<TaggedExtraKeys<Qk>> = Ac::extra_public_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_pubkey(AccordantKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let accordant_shared_keys: Res<TaggedSharedKeys<Sk>> = Ac::extra_shared_private_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let (spend, adaptor, proof) = key_gen.generate_proof()?;

        Ok(Parameters {
            buy: key_gen.get_pubkey(ArbitratingKeyId::Buy)?,
            cancel: key_gen.get_pubkey(ArbitratingKeyId::Cancel)?,
            refund: key_gen.get_pubkey(ArbitratingKeyId::Refund)?,
            punish: Some(key_gen.get_pubkey(ArbitratingKeyId::Punish)?),
            adaptor,
            extra_arbitrating_keys: extra_arbitrating_keys?,
            arbitrating_shared_keys: arbitrating_shared_keys?,
            spend,
            extra_accordant_keys: extra_accordant_keys?,
            accordant_shared_keys: accordant_shared_keys?,
            proof: Some(proof),
            destination_address: self.destination_address.clone(),
            cancel_timelock: Some(public_offer.offer.cancel_timelock),
            punish_timelock: Some(public_offer.offer.punish_timelock),
            fee_strategy: Some(public_offer.offer.fee_strategy),
        })
    }

    // FIXME: check if doc is up-to-date
    /// Generates the witness on the [`Refundable`] transaction and adaptor sign it.
    ///
    /// # Safety
    ///
    /// [`BobParameters`] bundle is created and validated with the protocol messages that commit
    /// and reveal the values present in the bundle.
    ///
    /// **This function assumes that the commit/reveal scheme has been validated and assumes that
    /// all cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and requries extra validation.
    ///
    /// _Previously verified data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `ar_engine`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Verified data_:
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Refundable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Validate the [`Lockable`], [`Cancelable`], [`Refundable`] partial transactions in
    ///  [`CoreArbitratingTransactions`]
    ///  * Retrieve Bob's adaptor public key from [`BobParameters`] bundle
    ///  * Retrieve Alice's refund public key from [`AliceParameters`] bundle
    ///  * Generate the witness data and adaptor sign it
    ///
    /// Returns the adaptor signature inside the [`SignedAdaptorRefund`] bundle.
    ///
    pub fn sign_adaptor_refund<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si, EncSig>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
    ) -> Res<EncSig>
    where
        S: EncSign<Pk, Ms, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Pk: Copy,
        Ti: Copy,
        Amt: Copy + PartialEq,
    {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { refund, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, arb_params)?;

        // Generate the witness message to sign and adaptor sign with the refund key and the
        // counter-party adaptor.
        let adaptor = &bob_parameters.adaptor;
        let refund = <Ar::Refund>::from_partial(refund);
        let msg = refund.generate_witness_message(ScriptPath::Success)?;
        wallet
            .encrypt_sign(ArbitratingKeyId::Refund, adaptor, msg)
            .map_err(Into::into)
    }

    // FIXME check doc
    /// Generates the witness on the [`Cancelable`] transaction and sign it.
    ///
    /// # Safety
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and requries extra validation.
    ///
    /// _Previously verified data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `ar_engine`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Verified data_:
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Cancelable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Validate the [`Lockable`], [`Cancelable`], [`Refundable`] partial transactions in
    ///  [`CoreArbitratingTransactions`]
    ///  * Retreive Alice's cancel public key from the parameters
    ///  * Generate the witness data and sign it
    ///
    /// Returns the witness inside the [`CosignedArbitratingCancel`] bundle.
    ///
    pub fn cosign_arbitrating_cancel<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
    ) -> Res<Si>
    where
        S: Sign<Pk, Ms, Si>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Pk: Copy,
        Ti: Copy,
        Amt: Copy + PartialEq,
    {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { cancel, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, arb_params)?;

        // Generate the witness message to sign and sign with the cancel key.
        let cancel = <Ar::Cancel>::from_partial(cancel);
        let msg = cancel.generate_witness_message(ScriptPath::Failure)?;
        wallet
            .sign(ArbitratingKeyId::Cancel, msg)
            .map_err(Into::into)
    }

    /// Validates the adaptor buy witness with based on the parameters and the buy arbitrating
    /// transactions.
    ///
    /// # Safety
    ///
    /// [`BobParameters`] bundle is created and validated with the protocol messages that commit
    /// and reveal the values present in the bundle.
    ///
    /// **This function assumes that the commit/reveal scheme has been validated and assumes that
    /// all cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// _Previously verified data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Verified data_:
    ///  * `core`: Core arbitrating transactions bundle
    ///  * `adaptor_buy`: The adaptor witness to verify
    ///
    /// # Execution
    ///
    ///  * Parse the [`Buyable`] partial transaction in [`SignedAdaptorBuy`]
    ///  * Verify the adaptor witness in [`SignedAdaptorBuy`] with the public keys from the
    ///  parameters bundles
    ///
    pub fn validate_adaptor_buy<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si, EncSig>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
        adaptor_buy: &BuyProcedureSignature<Px, EncSig>,
    ) -> Res<()>
    where
        S: EncSign<Pk, Ms, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Pk: Copy,
        Ti: Copy,
        F: Copy,
        Amt: Copy + PartialEq,
    {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { lock, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, arb_params)?;
        let lock = <Ar::Lock>::from_partial(lock);

        let fee_strategy = &arb_params.fee_strategy;

        // Extract the partial transaction from the adaptor buy bundle, this operation should not
        // error if the bundle is well formed.
        let partial_buy = adaptor_buy.buy.clone();

        // Initialize the buy transaction based on the extracted partial transaction format.
        let buy = <Ar::Buy>::from_partial(partial_buy);

        buy.is_build_on_top_of(&lock)?;
        buy.verify_template(self.destination_address.clone())?;
        buy.as_partial().validate_fee(fee_strategy)?;

        // Verify the adaptor buy witness
        let msg = buy.generate_witness_message(ScriptPath::Success)?;
        wallet.verify_encrypted_signature(
            &bob_parameters.buy,
            &alice_parameters.adaptor,
            msg,
            &adaptor_buy.buy_adaptor_sig,
        )?;

        Ok(())
    }

    /// Sign the arbitrating [`Buyable`] transaction and adapt the counter-party adaptor witness
    /// with the private adaptor key.
    ///
    /// # Safety
    ///
    /// This function **MUST NOT** be run if [`validate_adaptor_buy`] is not successful.
    ///
    /// [`SignedAdaptorBuy`] bundle is created by Bob and must be verified to be a valid encrypted
    /// signature and a valid transaction.
    ///
    /// **This function assumes that the adaptor signature has been validated and assumes that all
    /// cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// _Previously verified data_:
    ///  * `signed_adaptor_buy`: Verified by [`validate_adaptor_buy`]
    ///
    /// _Trusted data_:
    ///  * `ar_engine`, `ac_engine`: Bob's arbitrating and accordant seeds
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Verified data_:
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Buyable`] partial transaction in [`SignedAdaptorBuy`]
    ///  * Retreive the buy public key from the paramters
    ///  * Generate the buy witness data and sign it
    ///  * Retreive the adaptor public key from the parameters
    ///  * Adapt the signature
    ///
    /// Returns the signatures inside a [`TxSignatures`] bundle.
    ///
    /// [`validate_adaptor_buy`]: Alice::validate_adaptor_buy
    ///
    pub fn fully_sign_buy<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si, EncSig>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
        adaptor_buy: &BuyProcedureSignature<Px, EncSig>,
    ) -> Res<TxSignatures<Si>>
    where
        S: Sign<Pk, Ms, Si> + EncSign<Pk, Ms, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Pk: Copy,
        Ti: Copy,
        F: Copy,
        Amt: Copy + PartialEq,
        EncSig: Clone,
    {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { lock, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, arb_params)?;
        let lock = <Ar::Lock>::from_partial(lock);

        let fee_strategy = &arb_params.fee_strategy;

        // Extract the partial transaction from the adaptor buy bundle, this operation should not
        // error if the bundle is well formed.
        let partial_buy = adaptor_buy.buy.clone();

        // Initialize the buy transaction based on the extracted partial transaction format.
        let buy = <Ar::Buy>::from_partial(partial_buy);

        buy.is_build_on_top_of(&lock)?;
        buy.verify_template(self.destination_address.clone())?;
        buy.as_partial().validate_fee(fee_strategy)?;

        // Generate the witness message to sign and sign with the buy key.
        let msg = buy.generate_witness_message(ScriptPath::Success)?;
        let sig = wallet.sign(ArbitratingKeyId::Buy, msg)?;

        // Retreive the adaptor public key and the counter-party adaptor witness.
        let adapted_sig =
            wallet.decrypt_signature(AccordantKeyId::Spend, adaptor_buy.buy_adaptor_sig.clone())?;

        Ok(TxSignatures { sig, adapted_sig })
    }

    /// Create and sign the arbitrating [`Punishable`] transaction.
    ///
    /// # Safety
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and requries extra validation.
    ///
    /// This transaction does not require the same validation of Bob's parameters because the
    /// adaptor is not used and no private key is revealed during the process. Alice's should
    /// always be able to produce the punish transaction if the contract on cancel has been
    /// correctly validated.
    ///
    /// _Previously verified data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///  * `core`: The core arbitrating transactions
    ///
    /// _Trusted data_:
    ///  * `ar_engine`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Buyable`] partial transaction in [`SignedAdaptorBuy`]
    ///  * Retreive the buy public key from the parameters
    ///  * Generate the buy witness data
    ///  * Retreive the adaptor public key from the parameters
    ///  * Adapt the signature
    ///
    /// Returns the signatures inside a [`TxSignatures`] bundle.
    ///
    /// [`validate_adaptor_buy`]: Alice::validate_adaptor_buy
    ///
    pub fn fully_sign_punish<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
    ) -> Res<FullySignedPunish<Px, Si>>
    where
        S: Sign<Pk, Ms, Si>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Pk: Copy,
        Ti: Copy,
        F: Copy,
        Amt: Copy + PartialEq,
    {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions {
            cancel,
            punish_lock,
            ..
        } = self.validate_core(alice_parameters, bob_parameters, core, arb_params)?;
        let cancel = <Ar::Cancel>::from_partial(cancel);

        let fee_strategy = &arb_params.fee_strategy;

        // Initialize the punish transaction based on the cancel transaction.
        let mut punish =
            <Ar::Punish>::initialize(&cancel, punish_lock, self.destination_address.clone())?;

        // Set the fees according to the strategy in the offer and the local politic.
        punish
            .as_partial_mut()
            .set_fee(fee_strategy, self.fee_politic)?;

        // Generate the witness message to sign and sign with the punish key.
        let msg = punish.generate_witness_message(ScriptPath::Failure)?;
        let punish_sig = wallet.sign(ArbitratingKeyId::Punish, msg)?;

        Ok(FullySignedPunish {
            punish: punish.to_partial(),
            punish_sig,
        })
    }

    // TODO: transform into other private key type
    pub fn recover_accordant_key<Amt, Tx, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Si, EncSig>(
        &self,
        wallet: &mut S,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        refund_adaptor_sig: EncSig,
        refund_tx: Tx,
    ) -> Rk
    where
        S: RecoverSecret<Pk, Rk, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Pk = Pk, Si = Si, Px = Px, Tx = Tx>,
    {
        let encryption_key = &bob_parameters.adaptor;
        let signature = <Ar::Refund>::extract_witness(refund_tx);
        wallet.recover_secret_key(refund_adaptor_sig, encryption_key, signature)
    }

    // FIXME check doc
    // Internal method to parse and validate the core arbitratring transactions received by Alice
    // from Bob.
    //
    // Each transaction is parsed from the bundle and initialized from its partial transaction
    // format. After initialization validation tests are performed to ensure:
    //
    //  * the transaction template is valid (transaction is well formed, contract and keys are used
    //  correctly)
    //  * the target amount from the offer is correct (for the lock transaction)
    //  * the fee strategy validation passes
    fn validate_core<Amt, Pk, Qk, Rk, Sk, Ti, F, Pr, Ms, Si, Px>(
        &self,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
    ) -> Res<ValidatedCoreTransactions<Px, Ti, Pk>>
    where
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Amt: PartialEq + Copy,
        Pk: Copy,
        Ti: Copy,
    {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.clone();

        // Initialize the lock transaction based on the extracted partial transaction format.
        let lock = <Ar::Lock>::from_partial(partial_lock);

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy;
        let bob_buy = bob_parameters.buy;
        let alice_cancel = alice_parameters.cancel;
        let bob_cancel = bob_parameters.cancel;

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let data_lock = DataLock {
            timelock: arb_params.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // Verify the lock transaction template.
        lock.verify_template(data_lock)?;
        // The target amount is dictated from the public offer.
        let target_amount = arb_params.arbitrating_amount;
        // Verify the target amount
        lock.verify_target_amount(target_amount)?;
        // Validate that the transaction follows the strategy.
        let fee_strategy = &arb_params.fee_strategy;
        lock.as_partial().validate_fee(fee_strategy)?;

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        let alice_refund = alice_parameters.refund;
        let bob_refund = bob_parameters.refund;
        let alice_punish = alice_parameters
            .punish
            .expect("Alice has a punish transaction");

        // Create the data structure that represents an on-chain punishable contract for the
        // arbitrating blockchain.
        let punish_lock = DataPunishableLock {
            timelock: arb_params.punish_timelock,
            success: DoubleKeys::new(alice_refund, bob_refund),
            failure: alice_punish,
        };

        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_cancel = core.cancel.clone();

        // Initialize the lock transaction based on the extracted partial transaction format.
        let cancel = <Ar::Cancel>::from_partial(partial_cancel);
        // Check that the cancel transaction is build on top of the lock.
        cancel.is_build_on_top_of(&lock)?;
        cancel.verify_template(data_lock, punish_lock)?;
        // Validate the fee strategy
        cancel.as_partial().validate_fee(fee_strategy)?;

        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.clone();

        // Initialize the refund transaction based on the extracted partial transaction format.
        let refund = <Ar::Refund>::from_partial(partial_refund);
        // Check that the refund transaction is build on top of the cancel transaction.
        refund.is_build_on_top_of(&cancel)?;
        let refund_address = bob_parameters.destination_address.clone();
        refund.verify_template(refund_address)?;
        // Validate the fee strategy
        refund.as_partial().validate_fee(fee_strategy)?;

        Ok(ValidatedCoreTransactions {
            lock: lock.to_partial(),
            cancel: cancel.to_partial(),
            refund: refund.to_partial(),
            punish_lock,
        })
    }
}

/// Bob, a [`SwapRole`], starts with [`Arbitrating`] blockchain assets and exchange them for
/// [`Accordant`] blockchain assets.
#[derive(Debug, Clone)]
pub struct Bob<Addr, Ar, Ac> {
    /// The **arbitrating** blockchain to use during the swap
    pub arbitrating: Ar,
    /// The **accordant** blockchain to use during the swap
    pub accordant: Ac,
    /// An arbitrating address where, if unsuccessfully executed, the funds exchanged will be sent
    /// back to
    pub refund_address: Addr,
    /// The fee politic to apply during the swap fee calculation
    pub fee_politic: FeePriority,
}

impl<Addr, Ar, Ac> Encodable for Bob<Addr, Ar, Ac>
where
    Ar: Encodable,
    Ac: Encodable,
    Addr: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.fee_politic.consensus_encode(writer)?;
        len += self.arbitrating.consensus_encode(writer)?;
        len += self.accordant.consensus_encode(writer)?;
        Ok(len
            + self
                .refund_address
                .as_canonical_bytes()
                .consensus_encode(writer)?)
    }
}

impl<Addr, Ar, Ac> Decodable for Bob<Addr, Ar, Ac>
where
    Ar: Decodable,
    Ac: Decodable,
    Addr: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let fee_politic = FeePriority::consensus_decode(d)?;
        let arbitrating = Decodable::consensus_decode(d)?;
        let accordant = Decodable::consensus_decode(d)?;
        let refund_address = Addr::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?;
        Ok(Bob {
            arbitrating,
            accordant,
            refund_address,
            fee_politic,
        })
    }
}

impl<Addr, Ar, Ac> Bob<Addr, Ar, Ac> {
    /// Create a new [`Bob`] role with the local parameters.
    pub fn new(
        arbitrating: Ar,
        accordant: Ac,
        refund_address: Addr,
        fee_politic: FeePriority,
    ) -> Self {
        Self {
            arbitrating,
            accordant,
            refund_address,
            fee_politic,
        }
    }
}

impl<Addr, Ar, Ac> Bob<Addr, Ar, Ac>
where
    Addr: Clone,
{
    /// Generate Bob's parameters for the protocol execution based on the arbitrating and accordant
    /// seeds and the public offer agreed upon during the negotiation phase.
    ///
    /// # Safety
    ///
    /// All the data passed to the function are considered trusted and does not require extra
    /// validation.
    ///
    /// The parameters contain:
    ///
    ///  * The public keys used in the arbitrating and accordant blockchains
    ///  * The shared private keys (for reading opaque blockchains)
    ///  * The timelock parameters from the public offer
    ///  * The target arbitrating address used by Bob
    ///
    pub fn generate_parameters<Amt, Bmt, Pk, Qk, Rk, Sk, Ti, F, Pr, Kg>(
        &self,
        key_gen: &mut Kg,
        public_offer: &PublicOffer<Amt, Bmt, Ti, F>,
    ) -> Res<Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>>
    where
        Ar: DeriveKeys<PublicKey = Pk, PrivateKey = Rk>,
        Ac: DeriveKeys<PublicKey = Qk, PrivateKey = Sk>,
        Ti: Copy,
        F: Clone,
        Kg: KeyGenerator<Pk, Qk, Rk, Sk, Pr>,
    {
        let extra_arbitrating_keys: Res<TaggedExtraKeys<Pk>> = Ar::extra_public_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_pubkey(ArbitratingKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let arbitrating_shared_keys: Res<TaggedSharedKeys<Rk>> = Ar::extra_shared_private_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let extra_accordant_keys: Res<TaggedExtraKeys<Qk>> = Ac::extra_public_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_pubkey(AccordantKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let accordant_shared_keys: Res<TaggedSharedKeys<Sk>> = Ac::extra_shared_private_keys()
            .into_iter()
            .map(|tag| {
                let key = key_gen.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let (spend, adaptor, proof) = key_gen.generate_proof()?;

        Ok(Parameters {
            buy: key_gen.get_pubkey(ArbitratingKeyId::Buy)?,
            cancel: key_gen.get_pubkey(ArbitratingKeyId::Cancel)?,
            refund: key_gen.get_pubkey(ArbitratingKeyId::Refund)?,
            punish: None,
            adaptor,
            extra_arbitrating_keys: extra_arbitrating_keys?,
            arbitrating_shared_keys: arbitrating_shared_keys?,
            spend,
            extra_accordant_keys: extra_accordant_keys?,
            accordant_shared_keys: accordant_shared_keys?,
            proof: Some(proof),
            destination_address: self.refund_address.clone(),
            cancel_timelock: Some(public_offer.offer.cancel_timelock),
            punish_timelock: Some(public_offer.offer.punish_timelock),
            fee_strategy: Some(public_offer.offer.fee_strategy.clone()),
        })
    }

    /// Initialize the core arbitrating transactions composed of: [`Lockable`], [`Cancelable`], and
    /// [`Refundable`] transactions.
    ///
    /// # Safety
    ///
    /// [`AliceParameters`] bundle is created and validated with the protocol messages that commit
    /// and reveal the values present in the bundle.
    ///
    /// **This function assumes that the commit/reveal scheme has been validated and assumes that
    /// all cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// _Previously verified data_:
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///  * `funding_bundle`: Funding transaction bundle
    ///
    /// # Execution
    ///
    /// The parameters to create the three transactions are:
    ///  * Alice's public keys present in Alice's parameters bundle: [`AliceParameters`]
    ///  * Bob's public keys present in Bob's parameters bundle: [`BobParameters`]
    ///  * The [`Fundable`] transaction
    ///  * The [`FeeStrategy`] and the [`FeePriority`]
    ///
    /// The lock transaction is initialized by passing the [`DataLock`] structure, then the cancel
    /// transaction is initialized based on the lock transaction with the [`DataPunishableLock`]
    /// structure, then the punish is initialized based on the cancel transaction.
    ///
    /// # Transaction Fee
    ///
    /// The fee on each transactions are set according to the [`FeeStrategy`] specified in the
    /// public offer and the [`FeePriority`] in `self`.
    ///
    /// [`FeeStrategy`]: crate::blockchain::FeeStrategy
    ///
    pub fn core_arbitrating_transactions<Amt, Tx, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, Out>(
        &self,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        funding: impl Fundable<Tx, Out, Addr, Pk>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
    ) -> Res<CoreArbitratingTransactions<Px>>
    where
        Ar: Transactions<Addr = Addr, Amt = Amt, Tx = Tx, Out = Out, Ti = Ti, Pk = Pk, Px = Px>,
        Px: Fee<FeeUnit = F>,
        Out: Eq,
        Pk: Copy,
        Amt: Copy,
        Ti: Copy,
    {
        // Initialize the fundable transaction to build the lockable transaction on top of it.
        //
        // The fundable transaction `funding` contains all the logic to build on top of a
        // externally created transaction seen on-chain asyncronously by a syncer when broadcasted
        // by the external wallet.

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy;
        let bob_buy = bob_parameters.buy;
        let alice_cancel = alice_parameters.cancel;
        let bob_cancel = bob_parameters.cancel;

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let cancel_lock = DataLock {
            timelock: arb_params.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // The target amount is dictated from the public offer.
        let target_amount = arb_params.arbitrating_amount;

        // Initialize the lockable transaction based on the fundable structure. The lockable
        // transaction prepare the on-chain contract for a buy or a cancel. The amount of available
        // assets is defined as the target by the public offer.
        let lock = <Ar::Lock>::initialize(&funding, cancel_lock, target_amount)?;

        // Ensure that the transaction contains enough assets to pass the fee validation latter.
        let fee_strategy = &arb_params.fee_strategy;
        lock.as_partial().validate_fee(fee_strategy)?;

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        let alice_refund = alice_parameters.refund;
        let bob_refund = bob_parameters.refund;
        let alice_punish = alice_parameters.punish.expect("Alice has punish key");

        // Create the data structure that represents an on-chain punishable contract for the
        // arbitrating blockchain.
        let punish_lock = DataPunishableLock {
            timelock: arb_params.punish_timelock,
            success: DoubleKeys::new(alice_refund, bob_refund),
            failure: alice_punish,
        };

        // Initialize the cancel transaction for the lock transaction, removing the funds from the
        // buy and moving them into a punisable on-chain contract.
        let mut cancel = <Ar::Cancel>::initialize(&lock, cancel_lock, punish_lock)?;

        // Set the fees according to the strategy in the offer and the local politic.
        cancel
            .as_partial_mut()
            .set_fee(fee_strategy, self.fee_politic)?;

        // Initialize the refund transaction for the cancel transaction, moving the funds out of
        // the punishable lock to Bob's refund address.
        let mut refund = <Ar::Refund>::initialize(&cancel, self.refund_address.clone())?;

        // Set the fees according to the strategy in the offer and the local politic.
        refund
            .as_partial_mut()
            .set_fee(fee_strategy, self.fee_politic)?;

        Ok(CoreArbitratingTransactions {
            lock: lock.to_partial(),
            cancel: cancel.to_partial(),
            refund: refund.to_partial(),
        })
    }

    /// Co-sign the arbitrating [`Cancelable`] transaction.
    ///
    /// # Safety
    ///
    /// All the data passed to [`cosign_arbitrating_cancel`] are considered trusted.
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and does not require any extra
    /// validation.
    ///
    /// # Execution
    ///
    ///  * Parse the [`Cancelable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Retreive the cancel public key from the paramters
    ///  * Generate the witness data and sign it
    ///
    /// Returns the signature inside [`CosignedArbitratingCancel`] bundle.
    ///
    /// [`cosign_arbitrating_cancel`]: Bob::cosign_arbitrating_cancel
    ///
    pub fn cosign_arbitrating_cancel<S, Px, Si, Pk, Ms>(
        &self,
        wallet: &mut S,
        core: &CoreArbitratingTransactions<Px>,
    ) -> Res<Si>
    where
        S: Sign<Pk, Ms, Si>,
        Ar: Transactions<Addr = Addr, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone,
    {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_cancel = core.cancel.clone();

        // Initialize the cancel transaction based on the partial transaction format.
        let cancel = <Ar::Cancel>::from_partial(partial_cancel);

        // Generate the witness message to sign and sign with the cancel key.
        let msg = cancel.generate_witness_message(ScriptPath::Failure)?;
        wallet
            .sign(ArbitratingKeyId::Cancel, msg)
            .map_err(Into::into)
    }

    /// Validates the adaptor refund witness based on the parameters and the core arbitrating
    /// transactions.
    ///
    /// # Safety
    ///
    /// [`AliceParameters`] bundle is created and validated with the protocol messages that commit
    /// and reveal the values present in the bundle.
    ///
    /// **This function assumes that the commit/reveal scheme has been validated and assumes that
    /// all cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and does not require any extra
    /// validation.
    ///
    /// _Previously verified data_:
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// _Verified data_:
    ///  * `adaptor_refund`: The adaptor witness to verify
    ///
    /// # Execution
    ///
    ///  * Parse the [`Refundable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Verify the adaptor witness in [`SignedAdaptorRefund`] with the public keys from the
    ///  parameters bundles
    ///
    pub fn validate_adaptor_refund<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si, EncSig>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        refund_adaptor_sig: &EncSig,
    ) -> Res<()>
    where
        S: EncSign<Pk, Ms, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone,
    {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.clone();

        // Initialize the refund transaction based on the partial transaction format.
        let refund = <Ar::Refund>::from_partial(partial_refund);

        // Verify the adaptor refund witness
        let msg = refund.generate_witness_message(ScriptPath::Success)?;
        wallet.verify_encrypted_signature(
            &alice_parameters.refund,
            &bob_parameters.adaptor,
            msg,
            refund_adaptor_sig,
        )?;

        Ok(())
    }

    /// Creates the [`Buyable`] transaction and generate the adaptor witness
    ///
    /// # Safety
    ///
    /// This function **MUST NOT** be run if [`validate_adaptor_refund`] is not successful.
    ///
    /// This function **MUST NOT** be run if the accordant assets are not confirmed on-chain.
    ///
    /// [`AliceParameters`] bundle is created and validated with the protocol messages that commit
    /// and reveal the values present in the bundle.
    ///
    /// **This function assumes that the commit/reveal scheme has been validated and assumes that
    /// all cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and does not require any extra
    /// validation.
    ///
    /// _Previously verified data_:
    ///  * `alice_parameters`: Alice's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `ar_engine`: Bob's arbitrating seed
    ///  * `bob_parameters`: Bob's parameters bundle
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Lockable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Generate the [`DataLock`] structure from Alice and Bob parameters and the public offer
    ///  * Retrieve Alice's adaptor public key from [`AliceParameters`] bundle
    ///  * Retreive the buy public key from the paramters
    ///  * Generate the adaptor witness data and sign it
    ///
    /// Returns the partial transaction and the signature inside the [`SignedAdaptorBuy`] bundle.
    ///
    /// [`sign_adaptor_buy`]: Bob::sign_adaptor_buy
    /// [`validate_adaptor_refund`]: Bob::validate_adaptor_refund
    ///
    pub fn sign_adaptor_buy<Amt, Px, Pk, Qk, Rk, Sk, Ti, F, Pr, S, Ms, Si, EncSig>(
        &self,
        swap_id: SwapId,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        bob_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        core: &CoreArbitratingTransactions<Px>,
        arb_params: ArbitratingParameters<Amt, Ti, F>,
    ) -> Res<BuyProcedureSignature<Px, EncSig>>
    where
        S: EncSign<Pk, Ms, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Amt = Amt, Ti = Ti, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone + Fee<FeeUnit = F>,
        Pk: Copy,
        Ti: Copy,
    {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.clone();

        // Initialize the lock transaction based on the partial transaction format.
        let lock = <Ar::Lock>::from_partial(partial_lock);

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy;
        let bob_buy = bob_parameters.buy;
        let alice_cancel = alice_parameters.cancel;
        let bob_cancel = bob_parameters.cancel;

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let cancel_lock = DataLock {
            timelock: arb_params.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // Initialize the buy transaction based on the lock and the data lock. The buy transaction
        // consumes the success path of the lock and send the funds into Alice's destination
        // address.
        let mut buy = <Ar::Buy>::initialize(
            &lock,
            cancel_lock,
            alice_parameters.destination_address.clone(),
        )?;

        // Set the fees according to the strategy in the offer and the local politic.
        let fee_strategy = &arb_params.fee_strategy;
        buy.as_partial_mut()
            .set_fee(fee_strategy, self.fee_politic)?;

        // Generate the witness message to sign and adaptor sign with the buy key and the
        // counter-party adaptor.
        let adaptor = &alice_parameters.adaptor;
        let msg = buy.generate_witness_message(ScriptPath::Success)?;
        let sig = wallet.encrypt_sign(ArbitratingKeyId::Buy, adaptor, msg)?;

        Ok(BuyProcedureSignature {
            swap_id,
            buy: buy.to_partial(),
            buy_adaptor_sig: sig,
        })
    }

    /// Sign the arbitrating [`Lockable`] transaction and return the signature.
    ///
    /// # Safety
    ///
    /// This function **MUST NOT** be run if [`validate_adaptor_refund`] is not successful.
    ///
    /// All the data passed to [`sign_arbitrating_lock`] are considered trusted.
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and does not require any extra
    /// validation.
    ///
    /// # Execution
    ///
    ///  * Parse the [`Lockable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Retreive the funding public key from the paramters
    ///  * Generate the witness data and sign it
    ///
    /// Returns the signature inside a [`SignedArbitratingLock`] bundle.
    ///
    /// [`sign_arbitrating_lock`]: Bob::sign_arbitrating_lock
    /// [`validate_adaptor_refund`]: Bob::validate_adaptor_refund
    ///
    pub fn sign_arbitrating_lock<S, Px, Si, Pk, Ms>(
        &self,
        wallet: &mut S,
        core: &CoreArbitratingTransactions<Px>,
    ) -> Res<Si>
    where
        S: Sign<Pk, Ms, Si>,
        Ar: Transactions<Addr = Addr, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        Px: Clone,
    {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.clone();

        // Initialize the lock transaction based on the partial transaction format.
        let lock = <Ar::Lock>::from_partial(partial_lock);

        // Generate the witness message to sign and sign with the fund key.
        let msg = lock.generate_witness_message(ScriptPath::Success)?;
        wallet.sign(ArbitratingKeyId::Lock, msg).map_err(Into::into)
    }

    /// Sign the arbitrating [`Refundable`] transaction and adapt the counter-party adaptor witness
    /// with the private adaptor key.
    ///
    /// # Safety
    ///
    /// This function **MUST NOT** be run if [`validate_adaptor_refund`] is not successful.
    ///
    /// [`SignedAdaptorRefund`] bundle is created by Alice and must be verified to be a valid
    /// encrypted signature.
    ///
    /// **This function assumes that the adaptor signature has been validated and assumes that all
    /// cryptographic proof needed for securing the system have passed the validation.**
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and does not require any extra
    /// validation.
    ///
    /// # Execution
    ///
    ///  * Parse the [`Refundable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Retreive the refund public key from the paramters
    ///  * Generate the refund witness data
    ///  * Retreive the adaptor public key from the pamaters
    ///  * Adapt the signature
    ///
    /// Returns the signatures inside a [`SignedArbitratingLock`] bundle.
    ///
    /// [`validate_adaptor_refund`]: Bob::validate_adaptor_refund
    ///
    pub fn fully_sign_refund<S, Px, Si, Pk, Ms, EncSig>(
        &self,
        wallet: &mut S,
        core: &CoreArbitratingTransactions<Px>,
        signed_adaptor_refund: &EncSig,
    ) -> Res<TxSignatures<Si>>
    where
        S: Sign<Pk, Ms, Si> + EncSign<Pk, Ms, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Ms = Ms, Pk = Pk, Si = Si, Px = Px>,
        EncSig: Clone,
        Px: Clone,
    {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.clone();

        // Initialize the refund transaction based on the partial transaction format.
        let refund = <Ar::Refund>::from_partial(partial_refund);

        // Generate the witness message to sign and sign with the refund key.
        let msg = refund.generate_witness_message(ScriptPath::Success)?;
        let sig = wallet.sign(ArbitratingKeyId::Refund, msg)?;

        let adapted_sig =
            wallet.decrypt_signature(AccordantKeyId::Spend, signed_adaptor_refund.clone())?;

        Ok(TxSignatures { sig, adapted_sig })
    }

    pub fn recover_accordant_key<S, Tx, Px, Si, Pk, Qk, Rk, Sk, Ti, F, Pr, EncSig>(
        &self,
        wallet: &mut S,
        alice_parameters: &Parameters<Pk, Qk, Rk, Sk, Addr, Ti, F, Pr>,
        buy_adaptor_sig: EncSig,
        buy_tx: Tx,
    ) -> Rk
    where
        S: RecoverSecret<Pk, Rk, Si, EncSig>,
        Ar: Transactions<Addr = Addr, Tx = Tx, Px = Px, Pk = Pk, Si = Si>,
    {
        let encryption_key = &alice_parameters.adaptor;
        let signature = <Ar::Buy>::extract_witness(buy_tx);
        wallet.recover_secret_key(buy_adaptor_sig, encryption_key, signature)
    }
}
