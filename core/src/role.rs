//! Roles during negotiation and swap phases, blockchain roles, and network definitions.

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

use crate::blockchain::{Address, Asset, Fee, FeePolitic, Onchain, Timelock, Transactions};
use crate::bundle::{
    AliceParameters, BobParameters, CoreArbitratingTransactions, CosignedArbitratingCancel,
    FullySignedBuy, FullySignedRefund, FundingTransaction, SignedAdaptorBuy, SignedAdaptorRefund,
    SignedArbitratingLock, SignedArbitratingPunish,
};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{
    self, AccordantKey, ArbitratingKey, Commitment, DleqProof, FromSeed, Keys, SharedPrivateKeys,
    SignatureType, Signatures,
};
use crate::datum;
use crate::negotiation::PublicOffer;
use crate::script::{DataLock, DataPunishableLock, DoubleKeys};
use crate::swap::Swap;
use crate::transaction::{
    AdaptorSignable, Cancelable, Forkable, Fundable, Lockable, Refundable, Transaction, TxId,
};
use crate::Error;

/// Defines the possible roles during the negotiation phase. Any negotiation role can transition
/// into any swap role when negotiation is done.
pub enum NegotiationRole {
    /// The maker role create the public offer during the negotiation phase and waits for incoming
    /// connections.
    Maker,
    /// The taker role parses public offers and choose to connect to a maker node to start
    /// swapping.
    Taker,
}

impl NegotiationRole {
    /// Return the other role possible in the negotiation phase.
    pub fn other(&self) -> Self {
        match self {
            Self::Maker => Self::Taker,
            Self::Taker => Self::Maker,
        }
    }
}

/// A maker is one that creates and share a public offer and start his daemon in listening mode so
/// one taker can connect and start interacting with him.
pub struct Maker;

/// A taker parses offers and, if interested, connects to the peer registred in the offer.
pub struct Taker;

/// Defines the possible roles during the swap phase. When negotitation is done negotitation role
/// will transition into swap role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapRole {
    /// Alice, the swap role, is the role starting with accordant blockchain assets and exchange
    /// them for arbitrating blockchain assets.
    Alice,
    /// Bob, the swap role, is the role starting with arbitrating blockchain assets and exchange
    /// them for accordant blockchain assets.
    Bob,
}

impl SwapRole {
    /// Return the other role possible in the swap phase.
    pub fn other(&self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }
}

impl Encodable for SwapRole {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            SwapRole::Alice => 0x01u8.consensus_encode(writer),
            SwapRole::Bob => 0x02u8.consensus_encode(writer),
        }
    }
}

impl Decodable for SwapRole {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(SwapRole::Alice),
            0x02u8 => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl FromStr for SwapRole {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Alice" => Ok(SwapRole::Alice),
            "Bob" => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::ParseFailed("Bob or Alice valid")),
        }
    }
}

/// Alice, the swap role, is the role starting with accordant blockchain assets and exchange them
/// for arbitrating blockchain assets.
pub struct Alice<Ctx: Swap> {
    /// An arbitrating address where, if successfully executed, the funds exchanged will be sent to
    pub destination_address: <Ctx::Ar as Address>::Address,
    /// The fee politic to apply during the swap fee calculation
    pub fee_politic: FeePolitic,
}

impl<Ctx> Alice<Ctx>
where
    Ctx: Swap,
{
    pub fn new(
        destination_address: <Ctx::Ar as Address>::Address,
        fee_politic: FeePolitic,
    ) -> Self {
        Self {
            destination_address,
            fee_politic,
        }
    }

    pub fn generate_parameters(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        public_offer: &PublicOffer<Ctx>,
    ) -> AliceParameters<Ctx> {
        let (spend, adaptor, proof) = Ctx::Proof::generate(ac_seed);
        AliceParameters {
            buy: datum::Key::new_alice_buy(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Buy,
            )),
            cancel: datum::Key::new_alice_cancel(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Cancel,
            )),
            refund: datum::Key::new_alice_refund(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Refund,
            )),
            punish: datum::Key::new_alice_punish(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Punish,
            )),
            adaptor: datum::Key::new_alice_adaptor(adaptor),
            destination_address: datum::Parameter::new_destination_address(
                self.destination_address.clone(),
            ),
            view: datum::Key::new_alice_private_view(
                <Ctx::Ac as SharedPrivateKeys<Acc>>::get_shared_privkey(
                    ac_seed,
                    crypto::SharedPrivateKey::View,
                ),
            ),
            spend: datum::Key::new_alice_spend(spend),
            proof: datum::Proof::new_cross_group_dleq(proof),
            cancel_timelock: Some(datum::Parameter::new_cancel_timelock(
                public_offer.offer.cancel_timelock,
            )),
            punish_timelock: Some(datum::Parameter::new_punish_timelock(
                public_offer.offer.punish_timelock,
            )),
            fee_strategy: Some(datum::Parameter::new_fee_strategy(
                public_offer.offer.fee_strategy.clone(),
            )),
        }
    }

    pub fn sign_adaptor_refund(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        bob_parameters: &BobParameters<Ctx>,
        core_arbitrating: &CoreArbitratingTransactions<Ctx::Ar>,
    ) -> Result<SignedAdaptorRefund<Ctx::Ar>, Error> {
        let partial_refund = core_arbitrating
            .refund
            .tx()
            .try_into_partial_transaction()?;
        // FIXME: the mutation is on a cloned value and is dropped at the end of the scope
        let mut refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(&partial_refund);

        // TODO verify transaction before signing

        let adaptor = bob_parameters.adaptor.key().try_into_arbitrating_pubkey()?;
        let privkey =
            <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, crypto::ArbitratingKey::Refund);
        let sig = refund.generate_adaptor_witness(&privkey, &adaptor).unwrap(); // FIXME unwrap

        Ok(SignedAdaptorRefund {
            refund_adaptor_sig: datum::Signature::new(
                TxId::Refund,
                SwapRole::Alice,
                SignatureType::Adaptor(sig),
            ),
        })
    }

    pub fn cosign_arbitrating_cancel(&self) -> CosignedArbitratingCancel<Ctx::Ar> {
        todo!()
    }

    pub fn fully_sign_buy(&self) -> FullySignedBuy<Ctx::Ar> {
        todo!()
    }

    pub fn sign_arbitrating_punish(&self) -> SignedArbitratingPunish<Ctx::Ar> {
        todo!()
    }
}

/// Bob, the swap role, is the role starting with arbitrating blockchain assets and exchange them
/// for accordant blockchain assets.
pub struct Bob<Ctx: Swap> {
    /// An arbitrating address where, if unsuccessfully executed, the funds exchanged will be sent
    /// back to
    pub refund_address: <Ctx::Ar as Address>::Address,
    /// The fee politic to apply during the swap fee calculation
    pub fee_politic: FeePolitic,
}

impl<Ctx: Swap> Bob<Ctx> {
    pub fn new(refund_address: <Ctx::Ar as Address>::Address, fee_politic: FeePolitic) -> Self {
        Self {
            refund_address,
            fee_politic,
        }
    }

    pub fn generate_parameters(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        public_offer: &PublicOffer<Ctx>,
    ) -> BobParameters<Ctx> {
        let (spend, adaptor, proof) = Ctx::Proof::generate(ac_seed);
        BobParameters {
            buy: datum::Key::new_bob_buy(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Buy,
            )),
            cancel: datum::Key::new_bob_cancel(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Cancel,
            )),
            refund: datum::Key::new_bob_refund(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                crypto::ArbitratingKey::Refund,
            )),
            adaptor: datum::Key::new_bob_adaptor(adaptor),
            refund_address: datum::Parameter::new_destination_address(self.refund_address.clone()),
            view: datum::Key::new_bob_private_view(
                <Ctx::Ac as SharedPrivateKeys<Acc>>::get_shared_privkey(
                    ac_seed,
                    crypto::SharedPrivateKey::View,
                ),
            ),
            spend: datum::Key::new_bob_spend(spend),
            proof: datum::Proof::new_cross_group_dleq(proof),
            cancel_timelock: Some(datum::Parameter::new_cancel_timelock(
                public_offer.offer.cancel_timelock,
            )),
            punish_timelock: Some(datum::Parameter::new_punish_timelock(
                public_offer.offer.punish_timelock,
            )),
            fee_strategy: Some(datum::Parameter::new_fee_strategy(
                public_offer.offer.fee_strategy.clone(),
            )),
        }
    }

    // FIXME: take bob parameters instead of requerying the public keys
    pub fn core_arbitrating_transactions(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        alice_parameters: &AliceParameters<Ctx>,
        funding_bundle: &FundingTransaction<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<CoreArbitratingTransactions<Ctx::Ar>, Error> {
        // Initialize the fundable transaction to build the lockable transaction on top of it.
        //
        // The fundable transaction contains all the logic to build on top of a externally created
        // transaction seen on-chain asyncronously by a syncer when broadcasted by the external
        // wallet.
        let funding = <<Ctx::Ar as Transactions>::Funding as Fundable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
            <Ctx::Ar as Transactions>::Error,
        >>::raw(funding_bundle.funding.tx().try_into_transaction()?)
        .unwrap(); // FIXME unwrap

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        //
        // Alice's keys are shared over the network by Alice and end-up in Alice parameters bundle,
        // Bob's keys are generated by Bob through the seed.
        let alice_buy = alice_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let bob_buy = <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Buy);
        let alice_cancel = alice_parameters
            .cancel
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_cancel =
            <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Cancel);

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let cancel_lock = DataLock {
            timelock: public_offer.offer.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // Initialize the lockable transaction based on the fundable structure. The lockable
        // transaction prepare the on-chain contract for a buy or a cancel.
        let lock = <<Ctx::Ar as Transactions>::Lock as Lockable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
            <Ctx::Ar as Transactions>::Error,
        >>::initialize(
            &funding,
            cancel_lock.clone(),
            &public_offer.offer.fee_strategy,
            self.fee_politic,
        )
        .unwrap(); // FIXME unwrap

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        //
        // Alice's keys are shared over the network by Alice and end-up in Alice parameters bundle,
        // Bob's keys are generated by Bob through the seed.
        let alice_refund = alice_parameters
            .refund
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_refund =
            <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Refund);
        let alice_punish = alice_parameters
            .punish
            .key()
            .try_into_arbitrating_pubkey()?;

        // Create the data structure that represents an on-chain punishable contract for the
        // arbitrating blockchain.
        let punish_lock = DataPunishableLock {
            timelock: public_offer.offer.punish_timelock,
            success: DoubleKeys::new(alice_refund, bob_refund),
            failure: alice_punish,
        };

        // Initialize the cancel transaction for the lock transaction, removing the funds from the
        // buy and moving them into a punisable on-chain contract.
        let cancel = <<Ctx::Ar as Transactions>::Cancel as Cancelable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
            <Ctx::Ar as Transactions>::Error,
        >>::initialize(
            &lock,
            cancel_lock,
            punish_lock.clone(),
            &public_offer.offer.fee_strategy,
            self.fee_politic,
        )
        .unwrap(); // FIXME unwrap

        // Initialize the refund transaction for the cancel transaction, moving the funds out of
        // the punishable lock to Bob's refund address.
        let refund = <<Ctx::Ar as Transactions>::Refund as Refundable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
            <Ctx::Ar as Transactions>::Error,
        >>::initialize(
            &cancel,
            punish_lock,
            self.refund_address.clone(),
            &public_offer.offer.fee_strategy,
            self.fee_politic,
        )
        .unwrap(); // FIXME unwrap

        Ok(CoreArbitratingTransactions {
            lock: datum::Transaction::new_lock(lock.to_partial()),
            cancel: datum::Transaction::new_cancel(cancel.to_partial()),
            refund: datum::Transaction::new_refund(refund.to_partial()),
        })
    }

    pub fn cosign_arbitrating_cancel(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        core_arbitrating: &CoreArbitratingTransactions<Ctx::Ar>,
    ) -> Result<CosignedArbitratingCancel<Ctx::Ar>, Error> {
        let partial_cancel = core_arbitrating
            .cancel
            .tx()
            .try_into_partial_transaction()?;
        let mut cancel = <<Ctx::Ar as Transactions>::Cancel>::from_partial(&partial_cancel);

        let privkey =
            <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, crypto::ArbitratingKey::Cancel);
        let sig = cancel.generate_failure_witness(&privkey).unwrap(); // FIXME unwrap

        Ok(CosignedArbitratingCancel {
            cancel_sig: datum::Signature::new(
                TxId::Cancel,
                SwapRole::Bob,
                SignatureType::Regular(sig),
            ),
        })
    }

    pub fn sign_adaptor_buy(&self) -> SignedAdaptorBuy<Ctx::Ar> {
        todo!()
    }

    pub fn sign_arbitrating_lock(&self) -> SignedArbitratingLock<Ctx::Ar> {
        todo!()
    }

    pub fn fully_sign_refund(&self) -> FullySignedRefund<Ctx::Ar> {
        todo!()
    }
}

/// An arbitrating is the blockchain which will act as the decision engine, the arbitrating
/// blockchain will use transaction to transfer the funds on both blockchains.
pub trait Arbitrating:
    Asset
    + Address
    + Commitment
    + Fee
    + FromSeed<Arb>
    + Keys
    + Onchain
    + Signatures
    + Timelock
    + Transactions
    + Clone
    + Eq
{
}

/// An accordant is the blockchain which does not need transaction inside the protocol nor
/// timelocks, it is the blockchain with the less requirements for an atomic swap.
pub trait Accordant:
    Asset + Keys + Commitment + SharedPrivateKeys<Acc> + FromSeed<Acc> + Clone + Eq
{
}

/// Defines the role of a blockchain. Farcaster uses two blockchain roles (1) [Arbitrating] and (2)
/// [Accordant].
pub trait Blockchain {
    /// The list of keys available for a blockchain role.
    type KeyList;
}

/// Concrete type for the arbitrating blockchain role used when a trait implementation is needed
/// per blockchain role, such as [FromSeed].
pub struct Arb;

impl Blockchain for Arb {
    type KeyList = ArbitratingKey;
}

/// Concrete type for the accordant blockchain role used when a trait implementation is needed per
/// blockchain role, such as [FromSeed].
pub struct Acc;

impl Blockchain for Acc {
    type KeyList = AccordantKey;
}
