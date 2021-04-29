//! Roles during negotiation and swap phases, blockchain roles, and network definitions.

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

use crate::blockchain::{Address, Asset, Fee, FeePolitic, Onchain, Timelock, Transactions};
use crate::bundle::{
    AliceParameters, BobParameters, CoreArbitratingTransactions, CosignedArbitratingCancel,
    FullySignedBuy, FullySignedPunish, FullySignedRefund, FundingTransaction, SignedAdaptorBuy,
    SignedAdaptorRefund, SignedArbitratingLock,
};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{
    AccordantKey, ArbitratingKey, Commitment, DleqProof, FromSeed, Keys, SharedPrivateKey,
    SharedPrivateKeys, SignatureType, Signatures,
};
use crate::datum::{self, Key, Parameter, Proof, Signature};
use crate::negotiation::PublicOffer;
use crate::script::{DataLock, DataPunishableLock, DoubleKeys};
use crate::swap::Swap;
use crate::transaction::{
    AdaptorSignable, Buyable, Cancelable, Chainable, Forkable, Fundable, Lockable, Punishable,
    Refundable, Signable, Transaction, TxId,
};
use crate::Error;

/// Defines the possible roles during the negotiation phase. Any negotiation role can transition
/// into any swap role when negotiation is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl FromStr for NegotiationRole {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Maker" | "maker" => Ok(NegotiationRole::Maker),
            "Taker" | "taker" => Ok(NegotiationRole::Taker),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl ToString for NegotiationRole {
    fn to_string(&self) -> String {
        match self {
            NegotiationRole::Maker => "Maker".to_string(),
            NegotiationRole::Taker => "Taker".to_string(),
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
            "Alice" | "alice" => Ok(SwapRole::Alice),
            "Bob" | "bob" => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl ToString for SwapRole {
    fn to_string(&self) -> String {
        match self {
            Self::Alice => "Alice".to_string(),
            Self::Bob => "Bob".to_string(),
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

struct ValidatedCoreTransactions<Ctx: Swap> {
    lock: <Ctx::Ar as Transactions>::Lock,
    cancel: <Ctx::Ar as Transactions>::Cancel,
    refund: <Ctx::Ar as Transactions>::Refund,
    data_lock: DataLock<Ctx::Ar>,
    punish_lock: DataPunishableLock<Ctx::Ar>,
}

impl<Ctx> Alice<Ctx>
where
    Ctx: Swap,
{
    /// Create a new role for Alice with the local parameters.
    pub fn new(
        destination_address: <Ctx::Ar as Address>::Address,
        fee_politic: FeePolitic,
    ) -> Self {
        Self {
            destination_address,
            fee_politic,
        }
    }

    /// Generate Alice's parameters for the protocol execution based on the arbitrating and
    /// accordant seeds and the public offer agreed upon during the negotiation phase.
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
    ///  * The target arbitrating address used by Alice
    ///
    pub fn generate_parameters(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<AliceParameters<Ctx>, Error> {
        let (spend, adaptor, proof) = Ctx::Proof::generate(ac_seed)?;
        Ok(AliceParameters {
            buy: Key::new_alice_buy(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Buy,
            )?),
            cancel: Key::new_alice_cancel(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Cancel,
            )?),
            refund: Key::new_alice_refund(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Refund,
            )?),
            punish: Key::new_alice_punish(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Punish,
            )?),
            adaptor: Key::new_alice_adaptor(adaptor),
            destination_address: Parameter::new_destination_address(
                self.destination_address.clone(),
            ),
            view: Key::new_alice_private_view(
                <Ctx::Ac as SharedPrivateKeys<Acc>>::get_shared_privkey(
                    ac_seed,
                    SharedPrivateKey::View,
                )?,
            ),
            spend: Key::new_alice_spend(spend),
            proof: Proof::new_cross_group_dleq(proof),
            cancel_timelock: Some(Parameter::new_cancel_timelock(
                public_offer.offer.cancel_timelock,
            )),
            punish_timelock: Some(Parameter::new_punish_timelock(
                public_offer.offer.punish_timelock,
            )),
            fee_strategy: Some(Parameter::new_fee_strategy(
                public_offer.offer.fee_strategy.clone(),
            )),
        })
    }

    /// Generates the adaptor witness with [`generate_adaptor_witness`] on the [`Refundable`]
    /// transaction.
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
    ///  * `ar_seed`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///  * `public_offer`: The public offer
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
    ///  * Derive the refund private key from the arbitrating seed: `ar_seed`
    ///  * Generate the adaptor witness data for success path with [`generate_adaptor_witness`]
    ///
    /// Returns the adaptor signature inside the [`SignedAdaptorRefund`] bundle.
    ///
    /// [`generate_adaptor_witness`]: AdaptorSignable::generate_adaptor_witness
    ///
    pub fn sign_adaptor_refund(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<SignedAdaptorRefund<Ctx::Ar>, Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { refund, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        // Extracts the adaptor public key from counter-party parameters.
        let adaptor = bob_parameters.adaptor.key().try_into_arbitrating_pubkey()?;

        // Derive the private refund key and generate the adaptor witness for the counter-party
        // adaptor.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Refund)?;
        let sig = refund.generate_adaptor_witness(&privkey, &adaptor)?;

        Ok(SignedAdaptorRefund {
            refund_adaptor_sig: Signature::new(
                TxId::Refund,
                SwapRole::Alice,
                SignatureType::Adaptor(sig),
            ),
        })
    }

    /// Generates the witness with [`generate_failure_witness`] on the [`Cancelable`] transaction.
    ///
    /// # Safety
    ///
    /// [`CoreArbitratingTransactions`] bundle is created by Bob and requries extra validation.
    ///
    /// _Previously verified data_:
    ///  * `bob_parameters`: Bob's parameters bundle
    ///
    /// _Trusted data_:
    ///  * `ar_seed`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///  * `public_offer`: The public offer
    ///
    /// _Verified data_:
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Cancelable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Validate the [`Lockable`], [`Cancelable`], [`Refundable`] partial transactions in
    ///  [`CoreArbitratingTransactions`]
    ///  * Derive the cancel private key from the arbitrating seed: `ar_seed`
    ///  * Generate the adaptor witness data for success path with [`generate_failure_witness`]
    ///
    /// Returns the witness inside the [`CosignedArbitratingCancel`] bundle.
    ///
    /// [`generate_failure_witness`]: Forkable::generate_failure_witness
    ///
    pub fn cosign_arbitrating_cancel(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<CosignedArbitratingCancel<Ctx::Ar>, Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { cancel, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        // Derive the private cancel key and generate the cancel witness.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Cancel)?;
        let sig = cancel.generate_failure_witness(&privkey)?;

        Ok(CosignedArbitratingCancel {
            cancel_sig: Signature::new(TxId::Cancel, SwapRole::Alice, SignatureType::Regular(sig)),
        })
    }

    /// Validates the adaptor buy witness with [`verify_adaptor_witness`] based on the parameters
    /// and the buy arbitrating transactions.
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
    ///  * `public_offer`: The public offer
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
    /// [`verify_adaptor_witness`]: AdaptorSignable::verify_adaptor_witness
    ///
    pub fn validate_adaptor_buy(
        &self,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
        adaptor_buy: &SignedAdaptorBuy<Ctx::Ar>,
    ) -> Result<(), Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions {
            lock, data_lock, ..
        } = self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        let fee_strategy = &public_offer.offer.fee_strategy;

        // Extract the partial transaction from the adaptor buy bundle, this operation should not
        // error if the bundle is well formed.
        let partial_buy = adaptor_buy.buy.tx().try_into_partial_transaction()?;

        // Initialize the buy transaction based on the extracted partial transaction format.
        let buy = <<Ctx::Ar as Transactions>::Buy>::from_partial(partial_buy);

        buy.is_build_on_top_of(&lock)?;
        buy.verify_template(data_lock, self.destination_address.clone())?;
        <Ctx::Ar as Fee>::validate_fee(buy.partial(), &fee_strategy)?;

        // Verify the adaptor refund witness
        buy.verify_adaptor_witness(
            &bob_parameters.buy.key().try_into_arbitrating_pubkey()?,
            &alice_parameters
                .adaptor
                .key()
                .try_into_arbitrating_pubkey()?,
            adaptor_buy.buy_adaptor_sig.signature().try_into_adaptor()?,
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
    ///  * `ar_seed`, `ac_seed`: Bob's arbitrating and accordant seeds
    ///  * `alice_parameters`: Alice's parameters bundle
    ///  * `public_offer`: The public offer
    ///
    /// _Verified data_:
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Buyable`] partial transaction in [`SignedAdaptorBuy`]
    ///  * Derive the buy private key from the arbitrating seed: `ar_seed`
    ///  * Generate the buy witness data with [`generate_witness`]
    ///  * Derive the adaptor private key from the accordant seed: `ac_seed`
    ///  * Adaprt the signature with [`adapt`]
    ///
    /// Returns the signatures inside a [`FullySignedBuy`] bundle.
    ///
    /// [`adapt`]: Signatures::adapt
    /// [`generate_witness`]: Signable::generate_witness
    /// [`validate_adaptor_buy`]: Alice::validate_adaptor_buy
    ///
    pub fn fully_sign_buy(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
        adaptor_buy: &SignedAdaptorBuy<Ctx::Ar>,
    ) -> Result<FullySignedBuy<Ctx::Ar>, Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions {
            lock, data_lock, ..
        } = self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        let fee_strategy = &public_offer.offer.fee_strategy;

        // Extract the partial transaction from the adaptor buy bundle, this operation should not
        // error if the bundle is well formed.
        let partial_buy = adaptor_buy.buy.tx().try_into_partial_transaction()?;

        // Initialize the buy transaction based on the extracted partial transaction format.
        let buy = <<Ctx::Ar as Transactions>::Buy>::from_partial(partial_buy);

        buy.is_build_on_top_of(&lock)?;
        buy.verify_template(data_lock, self.destination_address.clone())?;
        <Ctx::Ar as Fee>::validate_fee(buy.partial(), &fee_strategy)?;

        // Derive the buy private key and generate the witness for this key.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Buy)?;
        let sig = buy.generate_witness(&privkey)?;

        // Derive the adaptor private key and adaptor the counter-party witness with the private
        // key.
        let priv_adaptor = <Ctx::Proof as DleqProof<Ctx::Ar, Ctx::Ac>>::project_over(ac_seed)?;
        let adapted_sig = <Ctx::Ar as Signatures>::adapt(
            &priv_adaptor,
            adaptor_buy.buy_adaptor_sig.signature().try_into_adaptor()?,
        )?;

        Ok(FullySignedBuy {
            buy_sig: Signature::new(TxId::Buy, SwapRole::Alice, SignatureType::Regular(sig)),
            buy_adapted_sig: Signature::new(
                TxId::Buy,
                SwapRole::Bob,
                SignatureType::Adapted(adapted_sig),
            ),
        })
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
    ///  * `ar_seed`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///  * `public_offer`: The public offer
    ///
    /// # Execution
    ///
    ///  * Parse the [`Buyable`] partial transaction in [`SignedAdaptorBuy`]
    ///  * Derive the buy private key from the arbitrating seed: `ar_seed`
    ///  * Generate the buy witness data with [`generate_witness`]
    ///  * Derive the adaptor private key from the accordant seed: `ac_seed`
    ///  * Adaprt the signature with [`adapt`]
    ///
    /// Returns the signatures inside a [`FullySignedBuy`] bundle.
    ///
    /// [`adapt`]: Signatures::adapt
    /// [`generate_witness`]: Signable::generate_witness
    /// [`validate_adaptor_buy`]: Alice::validate_adaptor_buy
    ///
    pub fn fully_sign_punish(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<FullySignedPunish<Ctx::Ar>, Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions {
            cancel,
            punish_lock,
            ..
        } = self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        let fee_strategy = &public_offer.offer.fee_strategy;

        // Initialize the punish transaction based on the cancel transaction.
        let mut punish =
            <<Ctx::Ar as Transactions>::Punish as Punishable<
                Ctx::Ar,
                <Ctx::Ar as Transactions>::Metadata,
            >>::initialize(&cancel, punish_lock, self.destination_address.clone())?;

        // Set the fees according to the strategy in the offer and the local politic.
        <Ctx::Ar as Fee>::set_fee(punish.partial_mut(), &fee_strategy, self.fee_politic)?;

        // Derive the punish private key and generate the witness data for the punish transaction.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Punish)?;
        let punish_sig = punish.generate_failure_witness(&privkey)?;

        Ok(FullySignedPunish {
            punish: datum::Transaction::new_punish(punish.to_partial()),
            punish_sig: Signature::new(
                TxId::Punish,
                SwapRole::Alice,
                SignatureType::Regular(punish_sig),
            ),
        })
    }

    pub fn recover_accordant_assets(&self) -> Result<(), Error> {
        todo!()
    }

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
    //
    fn validate_core(
        &self,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<ValidatedCoreTransactions<Ctx>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.tx().try_into_partial_transaction()?;

        // Initialize the lock transaction based on the extracted partial transaction format.
        let lock = <<Ctx::Ar as Transactions>::Lock>::from_partial(partial_lock);

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let bob_buy = bob_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let alice_cancel = alice_parameters
            .cancel
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_cancel = bob_parameters.cancel.key().try_into_arbitrating_pubkey()?;

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let data_lock = DataLock {
            timelock: public_offer.offer.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // Verify the lock transaction template.
        lock.verify_template(data_lock.clone())?;
        // The target amount is dictated from the public offer.
        let target_amount = public_offer.offer.arbitrating_amount;
        // Verify the target amount
        lock.verify_target_amount(target_amount)?;
        // Validate that the transaction follows the strategy.
        let fee_strategy = &public_offer.offer.fee_strategy;
        <Ctx::Ar as Fee>::validate_fee(lock.partial(), &fee_strategy)?;

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        let alice_refund = alice_parameters
            .refund
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_refund = bob_parameters.refund.key().try_into_arbitrating_pubkey()?;
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

        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_cancel = core.lock.tx().try_into_partial_transaction()?;

        // Initialize the lock transaction based on the extracted partial transaction format.
        let cancel = <<Ctx::Ar as Transactions>::Cancel>::from_partial(partial_cancel);
        // Check that the cancel transaction is build on top of the lock.
        cancel.is_build_on_top_of(&lock)?;
        cancel.verify_template(data_lock.clone(), punish_lock.clone())?;
        // Validate the fee strategy
        <Ctx::Ar as Fee>::validate_fee(cancel.partial(), &fee_strategy)?;

        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.tx().try_into_partial_transaction()?;

        // Initialize the refund transaction based on the extracted partial transaction format.
        let refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(partial_refund);
        // Check that the refund transaction is build on top of the cancel transaction.
        refund.is_build_on_top_of(&cancel)?;
        let refund_address = bob_parameters.refund_address.param().try_into_address()?;
        refund.verify_template(punish_lock.clone(), refund_address)?;
        // Validate the fee strategy
        <Ctx::Ar as Fee>::validate_fee(refund.partial(), &fee_strategy)?;

        Ok(ValidatedCoreTransactions {
            lock,
            cancel,
            refund,
            data_lock,
            punish_lock,
        })
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
    /// Create a new [`Bob`] role with the local parameters.
    pub fn new(refund_address: <Ctx::Ar as Address>::Address, fee_politic: FeePolitic) -> Self {
        Self {
            refund_address,
            fee_politic,
        }
    }

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
    pub fn generate_parameters(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<BobParameters<Ctx>, Error> {
        let (spend, adaptor, proof) = Ctx::Proof::generate(ac_seed)?;
        Ok(BobParameters {
            buy: Key::new_bob_buy(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Buy,
            )?),
            cancel: Key::new_bob_cancel(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Cancel,
            )?),
            refund: Key::new_bob_refund(<Ctx::Ar as FromSeed<Arb>>::get_pubkey(
                ar_seed,
                ArbitratingKey::Refund,
            )?),
            adaptor: Key::new_bob_adaptor(adaptor),
            refund_address: Parameter::new_destination_address(self.refund_address.clone()),
            view: Key::new_bob_private_view(
                <Ctx::Ac as SharedPrivateKeys<Acc>>::get_shared_privkey(
                    ac_seed,
                    SharedPrivateKey::View,
                )?,
            ),
            spend: Key::new_bob_spend(spend),
            proof: Proof::new_cross_group_dleq(proof),
            cancel_timelock: Some(Parameter::new_cancel_timelock(
                public_offer.offer.cancel_timelock,
            )),
            punish_timelock: Some(Parameter::new_punish_timelock(
                public_offer.offer.punish_timelock,
            )),
            fee_strategy: Some(Parameter::new_fee_strategy(
                public_offer.offer.fee_strategy.clone(),
            )),
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
    ///  * `public_offer`: Public offer
    ///
    /// # Execution
    ///
    /// The parameters to create the three transactions are:
    ///  * Alice's public keys present in Alice's parameters bundle: [`AliceParameters`]
    ///  * Bob's public keys present in Bob's parameters bundle: [`BobParameters`]
    ///  * The [`Fundable`] transaction in [`FundingTransaction`] bundle
    ///  * The [`FeeStrategy`] and the [`FeePolitic`]
    ///
    /// The lock transaction is initialized by passing the [`DataLock`] structure, then the cancel
    /// transaction is initialized based on the lock transaction with the [`DataPunishableLock`]
    /// structure, then the punish is initialized based on the cancel transaction.
    ///
    /// # Transaction Fee
    ///
    /// The fee on each transactions are set according to the [`FeeStrategy`] specified in the
    /// public offer and the [`FeePolitic`] in `self`.
    ///
    /// [`FeeStrategy`]: crate::blockchain::FeeStrategy
    ///
    pub fn core_arbitrating_transactions(
        &self,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
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
        >>::raw(funding_bundle.funding.tx().try_into_transaction()?)?;

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let bob_buy = bob_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let alice_cancel = alice_parameters
            .cancel
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_cancel = bob_parameters.cancel.key().try_into_arbitrating_pubkey()?;

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let cancel_lock = DataLock {
            timelock: public_offer.offer.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // The target amount is dictated from the public offer.
        let target_amount = public_offer.offer.arbitrating_amount;

        // Initialize the lockable transaction based on the fundable structure. The lockable
        // transaction prepare the on-chain contract for a buy or a cancel. The amount of available
        // assets is defined as the target by the public offer.
        let lock = <<Ctx::Ar as Transactions>::Lock as Lockable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
        >>::initialize(&funding, cancel_lock.clone(), target_amount)?;

        // Ensure that the transaction contains enough assets to pass the fee validation latter.
        let fee_strategy = &public_offer.offer.fee_strategy;
        <Ctx::Ar as Fee>::validate_fee(lock.partial(), &fee_strategy)?;

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        let alice_refund = alice_parameters
            .refund
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_refund = bob_parameters.refund.key().try_into_arbitrating_pubkey()?;
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
        let mut cancel = <<Ctx::Ar as Transactions>::Cancel as Cancelable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
        >>::initialize(&lock, cancel_lock, punish_lock.clone())?;

        // Set the fees according to the strategy in the offer and the local politic.
        <Ctx::Ar as Fee>::set_fee(cancel.partial_mut(), &fee_strategy, self.fee_politic)?;

        // Initialize the refund transaction for the cancel transaction, moving the funds out of
        // the punishable lock to Bob's refund address.
        let mut refund = <<Ctx::Ar as Transactions>::Refund as Refundable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
        >>::initialize(&cancel, punish_lock, self.refund_address.clone())?;

        // Set the fees according to the strategy in the offer and the local politic.
        <Ctx::Ar as Fee>::set_fee(refund.partial_mut(), &fee_strategy, self.fee_politic)?;

        Ok(CoreArbitratingTransactions {
            lock: datum::Transaction::new_lock(lock.to_partial()),
            cancel: datum::Transaction::new_cancel(cancel.to_partial()),
            refund: datum::Transaction::new_refund(refund.to_partial()),
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
    ///  * Derive the cancel private key from the arbitrating seed: `ar_seed`
    ///  * Generate the witness data for cancel path with [`generate_failure_witness`]
    ///
    /// Returns the signature inside [`CosignedArbitratingCancel`] bundle.
    ///
    /// [`cosign_arbitrating_cancel`]: Bob::cosign_arbitrating_cancel
    /// [`generate_failure_witness`]: Forkable::generate_failure_witness
    ///
    pub fn cosign_arbitrating_cancel(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
    ) -> Result<CosignedArbitratingCancel<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_cancel = core.cancel.tx().try_into_partial_transaction()?;

        // Initialize the cancel transaction based on the partial transaction format.
        let cancel = <<Ctx::Ar as Transactions>::Cancel>::from_partial(partial_cancel);

        // Derive the private key from the seed and generate the failure witness.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Cancel)?;
        let sig = cancel.generate_failure_witness(&privkey)?;

        Ok(CosignedArbitratingCancel {
            cancel_sig: Signature::new(TxId::Cancel, SwapRole::Bob, SignatureType::Regular(sig)),
        })
    }

    /// Validates the adaptor refund witness with [`verify_adaptor_witness`] based on the parameters
    /// and the core arbitrating transactions.
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
    /// [`verify_adaptor_witness`]: AdaptorSignable::verify_adaptor_witness
    ///
    pub fn validate_adaptor_refund(
        &self,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        adaptor_refund: &SignedAdaptorRefund<Ctx::Ar>,
    ) -> Result<(), Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.tx().try_into_partial_transaction()?;

        // Initialize the refund transaction based on the partial transaction format.
        let refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(partial_refund);

        // Verify the adaptor refund witness
        refund.verify_adaptor_witness(
            &alice_parameters
                .refund
                .key()
                .try_into_arbitrating_pubkey()?,
            &bob_parameters.adaptor.key().try_into_arbitrating_pubkey()?,
            adaptor_refund
                .refund_adaptor_sig
                .signature()
                .try_into_adaptor()?,
        )?;

        Ok(())
    }

    /// Creates the [`Buyable`] transaction and generate the adaptor witness with
    /// [`generate_adaptor_witness`]
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
    ///  * `ar_seed`: Bob's arbitrating seed
    ///  * `bob_parameters`: Bob's parameters bundle
    ///  * `core`: Core arbitrating transactions bundle
    ///  * `public_offer`: Public offer
    ///
    /// # Execution
    ///
    ///  * Parse the [`Lockable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Generate the [`DataLock`] structure from Alice and Bob parameters and the public offer
    ///  * Retrieve Alice's adaptor public key from [`AliceParameters`] bundle
    ///  * Derive the buy private key from the arbitrating seed: `ar_seed`
    ///  * Generate the adaptor witness data for success path with [`generate_adaptor_witness`]
    ///
    /// Returns the partial transaction and the signature inside the [`SignedAdaptorBuy`] bundle.
    ///
    /// [`sign_adaptor_buy`]: Bob::sign_adaptor_buy
    /// [`generate_adaptor_witness`]: AdaptorSignable::generate_adaptor_witness
    /// [`validate_adaptor_refund`]: Bob::validate_adaptor_refund
    ///
    pub fn sign_adaptor_buy(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<SignedAdaptorBuy<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.tx().try_into_partial_transaction()?;

        // Initialize the lock transaction based on the partial transaction format.
        let lock = <<Ctx::Ar as Transactions>::Lock>::from_partial(partial_lock);

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let bob_buy = bob_parameters.buy.key().try_into_arbitrating_pubkey()?;
        let alice_cancel = alice_parameters
            .cancel
            .key()
            .try_into_arbitrating_pubkey()?;
        let bob_cancel = bob_parameters.cancel.key().try_into_arbitrating_pubkey()?;

        // Create the data structure that represents an on-chain cancelable contract for the
        // arbitrating blockchain.
        let cancel_lock = DataLock {
            timelock: public_offer.offer.cancel_timelock,
            success: DoubleKeys::new(alice_buy, bob_buy),
            failure: DoubleKeys::new(alice_cancel, bob_cancel),
        };

        // Initialize the buy transaction based on the lock and the data lock. The buy transaction
        // consumes the success path of the lock and send the funds into Alice's destination
        // address.
        let mut buy = <<Ctx::Ar as Transactions>::Buy as Buyable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
        >>::initialize(
            &lock,
            cancel_lock,
            alice_parameters
                .destination_address
                .param()
                .try_into_address()?,
        )?;

        // Set the fees according to the strategy in the offer and the local politic.
        let fee_strategy = &public_offer.offer.fee_strategy;
        <Ctx::Ar as Fee>::set_fee(buy.partial_mut(), &fee_strategy, self.fee_politic)?;

        // Retrieve Alice's public adaptor key from the Alice parameters bundle, the key is used to
        // generate Bob's encrypted signature over the buy transaction.
        let adaptor = alice_parameters
            .adaptor
            .key()
            .try_into_arbitrating_pubkey()?;

        // Derive Bob's buy private key and generate the adaptor witness with the private key and
        // Alice's adaptor.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Buy)?;
        let sig = buy.generate_adaptor_witness(&privkey, &adaptor)?;

        Ok(SignedAdaptorBuy {
            buy: datum::Transaction::new_buy(buy.to_partial()),
            buy_adaptor_sig: Signature::new(TxId::Buy, SwapRole::Bob, SignatureType::Adaptor(sig)),
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
    ///  * Derive the funding private key from the arbitrating seed: `ar_seed`
    ///  * Generate the witness data with [`generate_witness`]
    ///
    /// Returns the signature inside a [`SignedArbitratingLock`] bundle.
    ///
    /// [`sign_arbitrating_lock`]: Bob::sign_arbitrating_lock
    /// [`generate_witness`]: Signable::generate_witness
    /// [`validate_adaptor_refund`]: Bob::validate_adaptor_refund
    ///
    pub fn sign_arbitrating_lock(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
    ) -> Result<SignedArbitratingLock<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.tx().try_into_partial_transaction()?;

        // Initialize the lock transaction based on the partial transaction format.
        let lock = <<Ctx::Ar as Transactions>::Lock>::from_partial(partial_lock);

        // Derive Bob's funding private key and generate the witness to unlock the fundable
        // transaction.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Fund)?;
        let sig = lock.generate_witness(&privkey)?;

        Ok(SignedArbitratingLock {
            lock_sig: Signature::new(TxId::Lock, SwapRole::Bob, SignatureType::Regular(sig)),
        })
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
    /// _Previously verified data_:
    ///  * `alice_parameters`: Alice's adaptor signature in [`SignedAdaptorRefund`] bundle
    ///  * `signed_adaptor_refund`: Verified by [`validate_adaptor_refund`]
    ///
    /// _Trusted data_:
    ///  * `ar_seed`, `ac_seed`: Bob's arbitrating and accordant seeds
    ///  * `core`: Core arbitrating transactions bundle
    ///
    /// # Execution
    ///
    ///  * Parse the [`Refundable`] partial transaction in [`CoreArbitratingTransactions`]
    ///  * Derive the refund private key from the arbitrating seed: `ar_seed`
    ///  * Generate the refund witness data with [`generate_witness`]
    ///  * Derive the adaptor private key from the accordant seed: `ac_seed`
    ///  * Adaprt the signature with [`adapt`]
    ///
    /// Returns the signatures inside a [`SignedArbitratingLock`] bundle.
    ///
    /// [`adapt`]: Signatures::adapt
    /// [`generate_witness`]: Signable::generate_witness
    /// [`validate_adaptor_refund`]: Bob::validate_adaptor_refund
    ///
    pub fn fully_sign_refund(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        core: CoreArbitratingTransactions<Ctx::Ar>,
        signed_adaptor_refund: &SignedAdaptorRefund<Ctx::Ar>,
    ) -> Result<FullySignedRefund<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.tx().try_into_partial_transaction()?;

        // Initialize the refund transaction based on the partial transaction format.
        let refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(partial_refund);

        // Derive the refund private key from the arbitrating and generate Bob's refund witness.
        let privkey = <Ctx::Ar as FromSeed<Arb>>::get_privkey(ar_seed, ArbitratingKey::Refund)?;
        let sig = refund.generate_witness(&privkey)?;

        // Derive the adaptor private key from the accordant seed and adapt counter-party witness.
        let priv_adaptor = <Ctx::Proof as DleqProof<Ctx::Ar, Ctx::Ac>>::project_over(ac_seed)?;
        let adapted_sig = <Ctx::Ar as Signatures>::adapt(
            &priv_adaptor,
            signed_adaptor_refund
                .refund_adaptor_sig
                .signature()
                .try_into_adaptor()?,
        )?;

        Ok(FullySignedRefund {
            refund_sig: Signature::new(TxId::Refund, SwapRole::Bob, SignatureType::Regular(sig)),
            refund_adapted_sig: Signature::new(
                TxId::Refund,
                SwapRole::Alice,
                SignatureType::Adapted(adapted_sig),
            ),
        })
    }

    pub fn recover_accordant_assets(&self) -> Result<(), Error> {
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
