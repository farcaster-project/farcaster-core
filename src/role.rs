//! Roles during negotiation and swap phases, blockchain roles, and network definitions.

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

use crate::blockchain::{Address, Asset, Fee, FeePolitic, Onchain, Timelock, Transactions};
use crate::bundle::{
    AliceParameters, BobParameters, CoreArbitratingTransactions, CosignedArbitratingCancel,
    FullySignedBuy, FullySignedPunish, FullySignedRefund, SignedAdaptorBuy, SignedAdaptorRefund,
    SignedArbitratingLock,
};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{
    AccordantKeyId, ArbitratingKeyId, Keys, SharedKeyId, SharedPrivateKeys, Sign, Signatures,
    TaggedElement, Wallet,
};
use crate::negotiation::PublicOffer;
use crate::script::{DataLock, DataPunishableLock, DoubleKeys, ScriptPath};
use crate::swap::Swap;
use crate::transaction::{
    Buyable, Cancelable, Chainable, Fundable, Lockable, Punishable, Refundable, Transaction,
    Witnessable,
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

impl Encodable for NegotiationRole {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            NegotiationRole::Maker => 0x01u8.consensus_encode(writer),
            NegotiationRole::Taker => 0x02u8.consensus_encode(writer),
        }
    }
}

impl Decodable for NegotiationRole {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(NegotiationRole::Maker),
            0x02u8 => Ok(NegotiationRole::Taker),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl_strict_encoding!(NegotiationRole);

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

impl_strict_encoding!(SwapRole);

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
        wallet: &impl Wallet<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ac as Keys>::PublicKey,
            <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey,
            <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey,
            Ctx::Proof,
        >,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<AliceParameters<Ctx>, Error> {
        let extra_arbitrating_keys: Result<
            Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
            Error,
        > = <Ctx::Ar as Keys>::extra_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_pubkey(ArbitratingKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let arbitrating_shared_keys: Result<
            Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey>>,
            Error,
        > = <Ctx::Ar as SharedPrivateKeys>::shared_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let extra_accordant_keys: Result<
            Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
            Error,
        > = <Ctx::Ac as Keys>::extra_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_pubkey(AccordantKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let accordant_shared_keys: Result<
            Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey>>,
            Error,
        > = <Ctx::Ac as SharedPrivateKeys>::shared_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let (spend, adaptor, proof) = wallet.generate()?;

        Ok(AliceParameters {
            buy: wallet.get_pubkey(ArbitratingKeyId::Buy)?,
            cancel: wallet.get_pubkey(ArbitratingKeyId::Cancel)?,
            refund: wallet.get_pubkey(ArbitratingKeyId::Refund)?,
            punish: wallet.get_pubkey(ArbitratingKeyId::Punish)?,
            adaptor,
            extra_arbitrating_keys: extra_arbitrating_keys?,
            arbitrating_shared_keys: arbitrating_shared_keys?,
            spend,
            extra_accordant_keys: extra_accordant_keys?,
            accordant_shared_keys: accordant_shared_keys?,
            destination_address: self.destination_address.clone(),
            proof,
            cancel_timelock: Some(public_offer.offer.cancel_timelock),
            punish_timelock: Some(public_offer.offer.punish_timelock),
            fee_strategy: Some(public_offer.offer.fee_strategy.clone()),
        })
    }

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
    ///  * Retrieve Alice's refund public key from [`AliceParameters`] bundle
    ///  * Generate the witness data and adaptor sign it
    ///
    /// Returns the adaptor signature inside the [`SignedAdaptorRefund`] bundle.
    ///
    pub fn sign_adaptor_refund(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<SignedAdaptorRefund<Ctx::Ar>, Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { refund, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        // Generate the witness message to sign and adaptor sign with the refund key and the
        // counter-party adaptor.
        let key = &alice_parameters.refund;
        let adaptor = &bob_parameters.adaptor;
        let msg = refund.generate_witness_message(ScriptPath::Success)?;
        let sig = wallet.adaptor_sign_with_key(&key, &adaptor, msg)?;

        Ok(SignedAdaptorRefund {
            refund_adaptor_sig: sig,
        })
    }

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
    ///  * Retreive Alice's cancel public key from the parameters
    ///  * Generate the witness data and sign it
    ///
    /// Returns the witness inside the [`CosignedArbitratingCancel`] bundle.
    ///
    pub fn cosign_arbitrating_cancel(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<CosignedArbitratingCancel<Ctx::Ar>, Error> {
        // Verifies the core arbitrating transactions.
        let ValidatedCoreTransactions { cancel, .. } =
            self.validate_core(alice_parameters, bob_parameters, core, public_offer)?;

        // Generate the witness message to sign and sign with the cancel key.
        let msg = cancel.generate_witness_message(ScriptPath::Failure)?;
        let key = &alice_parameters.cancel;
        let sig = wallet.sign_with_key(&key, msg)?;

        Ok(CosignedArbitratingCancel { cancel_sig: sig })
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
    pub fn validate_adaptor_buy(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
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
        let partial_buy = adaptor_buy.buy.clone();

        // Initialize the buy transaction based on the extracted partial transaction format.
        let buy = <<Ctx::Ar as Transactions>::Buy>::from_partial(partial_buy);

        buy.is_build_on_top_of(&lock)?;
        buy.verify_template(data_lock, self.destination_address.clone())?;
        <Ctx::Ar as Fee>::validate_fee(buy.as_partial(), &fee_strategy)?;

        // Verify the adaptor buy witness
        let msg = buy.generate_witness_message(ScriptPath::Success)?;
        wallet.verify_adaptor_signature(
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
    ///  * `public_offer`: The public offer
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
    /// Returns the signatures inside a [`FullySignedBuy`] bundle.
    ///
    /// [`validate_adaptor_buy`]: Alice::validate_adaptor_buy
    ///
    pub fn fully_sign_buy(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
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
        let partial_buy = adaptor_buy.buy.clone();

        // Initialize the buy transaction based on the extracted partial transaction format.
        let buy = <<Ctx::Ar as Transactions>::Buy>::from_partial(partial_buy);

        buy.is_build_on_top_of(&lock)?;
        buy.verify_template(data_lock, self.destination_address.clone())?;
        <Ctx::Ar as Fee>::validate_fee(buy.as_partial(), &fee_strategy)?;

        // Generate the witness message to sign and sign with the buy key.
        let msg = buy.generate_witness_message(ScriptPath::Success)?;
        let key = &alice_parameters.buy;
        let sig = wallet.sign_with_key(&key, msg)?;

        // Retreive the adaptor public key and the counter-party adaptor witness.
        let key = &alice_parameters.adaptor;
        let adapted_sig = wallet.adapt_signature(&key, adaptor_buy.buy_adaptor_sig.clone())?;

        Ok(FullySignedBuy {
            buy_sig: sig,
            buy_adapted_sig: adapted_sig,
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
    ///  * `ar_engine`: Alice's arbitrating seed
    ///  * `alice_parameters`: Alice's parameters bundle
    ///  * `public_offer`: The public offer
    ///
    /// # Execution
    ///
    ///  * Parse the [`Buyable`] partial transaction in [`SignedAdaptorBuy`]
    ///  * Retreive the buy public key from the parameters
    ///  * Generate the buy witness data
    ///  * Retreive the adaptor public key from the parameters
    ///  * Adapt the signature
    ///
    /// Returns the signatures inside a [`FullySignedBuy`] bundle.
    ///
    /// [`validate_adaptor_buy`]: Alice::validate_adaptor_buy
    ///
    pub fn fully_sign_punish(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
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
        <Ctx::Ar as Fee>::set_fee(punish.as_partial_mut(), &fee_strategy, self.fee_politic)?;

        // Generate the witness message to sign and sign with the punish key.
        let msg = punish.generate_witness_message(ScriptPath::Failure)?;
        let key = &alice_parameters.punish;
        let punish_sig = wallet.sign_with_key(&key, msg)?;

        Ok(FullySignedPunish {
            punish: punish.to_partial(),
            punish_sig,
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
        let partial_lock = core.lock.clone();

        // Initialize the lock transaction based on the extracted partial transaction format.
        let lock = <<Ctx::Ar as Transactions>::Lock>::from_partial(partial_lock);

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        // FIXME change dataLock to take refs
        let alice_buy = alice_parameters.buy.clone();
        let bob_buy = bob_parameters.buy.clone();
        let alice_cancel = alice_parameters.cancel.clone();
        let bob_cancel = bob_parameters.cancel.clone();

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
        <Ctx::Ar as Fee>::validate_fee(lock.as_partial(), &fee_strategy)?;

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        // FIXME change dataLock to take refs
        let alice_refund = alice_parameters.refund.clone();
        let bob_refund = bob_parameters.refund.clone();
        let alice_punish = alice_parameters.punish.clone();

        // Create the data structure that represents an on-chain punishable contract for the
        // arbitrating blockchain.
        let punish_lock = DataPunishableLock {
            timelock: public_offer.offer.punish_timelock,
            success: DoubleKeys::new(alice_refund, bob_refund),
            failure: alice_punish,
        };

        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_cancel = core.cancel.clone();

        // Initialize the lock transaction based on the extracted partial transaction format.
        let cancel = <<Ctx::Ar as Transactions>::Cancel>::from_partial(partial_cancel);
        // Check that the cancel transaction is build on top of the lock.
        cancel.is_build_on_top_of(&lock)?;
        cancel.verify_template(data_lock.clone(), punish_lock.clone())?;
        // Validate the fee strategy
        <Ctx::Ar as Fee>::validate_fee(cancel.as_partial(), &fee_strategy)?;

        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.clone();

        // Initialize the refund transaction based on the extracted partial transaction format.
        let refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(partial_refund);
        // Check that the refund transaction is build on top of the cancel transaction.
        refund.is_build_on_top_of(&cancel)?;
        let refund_address = bob_parameters.refund_address.clone();
        refund.verify_template(punish_lock.clone(), refund_address)?;
        // Validate the fee strategy
        <Ctx::Ar as Fee>::validate_fee(refund.as_partial(), &fee_strategy)?;

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
        wallet: &impl Wallet<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ac as Keys>::PublicKey,
            <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey,
            <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey,
            Ctx::Proof,
        >,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<BobParameters<Ctx>, Error> {
        let extra_arbitrating_keys: Result<
            Vec<TaggedElement<u16, <Ctx::Ar as Keys>::PublicKey>>,
            Error,
        > = <Ctx::Ar as Keys>::extra_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_pubkey(ArbitratingKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let arbitrating_shared_keys: Result<
            Vec<TaggedElement<SharedKeyId, <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey>>,
            Error,
        > = <Ctx::Ar as SharedPrivateKeys>::shared_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let extra_accordant_keys: Result<
            Vec<TaggedElement<u16, <Ctx::Ac as Keys>::PublicKey>>,
            Error,
        > = <Ctx::Ac as Keys>::extra_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_pubkey(AccordantKeyId::Extra(tag))?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let accordant_shared_keys: Result<
            Vec<TaggedElement<SharedKeyId, <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey>>,
            Error,
        > = <Ctx::Ac as SharedPrivateKeys>::shared_keys()
            .into_iter()
            .map(|tag| {
                let key = wallet.get_shared_key(tag)?;
                Ok(TaggedElement::new(tag, key))
            })
            .collect();

        let (spend, adaptor, proof) = wallet.generate()?;

        Ok(BobParameters {
            buy: wallet.get_pubkey(ArbitratingKeyId::Buy)?,
            cancel: wallet.get_pubkey(ArbitratingKeyId::Cancel)?,
            refund: wallet.get_pubkey(ArbitratingKeyId::Refund)?,
            adaptor,
            extra_arbitrating_keys: extra_arbitrating_keys?,
            arbitrating_shared_keys: arbitrating_shared_keys?,
            spend,
            extra_accordant_keys: extra_accordant_keys?,
            accordant_shared_keys: accordant_shared_keys?,
            refund_address: self.refund_address.clone(),
            proof,
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
    ///  * `public_offer`: Public offer
    ///
    /// # Execution
    ///
    /// The parameters to create the three transactions are:
    ///  * Alice's public keys present in Alice's parameters bundle: [`AliceParameters`]
    ///  * Bob's public keys present in Bob's parameters bundle: [`BobParameters`]
    ///  * The [`Fundable`] transaction
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
        funding: impl Fundable<Ctx::Ar, <Ctx::Ar as Transactions>::Metadata>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<CoreArbitratingTransactions<Ctx::Ar>, Error> {
        // Initialize the fundable transaction to build the lockable transaction on top of it.
        //
        // The fundable transaction `funding` contains all the logic to build on top of a
        // externally created transaction seen on-chain asyncronously by a syncer when broadcasted
        // by the external wallet.

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy.clone();
        let bob_buy = bob_parameters.buy.clone();
        let alice_cancel = alice_parameters.cancel.clone();
        let bob_cancel = bob_parameters.cancel.clone();

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
        <Ctx::Ar as Fee>::validate_fee(lock.as_partial(), &fee_strategy)?;

        // Get the three keys, Alice and Bob for refund and Alice's punish key. The keys are
        // needed, along with the timelock for the punish, to create the punishable on-chain
        // contract on the arbitrating blockchain.
        let alice_refund = alice_parameters.refund.clone();
        let bob_refund = bob_parameters.refund.clone();
        let alice_punish = alice_parameters.punish.clone();

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
        <Ctx::Ar as Fee>::set_fee(cancel.as_partial_mut(), &fee_strategy, self.fee_politic)?;

        // Initialize the refund transaction for the cancel transaction, moving the funds out of
        // the punishable lock to Bob's refund address.
        let mut refund = <<Ctx::Ar as Transactions>::Refund as Refundable<
            Ctx::Ar,
            <Ctx::Ar as Transactions>::Metadata,
        >>::initialize(&cancel, punish_lock, self.refund_address.clone())?;

        // Set the fees according to the strategy in the offer and the local politic.
        <Ctx::Ar as Fee>::set_fee(refund.as_partial_mut(), &fee_strategy, self.fee_politic)?;

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
    pub fn cosign_arbitrating_cancel(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
    ) -> Result<CosignedArbitratingCancel<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_cancel = core.cancel.clone();

        // Initialize the cancel transaction based on the partial transaction format.
        let cancel = <<Ctx::Ar as Transactions>::Cancel>::from_partial(partial_cancel);

        // Generate the witness message to sign and sign with the cancel key.
        let msg = cancel.generate_witness_message(ScriptPath::Failure)?;
        let key = &bob_parameters.cancel;
        let sig = wallet.sign_with_key(&key, msg)?;

        Ok(CosignedArbitratingCancel { cancel_sig: sig })
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
    pub fn validate_adaptor_refund(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        adaptor_refund: &SignedAdaptorRefund<Ctx::Ar>,
    ) -> Result<(), Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund.clone();

        // Initialize the refund transaction based on the partial transaction format.
        let refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(partial_refund);

        // Verify the adaptor refund witness
        let msg = refund.generate_witness_message(ScriptPath::Success)?;
        wallet.verify_adaptor_signature(
            &alice_parameters.refund,
            &bob_parameters.adaptor,
            msg,
            &adaptor_refund.refund_adaptor_sig,
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
    ///  * `public_offer`: Public offer
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
    pub fn sign_adaptor_buy(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        alice_parameters: &AliceParameters<Ctx>,
        bob_parameters: &BobParameters<Ctx>,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
        public_offer: &PublicOffer<Ctx>,
    ) -> Result<SignedAdaptorBuy<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.clone();

        // Initialize the lock transaction based on the partial transaction format.
        let lock = <<Ctx::Ar as Transactions>::Lock>::from_partial(partial_lock);

        // Get the four keys, Alice and Bob for Buy and Cancel. The keys are needed, along with the
        // timelock for the cancel, to create the cancelable on-chain contract on the arbitrating
        // blockchain.
        let alice_buy = alice_parameters.buy.clone();
        let bob_buy = bob_parameters.buy.clone();
        let alice_cancel = alice_parameters.cancel.clone();
        let bob_cancel = bob_parameters.cancel.clone();

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
            alice_parameters.destination_address.clone(),
        )?;

        // Set the fees according to the strategy in the offer and the local politic.
        let fee_strategy = &public_offer.offer.fee_strategy;
        <Ctx::Ar as Fee>::set_fee(buy.as_partial_mut(), &fee_strategy, self.fee_politic)?;

        // Generate the witness message to sign and adaptor sign with the buy key and the
        // counter-party adaptor.
        let key = &bob_parameters.buy;
        let adaptor = &alice_parameters.adaptor;
        let msg = buy.generate_witness_message(ScriptPath::Success)?;
        let sig = wallet.adaptor_sign_with_key(&key, &adaptor, msg)?;

        Ok(SignedAdaptorBuy {
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
    pub fn sign_arbitrating_lock(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        key_wallet: &impl Wallet<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ac as Keys>::PublicKey,
            <Ctx::Ar as SharedPrivateKeys>::SharedPrivateKey,
            <Ctx::Ac as SharedPrivateKeys>::SharedPrivateKey,
            Ctx::Proof,
        >,
        core: &CoreArbitratingTransactions<Ctx::Ar>,
    ) -> Result<SignedArbitratingLock<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_lock = core.lock.clone();

        // Initialize the lock transaction based on the partial transaction format.
        let lock = <<Ctx::Ar as Transactions>::Lock>::from_partial(partial_lock);

        // Generate the witness message to sign and sign with the fund key.
        let msg = lock.generate_witness_message(ScriptPath::Success)?;
        let key = key_wallet.get_pubkey(ArbitratingKeyId::Fund)?;
        let sig = wallet.sign_with_key(&key, msg)?;

        Ok(SignedArbitratingLock { lock_sig: sig })
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
    ///  * `ar_engine`, `ac_engine`: Bob's arbitrating and accordant seeds
    ///  * `core`: Core arbitrating transactions bundle
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
    pub fn fully_sign_refund(
        &self,
        wallet: &impl Sign<
            <Ctx::Ar as Keys>::PublicKey,
            <Ctx::Ar as Keys>::PrivateKey,
            <Ctx::Ar as Signatures>::Message,
            <Ctx::Ar as Signatures>::Signature,
            <Ctx::Ar as Signatures>::AdaptorSignature,
        >,
        bob_parameters: &BobParameters<Ctx>,
        core: CoreArbitratingTransactions<Ctx::Ar>,
        signed_adaptor_refund: &SignedAdaptorRefund<Ctx::Ar>,
    ) -> Result<FullySignedRefund<Ctx::Ar>, Error> {
        // Extract the partial transaction from the core arbitrating bundle, this operation should
        // not error if the bundle is well formed.
        let partial_refund = core.refund;

        // Initialize the refund transaction based on the partial transaction format.
        let refund = <<Ctx::Ar as Transactions>::Refund>::from_partial(partial_refund);

        // Generate the witness message to sign and sign with the refund key.
        let msg = refund.generate_witness_message(ScriptPath::Success)?;
        let key = &bob_parameters.refund;
        let sig = wallet.sign_with_key(&key, msg)?;

        let key = &bob_parameters.adaptor;
        let adapted_sig =
            wallet.adapt_signature(&key, signed_adaptor_refund.refund_adaptor_sig.clone())?;

        Ok(FullySignedRefund {
            refund_sig: sig,
            refund_adapted_sig: adapted_sig,
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
    + Fee
    + Keys
    + Onchain
    + Signatures
    + Timelock
    + Transactions
    + SharedPrivateKeys
    + Clone
    + Eq
{
}

/// An accordant is the blockchain which does not need transaction inside the protocol nor
/// timelocks, it is the blockchain with the less requirements for an atomic swap.
pub trait Accordant: Asset + Address + Keys + SharedPrivateKeys + Clone + Eq {}
