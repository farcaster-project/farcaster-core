//! Arbitrating transaction module

use std::fmt::Debug;

use crate::blockchain::{FeePolitic, FeeStrategy, Network};
use crate::role::Arbitrating;
use crate::script;

/// Base trait for arbitrating transactions. Defines methods to generate a partial arbitrating
/// transaction used over the network.
pub trait Transaction<Ar>: Debug
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Extract the transaction in the defined partial format on the arbitrating blockchain. The
    /// partial format is used to exchange unsigned or patially signed transactions.
    fn to_partial(&self) -> Option<Ar::PartialTransaction>;
}

/// Defines the transaction IDs for serialization and network communication.
#[derive(Debug, Clone)]
pub enum TxId {
    /// Represents the first transaction created outside of the system by an external wallet to
    /// fund the swap on the arbitrating blockchain.
    Funding,
    /// Represents the core locking arbitrating transaction.
    Lock,
    /// Represents the happy path for swapping the assets.
    Buy,
    /// Represents the failure path, used as the first step to cancel a swap.
    Cancel,
    /// Represents the transaction that successfully cancel a swap by refunding both participants.
    Refund,
    /// Represents the full failure path, where only one participant gets refunded because he
    /// didn't act accordingly to the protocol.
    Punish,
}

/// Must be implemented on transactions with failable opperations.
pub trait Failable {
    /// Errors returned by the failable methods.
    type Error: Debug;
}

/// Transaction that requries multiple participants to construct and finalize the transaction.
pub trait Cooperable<Ar>: Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Add a cooperation to the transaction and store it internally for later usage.
    fn add_cooperation(
        &mut self,
        pubkey: Ar::PublicKey,
        sig: Ar::Signature,
    ) -> Result<(), Self::Error>;
}

/// Define a transaction that must have a finalization step.
pub trait Finalizable<Ar>: Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Finalize the internal transaction and make it ready for extraction.
    fn finalize(&mut self) -> Result<(), Self::Error>;
}

/// Define a transaction broadcastable by the system. Externally managed transaction are not
/// broadcastable.
pub trait Broadcastable<Ar>: Failable + Finalizable<Ar>
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Extract the finalized transaction and return a fully signed transaction type as defined in
    /// the arbitrating blockchain. Used before broadcasting the transaction on-chain.
    ///
    /// This correspond to the "role" of a "finalizer" as defined in BIP 174 for dealing with
    /// partial transactions, which can be applied more generically than just Bitcoin.
    fn extract(&self) -> Ar::Transaction;

    /// Finalize the internal transaction and extract it, ready to be broadcasted.
    fn finalize_and_extract(&mut self) -> Result<Ar::Transaction, Self::Error> {
        // TODO maybe do more validation based on other traits
        self.finalize()?;
        Ok(self.extract())
    }
}

/// Implemented by transactions that can be link to form chains of logic. A linkable transaction
/// can provide the data needed for other transaction to safely build on top of it.
pub trait Linkable<Ar>: Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Returned type of the consumable output, used to reference the funds and chain other
    /// transactions on it. This must contain all necessary data to latter create a valid unlocking
    /// witness for the output.
    type Output;

    /// Return the consumable output of this transaction. The output does not contain the witness
    /// data allowing spending the output, only the data that points to the consumable output and
    /// the data necessary to produce a valid unlocking witness.
    ///
    /// This correspond to data an "updater" such as defined in BIP 174 can use to update a
    /// partial transaction. This is used to get all data needed to describe this output as an
    /// input in another transaction.
    fn get_consumable_output(&self) -> Result<Self::Output, Self::Error>;
}

/// Implemented on transactions that can be signed by a normal private key and generate/validate a
/// valid signature.
pub trait Signable<Ar>: Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Generate the witness to unlock the default path of the locked asset.
    fn generate_witness(&mut self, privkey: &Ar::PrivateKey) -> Result<Ar::Signature, Self::Error>;

    /// Verify that the signature is valid to unlock the default path of the locked asset.
    fn verify_witness(
        &mut self,
        pubkey: &Ar::PublicKey,
        sig: Ar::Signature,
    ) -> Result<(), Self::Error>;
}

/// Implemented on transactions that can be signed by a private key and an adaptor key.
pub trait AdaptorSignable<Ar>: Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Generate the adaptor witness to unlock the default path of the locked asset.
    fn generate_adaptor_witness(
        &mut self,
        privkey: &Ar::PrivateKey,
        adaptor: &Ar::PublicKey,
    ) -> Result<Ar::AdaptorSignature, Self::Error>;

    /// Verify that the adaptor signature is valid to unlock the default path of the locked asset.
    fn verify_adaptor_witness(
        &mut self,
        pubkey: &Ar::PublicKey,
        adaptor: &Ar::PublicKey,
        sig: Ar::AdaptorSignature,
    ) -> Result<(), Self::Error>;
}

/// Defines a transaction where the consumable output has two paths: a successful path and a
/// failure path and generate witneesses for the second path.
pub trait Forkable<Ar>: Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Generates the witness used to unlock the second path of the asset lock, i.e. the failure
    /// path.
    fn generate_failure_witness(
        &mut self,
        privkey: &Ar::PrivateKey,
    ) -> Result<Ar::Signature, Self::Error>;

    /// Verify that the signature is valid to unlock the second path of of the locked asset, i.e.
    /// the failure path.
    fn verify_failure_witness(
        &mut self,
        pubkey: &Ar::PublicKey,
        sig: Ar::Signature,
    ) -> Result<(), Self::Error>;
}

/// Fundable is NOT a transaction generated by this library but the funds that arrived in the
/// generated address are controlled by the system. This trait allows to inject assets in the
/// system.
pub trait Fundable<Ar>: Linkable<Ar> + Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Create a new funding 'output', or equivalent depending on the blockchain and the
    /// cryptographic engine.
    fn initialize(privkey: Ar::PublicKey, network: Network) -> Result<Self, Self::Error>;

    /// Return the address to use for the funding.
    fn get_address(&self) -> Result<Ar::Address, Self::Error>;

    /// Update the transaction, this is used to update the data when the funding transaction is
    /// seen on-chain.
    ///
    /// This function is needed because we assume that the transaction is created outside of the
    /// system by an external wallet, the txid is not known in advance.
    fn update(&mut self, args: Ar::Transaction) -> Result<(), Self::Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Funding
    }
}

/// Represent a lockable transaction such as the `lock (b)` transaction that consumes the `funding
/// (a)` transaction and creates the scripts used by `buy (c)` and `cancel (d)` transactions.
pub trait Lockable<Ar>:
    Transaction<Ar> + Signable<Ar> + Broadcastable<Ar> + Linkable<Ar> + Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Defines what type the funding transaction must return when creating an output.
    type Input;

    /// Creates a new `lock (b)` transaction based on the `funding (a)` transaction and the data
    /// needed for creating the lock primitive (i.e. the timelock and the keys). Return a new `lock
    /// (b)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Fundable<Ar, Output = Self::Input, Error = Self::Error>,
        lock: script::DataLock<Ar>,
        fee_strategy: &FeeStrategy<Ar::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Self::Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Lock
    }
}

/// Represent a buyable transaction such as the `buy (c)` transaction that consumes the `lock (b)`
/// transaction and transfer the funds to the buyer while revealing the secret needed to the seller
/// to take ownership of the counter-party funds. This transaction becomes available directly after
/// `lock (b)` but should be broadcasted only when `lock (b)` is finalized on-chain.
pub trait Buyable<Ar>:
    Transaction<Ar>
    + Signable<Ar>
    + AdaptorSignable<Ar>
    + Broadcastable<Ar>
    + Linkable<Ar>
    + Cooperable<Ar>
    + Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Defines what type the lock transaction must return when creating an output.
    type Input;

    /// Creates a new `buy (c)` transaction based on the `lock (b)` transaction and the data needed
    /// for sending the funds to the buyer (i.e. the destination address). Return a new `buy (c)`
    /// transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Lockable<Ar, Output = Self::Input, Error = Self::Error>,
        lock: script::DataLock<Ar>,
        destination_target: Ar::Address,
        fee_strategy: &FeeStrategy<Ar::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Self::Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Buy
    }
}

/// Represent a cancelable transaction such as the `cancel (d)` transaction that consumes the `lock
/// (b)` transaction and creates a new punishable lock, i.e. a lock with a consensus path and an
/// unilateral path available after some defined timelaps. This transaction becomes available after
/// the define timelock in `lock (b)`.
pub trait Cancelable<Ar>:
    Transaction<Ar> + Forkable<Ar> + Broadcastable<Ar> + Linkable<Ar> + Cooperable<Ar> + Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Defines what type the lock transaction must return when creating an output.
    type Input;

    /// Creates a new `cancel (d)` transaction based on the `lock (b)` transaction and the data
    /// needed for creating the lock primitive (i.e. the timelock and the keys). Return a new
    /// `cancel (d)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Lockable<Ar, Output = Self::Input, Error = Self::Error>,
        lock: script::DataLock<Ar>,
        punish_lock: script::DataPunishableLock<Ar>,
        fee_strategy: &FeeStrategy<Ar::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Self::Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Cancel
    }
}

/// Represent a refundable transaction such as the `refund (e)` transaction that consumes the
/// `cancel (d)` transaction and send the money to its original owner. This transaction is directly
/// available but should be broadcasted only after 'finalization' of `cancel (d)` on-chain.
pub trait Refundable<Ar>:
    Transaction<Ar>
    + Signable<Ar>
    + AdaptorSignable<Ar>
    + Broadcastable<Ar>
    + Linkable<Ar>
    + Cooperable<Ar>
    + Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Defines what type the lock transaction must return when creating an output.
    type Input;

    /// Creates a new `refund (e)` transaction based on the `cancel (d)` transaction and the data
    /// needed for refunding the funds (i.e. the refund address). Return a new `refund (e)`
    /// transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Cancelable<Ar, Output = Self::Input, Error = Self::Error>,
        punish_lock: script::DataPunishableLock<Ar>,
        refund_target: Ar::Address,
        fee_strategy: &FeeStrategy<Ar::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Self::Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Refund
    }
}

/// Represent a punishable transaction such as the `punish (f)` transaction that consumes the
/// `cancel (d)` transaction and send the money to the counter-party, the original buyer, but do
/// not reveal the secret needed to unlock the counter-party funds, effectivelly punishing the
/// missbehaving participant.  This transaction becomes available after the define timelock in
/// `cancel (d)`.
pub trait Punishable<Ar>:
    Transaction<Ar> + Forkable<Ar> + Broadcastable<Ar> + Linkable<Ar> + Failable
where
    Ar: Arbitrating,
    Self: Sized,
{
    /// Defines what type the lock transaction must return when creating an output.
    type Input;

    /// Creates a new `punish (f)` transaction based on the `cancel (d)` transaction and the data
    /// needed for punishing the counter-party (i.e. the same address as the buyer). Return a new
    /// `punish (f)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Cancelable<Ar, Output = Self::Input, Error = Self::Error>,
        punish_lock: script::DataPunishableLock<Ar>,
        destination_target: Ar::Address,
        fee_strategy: &FeeStrategy<Ar::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Self::Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Punish
    }
}
