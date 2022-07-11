//! Arbitrating transaction traits used as the on-chain arbitration engine on the arbitrating
//! blockchain. These traits define the steps allowed in the arbitration engine enforced on-chain.

use std::error;
use std::fmt::Debug;
use std::io;

use thiserror::Error;

use crate::blockchain::{Address, Asset, Fee, Network, Onchain, Timelock};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::Signatures;
use crate::script::{DataLock, DataPunishableLock, ScriptPath};

/// A list specifying general categories of transaction error.
#[derive(Error, Debug)]
pub enum Error {
    /// Missing UTXO.
    #[error("Missing UTXO")]
    MissingUTXO,
    /// Missing signature data.
    #[error("Missing signature")]
    MissingSignature,
    /// Missing witness data.
    #[error("Missing witness data")]
    MissingWitness,
    /// Missing network data.
    #[error("Missing network data")]
    MissingNetwork,
    /// Missing public key in the partial transaction.
    #[error("Public key not found in the partial transaction")]
    MissingPublicKey,
    /// The transaction has not been seen on-chain yet.
    #[error("The transaction has not been seen on-chain yet")]
    MissingOnchainTransaction,
    /// The arbitrating targeted amount is invalid.
    #[error("The targeted amount is invalid")]
    InvalidTargetAmount,
    /// Not enough assets to create the transaction.
    #[error("Not enough assets to create the transaction")]
    NotEnoughAssets,
    /// Wrong transaction template.
    #[error("Wrong transaction template: {0}")]
    WrongTemplate(&'static str),
    /// The transaction chain validation failed
    #[error("The transaction chain validation failed")]
    InvalidTransactionChain,
    /// Any transaction error not part of this list.
    #[error("Transaction error: {0}")]
    Other(Box<dyn error::Error + Send + Sync>),
}

impl Error {
    /// Creates a new transaction error of type other with an arbitrary payload.
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::Other(error.into())
    }

    /// Consumes the `Error`, returning its inner error (if any).
    ///
    /// If this [`enum@Error`] was constructed via [`new`] then this function will return [`Some`],
    /// otherwise it will return [`None`].
    ///
    /// [`new`]: Error::new
    ///
    pub fn into_inner(self) -> Option<Box<dyn error::Error + Send + Sync>> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

/// Base trait for arbitrating transactions. Defines methods to generate a partial arbitrating
/// transaction used over the network.
///
/// ```
/// use bitcoin::Amount;
/// use bitcoin::util::psbt::PartiallySignedTransaction;
/// use bitcoin::blockdata::transaction::TxIn;
/// use farcaster_core::transaction::Transaction;
///
/// pub struct MyTx(PartiallySignedTransaction);
///
/// impl Transaction<PartiallySignedTransaction, TxIn, Amount> for MyTx {
///     fn as_partial(&self) -> &PartiallySignedTransaction {
///         todo!()
///     }
///
///     fn as_partial_mut(&mut self) -> &mut PartiallySignedTransaction {
///         todo!()
///     }
///
///     fn to_partial(self) -> PartiallySignedTransaction {
///         todo!()
///     }
///
///     fn from_partial(partial: PartiallySignedTransaction) -> Self {
///         todo!()
///     }
///
///     fn based_on(&self) -> TxIn {
///         todo!()
///     }
///
///     fn output_amount(&self) -> Amount {
///         todo!()
///     }
/// }
/// ```
pub trait Transaction<Px, Out, Amt> {
    /// Returns a reference to the inner partial transaction data.
    fn as_partial(&self) -> &Px;

    /// Returns a mutable reference to the inner partial transaction data.
    fn as_partial_mut(&mut self) -> &mut Px;

    /// Extract the transaction in the defined partial format on the arbitrating blockchain. The
    /// partial format is used to exchange unsigned or patially signed transactions.
    fn to_partial(self) -> Px;

    /// Construct the transaction type from a deserialized partial transaction.
    fn from_partial(partial: Px) -> Self;

    /// Returns the metadata that identifies the transaction this transaction is build on top.
    fn based_on(&self) -> Out;

    /// Returns the output amount of the transaction.
    fn output_amount(&self) -> Amt;
}

/// Defines the transaction Farcaster IDs for serialization and network communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum TxLabel {
    /// Represents the first transaction created outside of the system by an external wallet to
    /// fund the swap on the arbitrating blockchain.
    Funding,
    /// Represents the core locking arbitrating transaction.
    #[display("Arbitrating Lock")]
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
    /// Represents the accordant lock transaction
    #[display("Accordant Lock")]
    AccLock,
}

impl Encodable for TxLabel {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            TxLabel::Funding => 0x01u16.consensus_encode(writer),
            TxLabel::Lock => 0x02u16.consensus_encode(writer),
            TxLabel::Buy => 0x03u16.consensus_encode(writer),
            TxLabel::Cancel => 0x04u16.consensus_encode(writer),
            TxLabel::Refund => 0x05u16.consensus_encode(writer),
            TxLabel::Punish => 0x06u16.consensus_encode(writer),
            TxLabel::AccLock => 0x07u16.consensus_encode(writer),
        }
    }
}

impl Decodable for TxLabel {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u16 => Ok(TxLabel::Funding),
            0x02u16 => Ok(TxLabel::Lock),
            0x03u16 => Ok(TxLabel::Buy),
            0x04u16 => Ok(TxLabel::Cancel),
            0x05u16 => Ok(TxLabel::Refund),
            0x06u16 => Ok(TxLabel::Punish),
            0x07u16 => Ok(TxLabel::AccLock),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl_strict_encoding!(TxLabel);

/// Transaction that requries one or more participants to sign and add witness before finalizing
/// the transaction.
pub trait Witnessable<Ms, Pk, Si> {
    /// Generate the witness message, given the scipt path if needed, to be signed to create a
    /// valid transaction.
    fn generate_witness_message(&self, path: ScriptPath) -> Result<Ms, Error>;

    /// Add a cooperation to the transaction and store it internally for later usage.
    fn add_witness(&mut self, pubkey: Pk, sig: Si) -> Result<(), Error>;
}

/// Define a transaction that must have a finalization step.
pub trait Finalizable {
    /// Finalize the internal transaction and make it ready for extraction.
    fn finalize(&mut self) -> Result<(), Error>;
}

/// Define a transaction broadcastable by the system. Externally managed transaction are not
/// broadcastable.
pub trait Broadcastable<Tx>: Finalizable {
    /// Extract the finalized transaction and return a fully signed transaction type as defined in
    /// the arbitrating blockchain. Used before broadcasting the transaction on-chain.
    ///
    /// This correspond to the "role" of a "finalizer" as defined in BIP 174 for dealing with
    /// partial transactions, which can be applied more generically than just Bitcoin.
    fn extract(&self) -> Tx;

    /// Finalize the internal transaction and extract it, ready to be broadcasted.
    fn finalize_and_extract(&mut self) -> Result<Tx, Error> {
        self.finalize()?;
        Ok(self.extract())
    }
}

/// Implemented by transactions that can be link to form chains of logic. A linkable transaction
/// can provide the data needed for other transaction to safely build on top of it.
///
/// `Out`, the returned type of the consumable output, used to reference the funds and chain other
/// transactions on it. This must contain all necessary data to latter create a valid unlocking
/// witness for the output.
pub trait Linkable<Out> {
    /// Return the consumable output of this transaction. The output does not contain the witness
    /// data allowing spending the output, only the data that points to the consumable output and
    /// the data necessary to produce a valid unlocking witness.
    ///
    /// This correspond to data an "updater" such as defined in BIP 174 can use to update a
    /// partial transaction. This is used to get all data needed to describe this output as an
    /// input in another transaction.
    fn get_consumable_output(&self) -> Result<Out, Error>;
}

/// Implemented by transactions based on another transaction. This trait is auto implemented for
/// all type `T` that implements `Transaction<Px, Out, Amt>` when and `Out` is `Eq`.
pub trait Chainable<Px, Out, Amt>: Transaction<Px, Out, Amt>
where
    Out: Eq,
{
    /// Verifies that the transaction build on top of the previous transaction.
    fn is_build_on_top_of(&self, prev: &impl Linkable<Out>) -> Result<(), Error>;
}

impl<T, Px, Out, Amt> Chainable<Px, Out, Amt> for T
where
    Out: Eq,
    T: Transaction<Px, Out, Amt>,
{
    fn is_build_on_top_of(&self, prev: &impl Linkable<Out>) -> Result<(), Error> {
        match self.based_on() == prev.get_consumable_output()? {
            true => Ok(()),
            false => Err(Error::InvalidTransactionChain),
        }
    }
}

/// Fundable is NOT a transaction generated by this library but the funds that arrived in the
/// generated address are controlled by the system. This trait allows to inject assets in the
/// system.
pub trait Fundable<Tx, Out, Addr, Pk>: Linkable<Out> {
    /// Create a new funding 'output', or equivalent depending on the blockchain and the
    /// cryptographic engine.
    fn initialize(pubkey: Pk, network: Network) -> Result<Self, Error>
    where
        Self: Sized;

    /// Return the address to use for the funding.
    fn get_address(&self) -> Result<Addr, Error>;

    /// Update the transaction, this is used to update the data when the funding transaction is
    /// seen on-chain.
    ///
    /// This function is needed because we assume that the transaction is created outside of the
    /// system by an external wallet, the txid is not known in advance.
    fn update(&mut self, tx: Tx) -> Result<(), Error>;

    /// Boolean indicating whether the transaction was seen
    fn was_seen(&self) -> bool;

    /// Create a raw funding structure based only on the transaction seen on-chain.
    fn raw(tx: Tx) -> Result<Self, Error>
    where
        Self: Sized;

    /// Return the Farcaster transaction identifier.
    fn get_label(&self) -> TxLabel {
        TxLabel::Funding
    }
}

/// Represent a lockable transaction such as the `lock (b)` transaction that consumes the `funding
/// (a)` transaction and creates the scripts used by `buy (c)` and `cancel (d)` transactions.
pub trait Lockable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>:
    Transaction<Px, Out, Amt> + Broadcastable<Tx> + Linkable<Out> + Witnessable<Ms, Pk, Si>
{
    /// Creates a new `lock (b)` transaction based on the `funding (a)` transaction and the data
    /// needed for creating the lock primitive (i.e. the timelock and the keys). Return a new `lock
    /// (b)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    ///
    /// # Target Amount
    ///
    /// The target amount is used to set the value of the output, the fee strategy is latter
    /// validated against the freshly created transaction to ensure that fee is valid for the
    /// transaction. The initialization must return an error if the amount is insufficient.
    ///
    fn initialize(
        prev: &impl Fundable<Tx, Out, Addr, Pk>,
        lock: DataLock<Ti, Pk>,
        target_amount: Amt,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Verifies that the transaction is compliant with the protocol requirements and implements
    /// the correct conditions of the [`DataLock`].
    fn verify_template(&self, lock: DataLock<Ti, Pk>) -> Result<(), Error>;

    // TODO this could be moved to transaction directly
    /// Verifies that the available output amount in lock is equal to the target amount.
    fn verify_target_amount(&self, target_amount: Amt) -> Result<(), Error>
    where
        Amt: PartialEq,
    {
        match self.output_amount() == target_amount {
            true => Ok(()),
            false => Err(Error::InvalidTargetAmount),
        }
    }

    /// Return the Farcaster transaction identifier.
    fn get_label(&self) -> TxLabel {
        TxLabel::Lock
    }
}

/// Represent a buyable transaction such as the `buy (c)` transaction that consumes the `lock (b)`
/// transaction and transfer the funds to the buyer while revealing the secret needed to the seller
/// to take ownership of the counter-party funds. This transaction becomes available directly after
/// `lock (b)` but should be broadcasted only when `lock (b)` is finalized on-chain.
pub trait Buyable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>:
    Transaction<Px, Out, Amt>
    + Broadcastable<Tx>
    + Linkable<Out>
    + Witnessable<Ms, Pk, Si>
    + Chainable<Px, Out, Amt>
where
    Out: Eq,
{
    /// Creates a new `buy (c)` transaction based on the `lock (b)` transaction and the data needed
    /// for sending the funds to the buyer (i.e. the destination address). Return a new `buy (c)`
    /// transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Lockable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>,
        lock: DataLock<Ti, Pk>,
        destination_target: Addr,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Verifies that the transaction is compliant with the protocol requirements and implements
    /// the correct conditions of the [`DataLock`] and the destination address.
    fn verify_template(&self, destination_target: Addr) -> Result<(), Error>;

    /// Extract the valuable witness from a transaction.
    fn extract_witness(tx: Tx) -> Si;

    /// Return the Farcaster transaction identifier.
    fn get_label(&self) -> TxLabel {
        TxLabel::Buy
    }
}

/// Represent a cancelable transaction such as the `cancel (d)` transaction that consumes the `lock
/// (b)` transaction and creates a new punishable lock, i.e. a lock with a consensus path and an
/// unilateral path available after some defined timelaps. This transaction becomes available after
/// the define timelock in `lock (b)`.
pub trait Cancelable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>:
    Transaction<Px, Out, Amt>
    + Broadcastable<Tx>
    + Linkable<Out>
    + Witnessable<Ms, Pk, Si>
    + Chainable<Px, Out, Amt>
where
    Out: Eq,
{
    /// Creates a new `cancel (d)` transaction based on the `lock (b)` transaction and the data
    /// needed for creating the lock primitive (i.e. the timelock and the keys). Return a new
    /// `cancel (d)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Lockable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>,
        lock: DataLock<Ti, Pk>,
        punish_lock: DataPunishableLock<Ti, Pk>,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Verifies that the transaction is compliant with the protocol requirements and implements
    /// the correct conditions of the [`DataLock`] and the [`DataPunishableLock`].
    fn verify_template(
        &self,
        lock: DataLock<Ti, Pk>,
        punish_lock: DataPunishableLock<Ti, Pk>,
    ) -> Result<(), Error>;

    /// Return the Farcaster transaction identifier.
    fn get_label(&self) -> TxLabel {
        TxLabel::Cancel
    }
}

/// Represent a refundable transaction such as the `refund (e)` transaction that consumes the
/// `cancel (d)` transaction and send the money to its original owner. This transaction is directly
/// available but should be broadcasted only after 'finalization' of `cancel (d)` on-chain.
pub trait Refundable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>:
    Transaction<Px, Out, Amt>
    + Broadcastable<Tx>
    + Linkable<Out>
    + Witnessable<Ms, Pk, Si>
    + Chainable<Px, Out, Amt>
where
    Out: Eq,
{
    /// Creates a new `refund (e)` transaction based on the `cancel (d)` transaction and the data
    /// needed for refunding the funds (i.e. the refund address). Return a new `refund (e)`
    /// transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Cancelable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>,
        refund_target: Addr,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Verifies that the transaction is compliant with the protocol requirements and implements
    /// the correct conditions of the [`DataPunishableLock`] and the refund address.
    fn verify_template(&self, refund_target: Addr) -> Result<(), Error>;

    /// Extract the valuable witness from a transaction.
    fn extract_witness(tx: Tx) -> Si;

    /// Return the Farcaster transaction identifier.
    fn get_label(&self) -> TxLabel {
        TxLabel::Refund
    }
}

/// Represent a punishable transaction such as the `punish (f)` transaction that consumes the
/// `cancel (d)` transaction and send the money to the counter-party, the original buyer, but do
/// not reveal the secret needed to unlock the counter-party funds, effectivelly punishing the
/// missbehaving participant.  This transaction becomes available after the define timelock in
/// `cancel (d)`.
///
/// # Verify template
///
/// This transaction does not have a `verify_template` function as it is created unilaterally and
/// thus is fully trusted by the creator.
pub trait Punishable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>:
    Transaction<Px, Out, Amt>
    + Broadcastable<Tx>
    + Linkable<Out>
    + Witnessable<Ms, Pk, Si>
    + Chainable<Px, Out, Amt>
where
    Out: Eq,
{
    /// Creates a new `punish (f)` transaction based on the `cancel (d)` transaction and the data
    /// needed for punishing the counter-party (i.e. the same address as the buyer). Return a new
    /// `punish (f)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Cancelable<Addr, Tx, Px, Out, Amt, Ti, Ms, Pk, Si>,
        punish_lock: DataPunishableLock<Ti, Pk>,
        destination_target: Addr,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Return the Farcaster transaction identifier.
    fn get_label(&self) -> TxLabel {
        TxLabel::Punish
    }
}
