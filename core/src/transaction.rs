//! Arbitrating transaction module

use std::error;
use std::fmt::Debug;
use std::io;

use thiserror::Error;

use crate::blockchain::{Address, Fee, FeePolitic, FeeStrategy, Network, Onchain, Timelock};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{Keys, Signatures};
use crate::script;

/// A list specifying general categories of transaction error.
#[derive(Error, Debug)]
pub enum Error {
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
pub trait Transaction<T>: Debug
where
    T: Onchain,
    Self: Sized,
{
    /// Returns a mutable reference to the inner partial transaction data.
    fn partial_mut(&mut self) -> &mut T::PartialTransaction;

    /// Extract the transaction in the defined partial format on the arbitrating blockchain. The
    /// partial format is used to exchange unsigned or patially signed transactions.
    fn to_partial(self) -> T::PartialTransaction;

    /// Construct the transaction type from a deserialized partial transaction.
    fn from_partial(partial: T::PartialTransaction) -> Self;
}

/// Defines the transaction IDs for serialization and network communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl Encodable for TxId {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            TxId::Funding => 0x01u16.consensus_encode(writer),
            TxId::Lock => 0x02u16.consensus_encode(writer),
            TxId::Buy => 0x03u16.consensus_encode(writer),
            TxId::Cancel => 0x04u16.consensus_encode(writer),
            TxId::Refund => 0x05u16.consensus_encode(writer),
            TxId::Punish => 0x06u16.consensus_encode(writer),
        }
    }
}

impl Decodable for TxId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u16 => Ok(TxId::Funding),
            0x02u16 => Ok(TxId::Lock),
            0x03u16 => Ok(TxId::Buy),
            0x04u16 => Ok(TxId::Cancel),
            0x05u16 => Ok(TxId::Refund),
            0x06u16 => Ok(TxId::Punish),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// Transaction that requries multiple participants to construct and finalize the transaction.
pub trait Witnessable<T>
where
    T: Keys + Signatures,
    Self: Sized,
{
    /// Add a cooperation to the transaction and store it internally for later usage.
    fn add_witness(&mut self, pubkey: T::PublicKey, sig: T::Signature) -> Result<(), Error>;
}

/// Define a transaction that must have a finalization step.
pub trait Finalizable {
    /// Finalize the internal transaction and make it ready for extraction.
    fn finalize(&mut self) -> Result<(), Error>;
}

/// Define a transaction broadcastable by the system. Externally managed transaction are not
/// broadcastable.
pub trait Broadcastable<T>: Finalizable
where
    T: Onchain,
    Self: Sized,
{
    /// Extract the finalized transaction and return a fully signed transaction type as defined in
    /// the arbitrating blockchain. Used before broadcasting the transaction on-chain.
    ///
    /// This correspond to the "role" of a "finalizer" as defined in BIP 174 for dealing with
    /// partial transactions, which can be applied more generically than just Bitcoin.
    fn extract(&self) -> T::Transaction;

    /// Finalize the internal transaction and extract it, ready to be broadcasted.
    fn finalize_and_extract(&mut self) -> Result<T::Transaction, Error> {
        // TODO maybe do more validation based on other traits
        self.finalize()?;
        Ok(self.extract())
    }
}

/// Implemented by transactions that can be link to form chains of logic. A linkable transaction
/// can provide the data needed for other transaction to safely build on top of it.
///
/// `O`, the returned type of the consumable output, used to reference the funds and chain other
/// transactions on it. This must contain all necessary data to latter create a valid unlocking
/// witness for the output.
pub trait Linkable<O>
where
    Self: Sized,
{
    /// Return the consumable output of this transaction. The output does not contain the witness
    /// data allowing spending the output, only the data that points to the consumable output and
    /// the data necessary to produce a valid unlocking witness.
    ///
    /// This correspond to data an "updater" such as defined in BIP 174 can use to update a
    /// partial transaction. This is used to get all data needed to describe this output as an
    /// input in another transaction.
    fn get_consumable_output(&self) -> Result<O, Error>;
}

// TODO change errors for crypto::errors for signable adaptor and forkable

/// Implemented on transactions that can be signed by a normal private key and generate/validate a
/// valid signature.
pub trait Signable<T>
where
    T: Keys + Signatures,
    Self: Sized,
{
    /// Generate the witness to unlock the default path of the locked asset.
    fn generate_witness(&self, privkey: &T::PrivateKey) -> Result<T::Signature, Error>;

    /// Verify that the signature is valid to unlock the default path of the locked asset.
    fn verify_witness(&self, pubkey: &T::PublicKey, sig: T::Signature) -> Result<(), Error>;
}

/// Implemented on transactions that can be signed by a private key and an adaptor key.
pub trait AdaptorSignable<T>
where
    T: Keys + Signatures,
    Self: Sized,
{
    /// Generate the adaptor witness to unlock the default path of the locked asset.
    fn generate_adaptor_witness(
        &self,
        privkey: &T::PrivateKey,
        adaptor: &T::PublicKey,
    ) -> Result<T::AdaptorSignature, Error>;

    /// Verify that the adaptor signature is valid to unlock the default path of the locked asset.
    fn verify_adaptor_witness(
        &self,
        pubkey: &T::PublicKey,
        adaptor: &T::PublicKey,
        sig: T::AdaptorSignature,
    ) -> Result<(), Error>;
}

/// Defines a transaction where the consumable output has two paths: a successful path and a
/// failure path and generate witnesses for the second path.
pub trait Forkable<T>
where
    T: Keys + Signatures,
    Self: Sized,
{
    /// Generates the witness used to unlock the second path of the asset lock, i.e. the failure
    /// path.
    fn generate_failure_witness(&self, privkey: &T::PrivateKey) -> Result<T::Signature, Error>;

    /// Verify that the signature is valid to unlock the second path of of the locked asset, i.e.
    /// the failure path.
    fn verify_failure_witness(&self, pubkey: &T::PublicKey, sig: T::Signature)
        -> Result<(), Error>;
}

/// Fundable is NOT a transaction generated by this library but the funds that arrived in the
/// generated address are controlled by the system. This trait allows to inject assets in the
/// system.
pub trait Fundable<T, O>: Linkable<O>
where
    T: Address + Keys + Signatures + Onchain,
    Self: Sized,
{
    /// Create a new funding 'output', or equivalent depending on the blockchain and the
    /// cryptographic engine.
    fn initialize(pubkey: T::PublicKey, network: Network) -> Result<Self, Error>;

    /// Return the address to use for the funding.
    fn get_address(&self) -> Result<T::Address, Error>;

    /// Update the transaction, this is used to update the data when the funding transaction is
    /// seen on-chain.
    ///
    /// This function is needed because we assume that the transaction is created outside of the
    /// system by an external wallet, the txid is not known in advance.
    fn update(&mut self, tx: T::Transaction) -> Result<(), Error>;

    /// Create a raw funding structure based only on the transaction seen on-chain.
    fn raw(tx: T::Transaction) -> Result<Self, Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Funding
    }
}

/// Represent a lockable transaction such as the `lock (b)` transaction that consumes the `funding
/// (a)` transaction and creates the scripts used by `buy (c)` and `cancel (d)` transactions.
pub trait Lockable<T, O>:
    Transaction<T> + Signable<T> + Broadcastable<T> + Linkable<O> + Witnessable<T>
where
    T: Keys + Address + Timelock + Signatures + Fee,
    Self: Sized,
{
    /// Creates a new `lock (b)` transaction based on the `funding (a)` transaction and the data
    /// needed for creating the lock primitive (i.e. the timelock and the keys). Return a new `lock
    /// (b)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Fundable<T, O>,
        lock: script::DataLock<T>,
        fee_strategy: &FeeStrategy<T::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Lock
    }
}

/// Represent a buyable transaction such as the `buy (c)` transaction that consumes the `lock (b)`
/// transaction and transfer the funds to the buyer while revealing the secret needed to the seller
/// to take ownership of the counter-party funds. This transaction becomes available directly after
/// `lock (b)` but should be broadcasted only when `lock (b)` is finalized on-chain.
pub trait Buyable<T, O>:
    Transaction<T> + Signable<T> + AdaptorSignable<T> + Broadcastable<T> + Linkable<O> + Witnessable<T>
where
    T: Keys + Address + Timelock + Fee + Signatures,
    Self: Sized,
{
    /// Creates a new `buy (c)` transaction based on the `lock (b)` transaction and the data needed
    /// for sending the funds to the buyer (i.e. the destination address). Return a new `buy (c)`
    /// transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Lockable<T, O>,
        lock: script::DataLock<T>,
        destination_target: T::Address,
        fee_strategy: &FeeStrategy<T::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Buy
    }
}

/// Represent a cancelable transaction such as the `cancel (d)` transaction that consumes the `lock
/// (b)` transaction and creates a new punishable lock, i.e. a lock with a consensus path and an
/// unilateral path available after some defined timelaps. This transaction becomes available after
/// the define timelock in `lock (b)`.
pub trait Cancelable<T, O>:
    Transaction<T> + Forkable<T> + Broadcastable<T> + Linkable<O> + Witnessable<T>
where
    T: Keys + Address + Timelock + Fee + Signatures,
    Self: Sized,
{
    /// Creates a new `cancel (d)` transaction based on the `lock (b)` transaction and the data
    /// needed for creating the lock primitive (i.e. the timelock and the keys). Return a new
    /// `cancel (d)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Lockable<T, O>,
        lock: script::DataLock<T>,
        punish_lock: script::DataPunishableLock<T>,
        fee_strategy: &FeeStrategy<T::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Cancel
    }
}

/// Represent a refundable transaction such as the `refund (e)` transaction that consumes the
/// `cancel (d)` transaction and send the money to its original owner. This transaction is directly
/// available but should be broadcasted only after 'finalization' of `cancel (d)` on-chain.
pub trait Refundable<T, O>:
    Transaction<T> + Signable<T> + AdaptorSignable<T> + Broadcastable<T> + Linkable<O> + Witnessable<T>
where
    T: Keys + Address + Timelock + Fee + Signatures,
    Self: Sized,
{
    /// Creates a new `refund (e)` transaction based on the `cancel (d)` transaction and the data
    /// needed for refunding the funds (i.e. the refund address). Return a new `refund (e)`
    /// transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Cancelable<T, O>,
        punish_lock: script::DataPunishableLock<T>,
        refund_target: T::Address,
        fee_strategy: &FeeStrategy<T::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error>;

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
pub trait Punishable<T, O>:
    Transaction<T> + Forkable<T> + Broadcastable<T> + Linkable<O> + Witnessable<T>
where
    T: Keys + Address + Timelock + Fee + Signatures,
    Self: Sized,
{
    /// Creates a new `punish (f)` transaction based on the `cancel (d)` transaction and the data
    /// needed for punishing the counter-party (i.e. the same address as the buyer). Return a new
    /// `punish (f)` transaction.
    ///
    /// This correspond to the "creator" and initial "updater" roles in BIP 174. Creates a new
    /// transaction and fill the inputs and outputs data.
    fn initialize(
        prev: &impl Cancelable<T, O>,
        punish_lock: script::DataPunishableLock<T>,
        destination_target: T::Address,
        fee_strategy: &FeeStrategy<T::FeeUnit>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error>;

    /// Return the Farcaster transaction identifier.
    fn get_id(&self) -> TxId {
        TxId::Punish
    }
}
