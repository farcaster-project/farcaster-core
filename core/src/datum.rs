//! Datum messages exchanged between client and daemon to update their states. They carry the data
//! and extra attributes/ids to identify them.

use strict_encoding::{strict_deserialize, strict_serialize, StrictDecode, StrictEncode};

use crate::blockchain::{Address, Fee, FeeStrategy, Onchain, Timelock};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{self, Keys, SharedPrivateKeys, Signatures};
use crate::role::{Acc, Arbitrating, SwapRole};
use crate::swap::Swap;
use crate::transaction::TxId;

use std::io;

#[derive(Debug, Clone, StrictDecode, StrictEncode)]
pub enum TransactionType<T>
where
    T: Onchain,
{
    Transaction(T::Transaction),
    PartialTransaction(T::PartialTransaction),
}

impl<T> TransactionType<T>
where
    T: Onchain,
{
    pub fn try_into_transaction(&self) -> Result<T::Transaction, consensus::Error> {
        match self {
            TransactionType::Transaction(tx) => Ok(tx.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_partial_transaction(&self) -> Result<T::PartialTransaction, consensus::Error> {
        match self {
            TransactionType::PartialTransaction(tx) => Ok(tx.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }
}

/// The transaction datum is used to convey a transaction between clients and daemons. The
/// transaction is transmitted within the tx_value field in its serialized format.
#[derive(Debug, Clone)]
pub struct Transaction<T>
where
    T: Onchain,
{
    /// The identifier of the transaction
    pub tx_id: TxId,
    /// The transaction to serialize
    pub tx_value: TransactionType<T>,
}

macro_rules! impl_new_tx {
    ( seen, $fnname:ident, $type:expr ) => {
        pub fn $fnname(tx_value: T::Transaction) -> Self {
            Self {
                tx_id: $type,
                tx_value: TransactionType::Transaction(tx_value),
            }
        }
    };
    ( $fnname:ident, $type:expr ) => {
        pub fn $fnname(tx_value: T::PartialTransaction) -> Self {
            Self {
                tx_id: $type,
                tx_value: TransactionType::PartialTransaction(tx_value),
            }
        }
    };
}

impl<T> Transaction<T>
where
    T: Onchain,
{
    pub fn tx_id(&self) -> TxId {
        self.tx_id
    }

    pub fn tx(&self) -> &TransactionType<T> {
        &self.tx_value
    }

    pub fn to_tx(self) -> TransactionType<T> {
        self.tx_value
    }

    impl_new_tx!(seen, new_funding_seen, TxId::Funding);
    impl_new_tx!(seen, new_lock_seen, TxId::Lock);
    impl_new_tx!(seen, new_buy_seen, TxId::Buy);
    impl_new_tx!(seen, new_cancel_seen, TxId::Cancel);
    impl_new_tx!(seen, new_refund_seen, TxId::Refund);
    impl_new_tx!(seen, new_punish_seen, TxId::Punish);

    impl_new_tx!(new_lock, TxId::Lock);
    impl_new_tx!(new_buy, TxId::Buy);
    impl_new_tx!(new_cancel, TxId::Cancel);
    impl_new_tx!(new_refund, TxId::Refund);
    impl_new_tx!(new_punish, TxId::Punish);
}

impl<T> Encodable for Transaction<T>
where
    T: Onchain,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let len = self.tx_id.consensus_encode(writer)?;
        let tx_value = strict_serialize(&self.tx_value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to encode the transaction value",
            )
        })?;
        Ok(len + tx_value.consensus_encode(writer)?)
    }
}

impl<T> Decodable for Transaction<T>
where
    T: Onchain,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let tx_id = Decodable::consensus_decode(d)?;
        let bytes: Vec<u8> = Decodable::consensus_decode(d)?;
        let tx_value = strict_deserialize(&bytes)?;
        Ok(Self { tx_id, tx_value })
    }
}

impl<T> StrictEncode for Transaction<T>
where
    T: Onchain,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<T> StrictDecode for Transaction<T>
where
    T: Onchain,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(
                "Failed to decode the transaction datum".to_string(),
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyId {
    AliceBuy,
    AliceCancel,
    AliceRefund,
    AlicePunish,
    AliceAdaptor,
    AliceSpend,
    AlicePrivateView,
    BobFund,
    BobBuy,
    BobCancel,
    BobRefund,
    BobAdaptor,
    BobSpend,
    BobPrivateView,
}

impl Encodable for KeyId {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            KeyId::AliceBuy => 0x01u16.consensus_encode(writer),
            KeyId::AliceCancel => 0x02u16.consensus_encode(writer),
            KeyId::AliceRefund => 0x03u16.consensus_encode(writer),
            KeyId::AlicePunish => 0x04u16.consensus_encode(writer),
            KeyId::AliceAdaptor => 0x05u16.consensus_encode(writer),
            KeyId::AliceSpend => 0x06u16.consensus_encode(writer),
            KeyId::AlicePrivateView => 0x07u16.consensus_encode(writer),
            KeyId::BobFund => 0x08u16.consensus_encode(writer),
            KeyId::BobBuy => 0x09u16.consensus_encode(writer),
            KeyId::BobCancel => 0x0au16.consensus_encode(writer),
            KeyId::BobRefund => 0x0bu16.consensus_encode(writer),
            KeyId::BobAdaptor => 0x0cu16.consensus_encode(writer),
            KeyId::BobSpend => 0x0du16.consensus_encode(writer),
            KeyId::BobPrivateView => 0x0eu16.consensus_encode(writer),
        }
    }
}

impl Decodable for KeyId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u16 => Ok(KeyId::AliceBuy),
            0x02u16 => Ok(KeyId::AliceCancel),
            0x03u16 => Ok(KeyId::AliceRefund),
            0x04u16 => Ok(KeyId::AlicePunish),
            0x05u16 => Ok(KeyId::AliceAdaptor),
            0x06u16 => Ok(KeyId::AliceSpend),
            0x07u16 => Ok(KeyId::AlicePrivateView),
            0x08u16 => Ok(KeyId::BobFund),
            0x09u16 => Ok(KeyId::BobBuy),
            0x0au16 => Ok(KeyId::BobCancel),
            0x0bu16 => Ok(KeyId::BobRefund),
            0x0cu16 => Ok(KeyId::BobAdaptor),
            0x0du16 => Ok(KeyId::BobSpend),
            0x0eu16 => Ok(KeyId::BobPrivateView),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// The key datum is used to convey keys between clients and daemons. The key is transmitted within
/// the key_value field in its serialized format and is identified by the key_id.
#[derive(Clone, Debug, PartialEq)]
pub struct Key<Ctx: Swap> {
    /// The identifier of the key
    pub key_id: KeyId,
    /// The key to serialize
    pub key_value: crypto::KeyType<Ctx>,
}

macro_rules! impl_new_key {
    ( ar, $fnname:ident, $type:expr ) => {
        pub fn $fnname(key_value: <Ctx::Ar as Keys>::PublicKey) -> Self {
            Self {
                key_id: $type,
                key_value: crypto::KeyType::PublicArbitrating(key_value),
            }
        }
    };
    ( ac, $fnname:ident, $type:expr ) => {
        pub fn $fnname(key_value: <Ctx::Ac as Keys>::PublicKey) -> Self {
            Self {
                key_id: $type,
                key_value: crypto::KeyType::PublicAccordant(key_value),
            }
        }
    };
    ( sp, $fnname:ident, $type:expr ) => {
        pub fn $fnname(key_value: <Ctx::Ac as SharedPrivateKeys<Acc>>::SharedPrivateKey) -> Self {
            Self {
                key_id: $type,
                key_value: crypto::KeyType::SharedPrivate(key_value),
            }
        }
    };
}

impl<Ctx> Key<Ctx>
where
    Ctx: Swap,
{
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn key(&self) -> &crypto::KeyType<Ctx> {
        &self.key_value
    }

    pub fn to_key(self) -> crypto::KeyType<Ctx> {
        self.key_value
    }

    impl_new_key!(ar, new_alice_buy, KeyId::AliceBuy);
    impl_new_key!(ar, new_alice_cancel, KeyId::AliceCancel);
    impl_new_key!(ar, new_alice_refund, KeyId::AliceRefund);
    impl_new_key!(ar, new_alice_punish, KeyId::AlicePunish);
    impl_new_key!(ar, new_alice_adaptor, KeyId::AliceAdaptor);
    impl_new_key!(ac, new_alice_spend, KeyId::AliceSpend);
    impl_new_key!(sp, new_alice_private_view, KeyId::AlicePrivateView);

    impl_new_key!(ar, new_bob_fund, KeyId::BobFund);
    impl_new_key!(ar, new_bob_buy, KeyId::BobBuy);
    impl_new_key!(ar, new_bob_cancel, KeyId::BobCancel);
    impl_new_key!(ar, new_bob_refund, KeyId::BobRefund);
    impl_new_key!(ar, new_bob_adaptor, KeyId::BobAdaptor);
    impl_new_key!(ac, new_bob_spend, KeyId::BobSpend);
    impl_new_key!(sp, new_bob_private_view, KeyId::BobPrivateView);
}

impl<Ctx> Encodable for Key<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let len = self.key_id.consensus_encode(writer)?;
        let key_value = dbg!(strict_serialize(&self.key_value).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Failed to encode the key value")
        })?);
        Ok(len + key_value.consensus_encode(writer)?)
    }
}

impl<Ctx> Decodable for Key<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let key_id = Decodable::consensus_decode(d)?;
        let bytes: Vec<u8> = dbg!(Decodable::consensus_decode(d)?);
        let key_value = dbg!(strict_deserialize(&bytes)?);
        Ok(Self { key_id, key_value })
    }
}

impl<Ctx> StrictEncode for Key<Ctx>
where
    Ctx: Swap,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<Ctx> StrictDecode for Key<Ctx>
where
    Ctx: Swap,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError("Failed to decode the key datum".to_string())
        })
    }
}

/// The signature datum is used to convey signatures between clients and daemons. When this datum
/// comes from a client, it is usually a signature freshly generated or adapted by the client. When
/// the datum is emitted by the daemon to the client, it is usually an adaptor signature to be
/// adapted by the client.
#[derive(Debug, Clone)]
pub struct Signature<S>
where
    S: Signatures,
{
    /// The identifier of the related transaction
    pub tx_id: TxId,
    /// The swap role that emitted the signature
    pub role: SwapRole,
    /// The signature to serialize, the signature can be a adaptor, adapted, or regular signature
    pub sig_value: crypto::SignatureType<S>,
}

impl<S> Signature<S>
where
    S: Signatures,
{
    pub fn new(tx_id: TxId, role: SwapRole, sig_value: crypto::SignatureType<S>) -> Self {
        Self {
            tx_id,
            role,
            sig_value,
        }
    }

    pub fn tx_id(&self) -> TxId {
        self.tx_id
    }

    pub fn role(&self) -> SwapRole {
        self.role
    }

    pub fn signature(&self) -> &crypto::SignatureType<S> {
        &self.sig_value
    }

    pub fn to_signature(self) -> crypto::SignatureType<S> {
        self.sig_value
    }
}

impl<S> Encodable for Signature<S>
where
    S: Signatures,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.tx_id.consensus_encode(writer)?;
        len += self.role.consensus_encode(writer)?;
        let sig_value = strict_serialize(&self.sig_value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to encode the signature value",
            )
        })?;
        Ok(len + sig_value.consensus_encode(writer)?)
    }
}

impl<S> Decodable for Signature<S>
where
    S: Signatures,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let tx_id = Decodable::consensus_decode(d)?;
        let role = Decodable::consensus_decode(d)?;
        let bytes: Vec<u8> = Decodable::consensus_decode(d)?;
        let sig_value = strict_deserialize(&bytes)?;
        Ok(Self {
            tx_id,
            role,
            sig_value,
        })
    }
}

impl<S> StrictEncode for Signature<S>
where
    S: Signatures,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<S> StrictDecode for Signature<S>
where
    S: Signatures,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(
                "Failed to decode the signature datum".to_string(),
            )
        })
    }
}

#[derive(Clone, Debug, Copy)]
pub enum ProofId {
    CrossGroupDleq,
}

impl Encodable for ProofId {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            ProofId::CrossGroupDleq => 0x01u16.consensus_encode(writer),
        }
    }
}

impl Decodable for ProofId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u16 => Ok(ProofId::CrossGroupDleq),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// The proof datum is used by clients to provides cryptographic proofs needed to secure the
/// protocol.
#[derive(Clone, Debug)]
pub struct Proof<Ctx: Swap> {
    /// The identifier of the proof
    pub proof_id: ProofId,
    /// The proof to serialize
    pub proof_value: Ctx::Proof,
}

impl<Ctx> Proof<Ctx>
where
    Ctx: Swap,
{
    pub fn new_cross_group_dleq(proof_value: Ctx::Proof) -> Self {
        Self {
            proof_id: ProofId::CrossGroupDleq,
            proof_value,
        }
    }

    pub fn proof_id(&self) -> ProofId {
        self.proof_id
    }

    pub fn proof(&self) -> &Ctx::Proof {
        &self.proof_value
    }

    pub fn to_proof(self) -> Ctx::Proof {
        self.proof_value
    }
}

impl<Ctx> Encodable for Proof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let len = self.proof_id.consensus_encode(writer)?;
        let proof_value = strict_serialize(&self.proof_value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to encode the proof value",
            )
        })?;
        Ok(len + proof_value.consensus_encode(writer)?)
    }
}

impl<Ctx> Decodable for Proof<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let proof_id = Decodable::consensus_decode(d)?;
        let bytes: Vec<u8> = Decodable::consensus_decode(d)?;
        let proof_value = strict_deserialize(&bytes)?;
        Ok(Self {
            proof_id,
            proof_value,
        })
    }
}

impl<Ctx> StrictEncode for Proof<Ctx>
where
    Ctx: Swap,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<Ctx> StrictDecode for Proof<Ctx>
where
    Ctx: Swap,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(
                "Failed to decode the proof datum".to_string(),
            )
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ParameterId {
    DestinationAddress,
    RefundAddress,
    CancelTimelock,
    PunishTimelock,
    FeeStrategy,
}

impl Encodable for ParameterId {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            ParameterId::DestinationAddress => 0x01u16.consensus_encode(writer),
            ParameterId::RefundAddress => 0x02u16.consensus_encode(writer),
            ParameterId::CancelTimelock => 0x03u16.consensus_encode(writer),
            ParameterId::PunishTimelock => 0x04u16.consensus_encode(writer),
            ParameterId::FeeStrategy => 0x05u16.consensus_encode(writer),
        }
    }
}

impl Decodable for ParameterId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u16 => Ok(ParameterId::DestinationAddress),
            0x02u16 => Ok(ParameterId::RefundAddress),
            0x03u16 => Ok(ParameterId::CancelTimelock),
            0x04u16 => Ok(ParameterId::PunishTimelock),
            0x05u16 => Ok(ParameterId::FeeStrategy),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParameterType<T>
where
    T: Address + Timelock + Fee,
{
    Address(T::Address),
    Timelock(T::Timelock),
    FeeStrategy(FeeStrategy<T::FeeUnit>),
}

impl<T> ParameterType<T>
where
    T: Address + Timelock + Fee,
{
    pub fn try_into_address(&self) -> Result<T::Address, consensus::Error> {
        match self {
            ParameterType::Address(add) => Ok(add.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_timelock(&self) -> Result<T::Timelock, consensus::Error> {
        match self {
            ParameterType::Timelock(timelock) => Ok(timelock.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }

    pub fn try_into_fee_strategy(&self) -> Result<FeeStrategy<T::FeeUnit>, consensus::Error> {
        match self {
            ParameterType::FeeStrategy(strat) => Ok(strat.clone()),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }
}

/// The parameter datum is used to convey parameters between clients and daemons such as addresses,
/// timelocks, fee strategies, etc. They are mostly used by clients to instruct daemons about user
/// parameters and offer parameters.
#[derive(Debug, Clone)]
pub struct Parameter<T>
where
    T: Address + Timelock + Fee,
{
    /// The identifier of the parameter
    pub param_id: ParameterId,
    /// The parameter value to serialize
    pub param_value: ParameterType<T>,
}

impl<T> Parameter<T>
where
    T: Address + Timelock + Fee,
{
    pub fn param_id(&self) -> ParameterId {
        self.param_id
    }

    pub fn param(&self) -> &ParameterType<T> {
        &self.param_value
    }

    pub fn to_param(self) -> ParameterType<T> {
        self.param_value
    }

    pub fn new_destination_address(address: T::Address) -> Self {
        Self {
            param_id: ParameterId::DestinationAddress,
            param_value: ParameterType::Address(address),
        }
    }

    pub fn new_refund_address(address: T::Address) -> Self {
        Self {
            param_id: ParameterId::RefundAddress,
            param_value: ParameterType::Address(address),
        }
    }

    pub fn new_cancel_timelock(timelock: T::Timelock) -> Self {
        Self {
            param_id: ParameterId::CancelTimelock,
            param_value: ParameterType::Timelock(timelock),
        }
    }

    pub fn new_punish_timelock(timelock: T::Timelock) -> Self {
        Self {
            param_id: ParameterId::PunishTimelock,
            param_value: ParameterType::Timelock(timelock),
        }
    }

    pub fn new_fee_strategy(strategy: FeeStrategy<T::FeeUnit>) -> Self {
        Self {
            param_id: ParameterId::FeeStrategy,
            param_value: ParameterType::FeeStrategy(strategy),
        }
    }
}

impl<T> Encodable for Parameter<T>
where
    T: Address + Timelock + Fee,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let len = self.param_id.consensus_encode(writer)?;
        match self.param_id {
            ParameterId::DestinationAddress | ParameterId::RefundAddress => {
                match &self.param_value {
                    ParameterType::Address(add) => Ok(len + wrap_in_vec!(wrap add in writer)),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to encode the parameter value",
                    )),
                }
            }
            ParameterId::CancelTimelock | ParameterId::PunishTimelock => match &self.param_value {
                ParameterType::Timelock(timelock) => {
                    Ok(len + wrap_in_vec!(wrap timelock in writer))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to encode the parameter value",
                )),
            },
            ParameterId::FeeStrategy => match &self.param_value {
                ParameterType::FeeStrategy(strat) => Ok(len + wrap_in_vec!(wrap strat in writer)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to encode the parameter value",
                )),
            },
        }
    }
}

impl<T> Decodable for Parameter<T>
where
    T: Address + Timelock + Fee,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let param_id = Decodable::consensus_decode(d)?;
        let param_value = match param_id {
            ParameterId::DestinationAddress | ParameterId::RefundAddress => {
                let add = unwrap_from_vec!(d);
                ParameterType::Address(add)
            }
            ParameterId::CancelTimelock | ParameterId::PunishTimelock => {
                let timelock = unwrap_from_vec!(d);
                ParameterType::Timelock(timelock)
            }
            ParameterId::FeeStrategy => {
                let strat = unwrap_from_vec!(d);
                ParameterType::FeeStrategy(strat)
            }
        };
        Ok(Self {
            param_id,
            param_value,
        })
    }
}

impl<T> StrictEncode for Parameter<T>
where
    T: Arbitrating + Fee,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<T> StrictDecode for Parameter<T>
where
    T: Address + Timelock + Fee,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(
                "Failed to decode the parameter datum".to_string(),
            )
        })
    }
}
