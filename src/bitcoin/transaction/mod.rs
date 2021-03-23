use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
use bitcoin::hashes::sha256d::Hash;
use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin::secp256k1::{Message, Secp256k1, SerializedSignature, Signing};
use bitcoin::util::address::{self, Address};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::{self, PartiallySignedTransaction};

use crate::bitcoin::{Bitcoin, SatPerVByte, PDLEQ};
use crate::blockchain::{Fee, FeePolitic, FeeStrategy, FeeStrategyError, Network};
use crate::script;
use crate::transaction::{
    AdaptorSignable, Broadcastable, Buyable, Cancelable, Failable, Forkable, Fundable, Linkable,
    Lockable, Punishable, Refundable, Signable, Transaction,
};

#[derive(Debug)]
pub struct Funding {
    pubkey: PublicKey,
    seen_tx: Option<bitcoin::blockdata::transaction::Transaction>,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    MultiUTXOUnsuported,
    MissingWitnessUTXO,
    MissingSigHashType,
    PSBT(psbt::Error),
    Address(address::Error),
    Fee(FeeStrategyError),
    Secp256k1(bitcoin::secp256k1::Error),
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Self {
        Self::PSBT(e)
    }
}

impl From<address::Error> for Error {
    fn from(e: address::Error) -> Self {
        Self::Address(e)
    }
}

impl From<FeeStrategyError> for Error {
    fn from(e: FeeStrategyError) -> Self {
        Self::Fee(e)
    }
}

impl Failable for Funding {
    type Error = Error;
}

#[derive(Debug)]
pub struct MetadataFundingOutput {
    pub out_point: OutPoint,
    pub tx_out: TxOut,
}

impl Linkable<Bitcoin> for Funding {
    type Output = MetadataFundingOutput;

    fn get_consumable_output(&self) -> Result<MetadataFundingOutput, Error> {
        match &self.seen_tx {
            Some(t) => {
                // More than one UTXO is not supported
                match t.output.len() {
                    1 => (),
                    2 =>
                    // Check if coinbase transaction
                    {
                        if !t.is_coin_base() {
                            return Err(Error::MultiUTXOUnsuported);
                        }
                    }
                    _ => return Err(Error::MultiUTXOUnsuported),
                }
                // vout is always 0 because output len is 1
                Ok(MetadataFundingOutput {
                    out_point: OutPoint::new(t.txid(), 0),
                    tx_out: t.output[0].clone(),
                })
            }
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(Error::MultiUTXOUnsuported),
        }
    }
}

impl Fundable<Bitcoin> for Funding {
    fn initialize(pubkey: PublicKey) -> Result<Self, Error> {
        Ok(Funding {
            pubkey,
            seen_tx: None,
        })
    }

    fn get_address(&self, network: Network) -> Result<Address, Error> {
        match network {
            Network::Mainnet => Ok(Address::p2wpkh(&self.pubkey, BtcNetwork::Bitcoin)?),
            Network::Testnet => Ok(Address::p2wpkh(&self.pubkey, BtcNetwork::Testnet)?),
            Network::Local => Ok(Address::p2wpkh(&self.pubkey, BtcNetwork::Regtest)?),
        }
    }

    fn update(&mut self, args: bitcoin::blockdata::transaction::Transaction) -> Result<(), Error> {
        self.seen_tx = Some(args);
        Ok(())
    }
}

pub trait SubTransaction: Debug {}

#[derive(Debug)]
pub struct Tx<T: SubTransaction> {
    psbt: PartiallySignedTransaction,
    _t: PhantomData<T>,
}

impl<T> Failable for Tx<T>
where
    T: SubTransaction,
{
    type Error = Error;
}

impl<T> Transaction<Bitcoin> for Tx<T>
where
    T: SubTransaction,
{
    fn to_partial(&self) -> Option<PartiallySignedTransaction> {
        Some(self.psbt.clone())
    }
}

impl<T> Broadcastable<Bitcoin> for Tx<T>
where
    T: SubTransaction,
{
    fn finalize(&self) -> bitcoin::blockdata::transaction::Transaction {
        self.psbt.clone().extract_tx()
    }
}

impl<T> Linkable<Bitcoin> for Tx<T>
where
    T: SubTransaction,
{
    type Output = MetadataFundingOutput;

    fn get_consumable_output(&self) -> Result<MetadataFundingOutput, Error> {
        match self.psbt.global.unsigned_tx.output.len() {
            1 => (),
            2 => {
                if !self.psbt.global.unsigned_tx.is_coin_base() {
                    return Err(Error::MultiUTXOUnsuported);
                }
            }
            _ => return Err(Error::MultiUTXOUnsuported),
        }

        Ok(MetadataFundingOutput {
            out_point: OutPoint::new(self.psbt.global.unsigned_tx.txid(), 0),
            tx_out: self.psbt.global.unsigned_tx.output[0].clone(),
        })
    }
}

#[derive(Debug)]
pub struct Lock;

impl SubTransaction for Lock {}

impl Lockable<Bitcoin> for Tx<Lock> {
    /// Type returned by the impl of a Funding tx
    type Input = MetadataFundingOutput;

    fn initialize(
        prev: &impl Fundable<Bitcoin, Output = MetadataFundingOutput, Error = Error>,
        lock: script::DataLock<Bitcoin>,
        fee_strategy: &FeeStrategy<SatPerVByte>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.failure.alice)
            .push_key(&lock.failure.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: (1 << 31) as u32, // activate disable flag on CSV
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: script.to_v0_p2wsh(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

/// A borrowed reference to a transaction input.
#[derive(Debug, Copy, Clone)]
pub struct TxInRef<'a> {
    transaction: &'a bitcoin::blockdata::transaction::Transaction,
    index: usize,
}

impl<'a> TxInRef<'a> {
    /// Constructs a reference to the input with the given index of the given transaction.
    pub fn new(
        transaction: &'a bitcoin::blockdata::transaction::Transaction,
        index: usize,
    ) -> TxInRef<'a> {
        assert!(transaction.input.len() > index);
        TxInRef { transaction, index }
    }

    /// Returns a reference to the borrowed transaction.
    pub fn transaction(&self) -> &bitcoin::blockdata::transaction::Transaction {
        self.transaction
    }

    /// Returns a reference to the input.
    pub fn input(&self) -> &TxIn {
        &self.transaction.input[self.index]
    }

    /// Returns the index of input.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl<'a> AsRef<TxIn> for TxInRef<'a> {
    fn as_ref(&self) -> &TxIn {
        self.input()
    }
}

impl Signable<Bitcoin> for Tx<Lock> {
    fn generate_witness(&mut self, privkey: &PrivateKey) -> Result<SerializedSignature, Error> {
        {
            // TODO validate the transaction before signing
        }

        let mut secp = Secp256k1::new();

        let unsigned_tx = self.psbt.global.unsigned_tx.clone();
        let txin = TxInRef::new(&unsigned_tx, 0);

        let witness_utxo = self.psbt.inputs[0]
            .witness_utxo
            .clone()
            .ok_or(Error::MissingWitnessUTXO)?;
        let script = witness_utxo.script_pubkey;
        let value = witness_utxo.value;

        let sighash_type = self.psbt.inputs[0]
            .sighash_type
            .ok_or(Error::MissingSigHashType)?;

        println!("{:?}", txin);
        println!("{:?}", script);
        println!("{:?}", value);
        println!("{:?}", sighash_type);
        let sig = sign_input(&mut secp, txin, &script, value, sighash_type, &privkey.key)?;

        // Finalize the witness
        let mut full_sig = sig.clone().to_vec();
        full_sig.extend_from_slice(&[sighash_type.as_u32() as u8]);

        let pubkey = PublicKey::from_private_key(&secp, &privkey);
        self.psbt.inputs[0].final_script_witness = Some(vec![full_sig, pubkey.to_bytes()]);

        Ok(sig)
    }

    fn verify_witness(
        &mut self,
        _pubkey: &PublicKey,
        _sig: SerializedSignature,
    ) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct Buy;

impl SubTransaction for Buy {}

impl Buyable<Bitcoin> for Tx<Buy> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataFundingOutput;

    fn initialize(
        _prev: &impl Lockable<Bitcoin, Output = MetadataFundingOutput>,
        _destination_target: Address,
        _fee_strategy: &FeeStrategy<SatPerVByte>,
        _fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        todo!()
    }
}

impl Signable<Bitcoin> for Tx<Buy> {
    fn generate_witness(&mut self, _privkey: &PrivateKey) -> Result<SerializedSignature, Error> {
        {
            // TODO validate the transaction before signing
        }
        todo!()
    }

    fn verify_witness(
        &mut self,
        _pubkey: &PublicKey,
        _sig: SerializedSignature,
    ) -> Result<(), Error> {
        todo!()
    }
}

impl AdaptorSignable<Bitcoin> for Tx<Buy> {
    fn generate_adaptor_witness(
        &mut self,
        _privkey: &PrivateKey,
        _adaptor: &PublicKey,
    ) -> Result<(SerializedSignature, PublicKey, PDLEQ), Error> {
        todo!()
    }

    fn verify_adaptor_witness(
        &mut self,
        _pubkey: &PublicKey,
        _adaptor: &PublicKey,
        _sig: (SerializedSignature, PublicKey, PDLEQ),
    ) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct Cancel;

impl SubTransaction for Cancel {}

impl Cancelable<Bitcoin> for Tx<Cancel> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataFundingOutput;

    fn initialize(
        prev: &impl Lockable<Bitcoin, Output = MetadataFundingOutput, Error = Error>,
        lock: script::DataPunishableLock<Bitcoin>,
        fee_strategy: &FeeStrategy<SatPerVByte>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_key(&lock.failure)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: 4294967295,
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: script.to_v0_p2wsh(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

impl Forkable<Bitcoin> for Tx<Cancel> {
    fn generate_failure_witness(
        &mut self,
        _privkey: &PrivateKey,
    ) -> Result<SerializedSignature, Error> {
        todo!()
    }

    fn verify_failure_witness(
        &mut self,
        _pubkey: &PublicKey,
        _sig: SerializedSignature,
    ) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct Refund;

impl SubTransaction for Refund {}

impl Refundable<Bitcoin> for Tx<Refund> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataFundingOutput;

    fn initialize(
        prev: &impl Cancelable<Bitcoin, Output = MetadataFundingOutput, Error = Error>,
        refund_target: Address,
        fee_strategy: &FeeStrategy<SatPerVByte>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: 4294967295,
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: refund_target.script_pubkey(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

impl Signable<Bitcoin> for Tx<Refund> {
    fn generate_witness(&mut self, _privkey: &PrivateKey) -> Result<SerializedSignature, Error> {
        todo!()
    }

    fn verify_witness(
        &mut self,
        _pubkey: &PublicKey,
        _sig: SerializedSignature,
    ) -> Result<(), Error> {
        todo!()
    }
}

impl AdaptorSignable<Bitcoin> for Tx<Refund> {
    fn generate_adaptor_witness(
        &mut self,
        _privkey: &PrivateKey,
        _adaptor: &PublicKey,
    ) -> Result<(SerializedSignature, PublicKey, PDLEQ), Error> {
        todo!()
    }

    fn verify_adaptor_witness(
        &mut self,
        _pubkey: &PublicKey,
        _adaptor: &PublicKey,
        _sig: (SerializedSignature, PublicKey, PDLEQ),
    ) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct Punish;

impl SubTransaction for Punish {}

impl Punishable<Bitcoin> for Tx<Punish> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataFundingOutput;

    fn initialize(
        _prev: &impl Cancelable<Bitcoin, Output = MetadataFundingOutput>,
        _destination_target: Address,
        _fee_strategy: &FeeStrategy<SatPerVByte>,
        _fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        todo!()
    }
}

impl Forkable<Bitcoin> for Tx<Punish> {
    fn generate_failure_witness(
        &mut self,
        _privkey: &PrivateKey,
    ) -> Result<SerializedSignature, Error> {
        todo!()
    }

    fn verify_failure_witness(
        &mut self,
        _pubkey: &PublicKey,
        _sig: SerializedSignature,
    ) -> Result<(), Error> {
        todo!()
    }
}

/// Computes the [`BIP-143`][bip-143] compliant sighash for a [`SIGHASH_ALL`][sighash_all]
/// signature for the given input.
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
/// [sighash_all]: https://bitcoin.org/en/developer-guide#signature-hash-types
pub fn signature_hash<'a>(
    txin: TxInRef<'a>,
    script: &Script,
    value: u64,
    sighash_type: SigHashType,
) -> Hash {
    SigHashCache::new(txin.transaction)
        .signature_hash(txin.index, script, value, sighash_type)
        .as_hash()
}

/// Computes the [`BIP-143`][bip-143] compliant signature for the given input.
/// [Read more...][signature-hash]
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
/// [signature-hash]: fn.signature_hash.html
pub fn sign_input<'a, C>(
    context: &mut Secp256k1<C>,
    txin: TxInRef<'a>,
    script: &Script,
    value: u64,
    sighash_type: SigHashType,
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> Result<SerializedSignature, bitcoin::secp256k1::Error>
where
    C: Signing,
{
    // Computes sighash.
    let sighash = signature_hash(txin, script, value, sighash_type);
    // Makes signature.
    let msg = Message::from_slice(&sighash[..])?;
    let mut sig = context.sign(&msg, secret_key);
    sig.normalize_s();
    Ok(sig.serialize_der())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{CSVTimelock, SatPerVByte};
    use crate::blockchain::FeeStrategy;
    use crate::script::DoubleKeys;

    use bitcoin::blockdata::script::Script;
    use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::key::{PrivateKey, PublicKey};
    use bitcoin::Transaction;

    #[test]
    fn create_funding_generic() {
        let secp = Secp256k1::new();

        let privkey: PrivateKey =
            PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
        let pubkey = PublicKey::from_private_key(&secp, &privkey);

        let mut funding = Funding::initialize(pubkey).unwrap();

        let funding_tx_seen = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_hex(
                        "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                    )
                    .unwrap(),
                    vout: 1,
                },
                script_sig: Script::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")
                    .unwrap(),
                sequence: 4294967295,
                witness: vec![Vec::from_hex(
                    "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105",
                )
                .unwrap()],
            }],
            output: vec![TxOut {
                value: 10_000_000,
                script_pubkey: Script::new_v0_wpkh(&pubkey.wpubkey_hash().unwrap()),
            }],
        };
        funding.update(funding_tx_seen).unwrap();

        let datalock = script::DataLock {
            timelock: CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey, pubkey),
            failure: DoubleKeys::new(pubkey, pubkey),
        };

        let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(20));
        let politic = FeePolitic::Aggressive;

        let mut lock = Tx::<Lock>::initialize(&funding, datalock, &fee, politic).unwrap();

        let datapunishablelock = script::DataPunishableLock {
            timelock: CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey, pubkey),
            failure: pubkey,
        };
        let cancel = Tx::<Cancel>::initialize(&lock, datapunishablelock, &fee, politic).unwrap();

        let address = {
            use bitcoin::network::constants::Network;
            use bitcoin::secp256k1::rand::thread_rng;
            use bitcoin::secp256k1::Secp256k1;
            use bitcoin::util::address::Address;
            use bitcoin::util::key;

            // Generate random key pair
            let s = Secp256k1::new();
            let public_key = key::PublicKey {
                compressed: true,
                key: s.generate_keypair(&mut thread_rng()).1,
            };

            // Generate pay-to-pubkey-hash address
            Address::p2pkh(&public_key, Network::Bitcoin)
        };

        let _refund = Tx::<Refund>::initialize(&cancel, address, &fee, politic).unwrap();

        // Sign lock tx
        let _sig = lock.generate_witness(&privkey).unwrap();
        assert!(true);
    }
}
