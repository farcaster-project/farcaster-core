use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Message, Secp256k1, SerializedSignature};
use bitcoin::util::address::Address;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::{Input, PartiallySignedTransaction};

use crate::bitcoin::{Bitcoin, FeeStrategies};
use crate::blockchain::{Fee, FeePolitic};
use crate::script;
use crate::transaction::{
    Broadcastable, Buyable, Cancelable, Failable, Fundable, Linkable, Lockable, Punishable,
    Refundable, Signable, Transaction,
};

#[derive(Debug)]
pub struct Funding {
    pubkey: PublicKey,
    seen_tx: Option<bitcoin::blockdata::transaction::Transaction>,
}

impl Failable for Funding {
    type Err = ();
}

#[derive(Debug)]
pub struct MetadataFundingOutput {
    pub out_point: OutPoint,
    pub tx_out: TxOut,
}

impl Linkable<Bitcoin> for Funding {
    type Output = MetadataFundingOutput;

    fn get_consumable_output(&self) -> Result<MetadataFundingOutput, ()> {
        match &self.seen_tx {
            Some(t) => {
                // More than one UTXO is not supported
                if t.output.len() != 1 {
                    return Err(());
                }
                // vout is always 0 because output len is 1
                Ok(MetadataFundingOutput {
                    out_point: OutPoint::new(t.txid(), 0),
                    tx_out: t.output[0].clone(),
                })
            }
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(()),
        }
    }
}

impl Fundable<Bitcoin> for Funding {
    fn initialize(pubkey: PublicKey) -> Result<Self, ()> {
        Ok(Funding {
            pubkey,
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, ()> {
        // FIXME: this always produce mainnet addresses
        Ok(Address::p2wpkh(&self.pubkey, Network::Bitcoin).map_err(|_| ())?)
    }

    fn update(&mut self, args: bitcoin::blockdata::transaction::Transaction) -> Result<(), ()> {
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
    type Err = ();
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

    fn get_consumable_output(&self) -> Result<MetadataFundingOutput, ()> {
        if self.psbt.global.unsigned_tx.output.len() != 1 {
            // multi outs not supported
            return Err(());
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
        prev: &impl Fundable<Bitcoin, Output = MetadataFundingOutput>,
        lock: script::DataLock<Bitcoin>,
        fee_strategy: &FeeStrategies,
        fee_politic: FeePolitic,
    ) -> Result<Self, ()> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.failure.alice)
            .push_key(&lock.failure.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output().map_err(|_| ())?;

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

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(|_| ())?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic).map_err(|_| ())?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

impl Signable<Bitcoin> for Tx<Lock> {
    fn generate_witness(&mut self, privkey: &PrivateKey) -> Result<SerializedSignature, ()> {
        {
            // TODO validate the transaction before signing
        }

        let secp = Secp256k1::new();
        let unsigned_tx = self.psbt.global.unsigned_tx.clone();
        let input = self.psbt.inputs[0].clone();
        let sig = sign_input(&secp, &unsigned_tx, 0, input, &privkey.key);
        let pubkey = PublicKey::from_private_key(&secp, &privkey);

        // Finalize the witness
        self.psbt.inputs[0].final_script_witness = Some(vec![sig.to_vec(), pubkey.to_bytes()]);

        Ok(sig)
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
        _fee_strategy: &FeeStrategies,
        _fee_politic: FeePolitic,
    ) -> Result<Self, ()> {
        todo!()
    }
}

impl Signable<Bitcoin> for Tx<Buy> {
    fn generate_witness(&mut self, _privkey: &PrivateKey) -> Result<SerializedSignature, ()> {
        {
            // TODO validate the transaction before signing
        }
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
        prev: &impl Lockable<Bitcoin, Output = MetadataFundingOutput>,
        lock: script::DataPunishableLock<Bitcoin>,
        fee_strategy: &FeeStrategies,
        fee_politic: FeePolitic,
    ) -> Result<Self, ()> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_key(&lock.failure)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output().map_err(|_| ())?;

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

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(|_| ())?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic).map_err(|_| ())?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

#[derive(Debug)]
pub struct Refund;

impl SubTransaction for Refund {}

impl Refundable<Bitcoin> for Tx<Refund> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataFundingOutput;

    fn initialize(
        prev: &impl Cancelable<Bitcoin, Output = MetadataFundingOutput>,
        refund_target: Address,
        fee_strategy: &FeeStrategies,
        fee_politic: FeePolitic,
    ) -> Result<Self, ()> {
        let output_metadata = prev.get_consumable_output().map_err(|_| ())?;

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

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(|_| ())?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic).map_err(|_| ())?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
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
        _fee_strategy: &FeeStrategies,
        _fee_politic: FeePolitic,
    ) -> Result<Self, ()> {
        todo!()
    }
}

fn sign_input(
    ctx: &Secp256k1<bitcoin::secp256k1::All>,
    unsigned_tx: &bitcoin::Transaction,
    index: usize,
    input: Input,
    key: &bitcoin::secp256k1::SecretKey,
) -> SerializedSignature {
    let sighash = unsigned_tx.signature_hash(
        index,
        &input.witness_utxo.unwrap().script_pubkey,
        input.sighash_type.unwrap().as_u32(),
    );
    let message = Message::from_slice(&sighash[..]).expect("32 bytes");
    let mut sig = ctx.sign(&message, &key);
    sig.normalize_s();
    sig.serialize_der()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{FeeStrategies, SatPerVByte};
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
        println!("{}", funding.get_address().unwrap());

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
        println!("{:?}", funding.get_consumable_output().unwrap());

        let datalock = script::DataLock {
            timelock: 10,
            success: DoubleKeys::new(pubkey, pubkey),
            failure: DoubleKeys::new(pubkey, pubkey),
        };

        let fee = FeeStrategies::fixed_fee(SatPerVByte::from_sat(20));
        let politic = FeePolitic::Aggressive;

        let mut lock = Tx::<Lock>::initialize(&funding, datalock, &fee, politic).unwrap();
        println!("{:#?}", lock);

        let datapunishablelock = script::DataPunishableLock {
            timelock: 10,
            success: DoubleKeys::new(pubkey, pubkey),
            failure: pubkey,
        };
        let cancel = Tx::<Cancel>::initialize(&lock, datapunishablelock, &fee, politic).unwrap();
        println!("{:#?}", cancel);

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

        let refund = Tx::<Refund>::initialize(&cancel, address, &fee, politic).unwrap();
        println!("{:#?}", refund);

        // Sign lock tx
        let sig = lock.generate_witness(&privkey).unwrap();
        println!("{:?}", &sig[..]);
        println!("{:#?}", lock.finalize());

        assert!(true);
    }
}
