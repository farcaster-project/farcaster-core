use bitcoin::blockdata::transaction::{OutPoint, Transaction};
use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin::util::key::PublicKey;

use farcaster_core::blockchain::Network;
use farcaster_core::transaction::{Fundable, Linkable};

use crate::bitcoin::transaction::{Error, MetadataOutput};
use crate::bitcoin::{Address, Bitcoin};

#[derive(Debug, Clone)]
pub struct Funding {
    pubkey: Option<PublicKey>,
    network: Option<Network>,
    seen_tx: Option<Transaction>,
}

impl Linkable<MetadataOutput, Error> for Funding {
    fn get_consumable_output(&self) -> Result<MetadataOutput, Error> {
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

                let pubkey = match self.pubkey {
                    Some(pubkey) => Ok(pubkey),
                    None => Err(Error::PublicKeyNotFound),
                }?;

                // vout is always 0 because output len is 1
                Ok(MetadataOutput {
                    out_point: OutPoint::new(t.txid(), 0),
                    tx_out: t.output[0].clone(),
                    script_pubkey: Some(
                        match self.network {
                            Some(Network::Mainnet) => {
                                bitcoin::Address::p2pkh(&pubkey, BtcNetwork::Bitcoin)
                            }
                            Some(Network::Testnet) => {
                                bitcoin::Address::p2pkh(&pubkey, BtcNetwork::Testnet)
                            }
                            Some(Network::Local) => {
                                bitcoin::Address::p2pkh(&pubkey, BtcNetwork::Regtest)
                            }
                            None => Err(Error::MissingNetwork)?,
                        }
                        .script_pubkey(),
                    ),
                })
            }
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(Error::TransactionNotSeen),
        }
    }
}

impl Fundable<Bitcoin, MetadataOutput, Error> for Funding {
    fn initialize(pubkey: PublicKey, network: Network) -> Result<Self, Error> {
        Ok(Funding {
            pubkey: Some(pubkey),
            network: Some(network),
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, Error> {
        let pubkey = match self.pubkey {
            Some(pubkey) => Ok(pubkey),
            None => Err(Error::PublicKeyNotFound),
        }?;

        match self.network {
            Some(Network::Mainnet) => Ok(Address(bitcoin::Address::p2wpkh(
                &pubkey,
                BtcNetwork::Bitcoin,
            )?)),
            Some(Network::Testnet) => Ok(Address(bitcoin::Address::p2wpkh(
                &pubkey,
                BtcNetwork::Testnet,
            )?)),
            Some(Network::Local) => Ok(Address(bitcoin::Address::p2wpkh(
                &pubkey,
                BtcNetwork::Regtest,
            )?)),
            None => Err(Error::MissingNetwork),
        }
    }

    fn update(&mut self, tx: Transaction) -> Result<(), Error> {
        self.seen_tx = Some(tx);
        Ok(())
    }

    fn raw(tx: Transaction) -> Result<Self, Error> {
        Ok(Self {
            pubkey: None,
            network: None,
            seen_tx: Some(tx),
        })
    }
}
