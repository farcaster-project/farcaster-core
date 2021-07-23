use bitcoin::blockdata::transaction::{OutPoint, Transaction};
use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin::util::key::PublicKey;
use bitcoin::Address;

use crate::blockchain::Network;
use crate::transaction::{Error as FError, Fundable, Linkable};

use crate::chain::bitcoin::transaction::{Error, MetadataOutput};
use crate::chain::bitcoin::{Bitcoin, SegwitV0};

#[derive(Debug, Clone)]
pub struct Funding {
    pubkey: Option<PublicKey>,
    network: Option<Network>,
    seen_tx: Option<Transaction>,
}

impl Linkable<MetadataOutput> for Funding {
    fn get_consumable_output(&self) -> Result<MetadataOutput, FError> {
        match &self.seen_tx {
            Some(t) => {
                // More than one UTXO is not supported
                match t.output.len() {
                    1 => (),
                    2 =>
                    // Check if coinbase transaction
                    {
                        if !t.is_coin_base() {
                            return Err(FError::new(Error::MultiUTXOUnsuported));
                        }
                    }
                    _ => return Err(FError::new(Error::MultiUTXOUnsuported)),
                }

                let pubkey = match self.pubkey {
                    Some(pubkey) => Ok(pubkey),
                    None => Err(FError::MissingPublicKey),
                }?;

                // vout is always 0 because output len is 1
                Ok(MetadataOutput {
                    out_point: OutPoint::new(t.txid(), 0),
                    tx_out: t.output[0].clone(),
                    script_pubkey: Some(
                        match self.network {
                            Some(Network::Mainnet) => Address::p2pkh(&pubkey, BtcNetwork::Bitcoin),
                            Some(Network::Testnet) => Address::p2pkh(&pubkey, BtcNetwork::Testnet),
                            Some(Network::Local) => Address::p2pkh(&pubkey, BtcNetwork::Regtest),
                            None => Err(FError::MissingNetwork)?,
                        }
                        .script_pubkey(),
                    ),
                })
            }
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(FError::MissingOnchainTransaction),
        }
    }
}

impl Fundable<Bitcoin<SegwitV0>, MetadataOutput> for Funding {
    fn initialize(pubkey: PublicKey, network: Network) -> Result<Self, FError> {
        Ok(Funding {
            pubkey: Some(pubkey),
            network: Some(network),
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, FError> {
        let pubkey = match self.pubkey {
            Some(pubkey) => Ok(pubkey),
            None => Err(FError::MissingPublicKey),
        }?;

        match self.network {
            Some(Network::Mainnet) => {
                Ok(Address::p2wpkh(&pubkey, BtcNetwork::Bitcoin).map_err(Error::from)?)
            }
            Some(Network::Testnet) => {
                Ok(Address::p2wpkh(&pubkey, BtcNetwork::Testnet).map_err(Error::from)?)
            }
            Some(Network::Local) => {
                Ok(Address::p2wpkh(&pubkey, BtcNetwork::Regtest).map_err(Error::from)?)
            }
            None => Err(FError::MissingNetwork),
        }
    }

    fn update(&mut self, tx: Transaction) -> Result<(), FError> {
        self.seen_tx = Some(tx);
        Ok(())
    }

    fn raw(tx: Transaction) -> Result<Self, FError> {
        Ok(Self {
            pubkey: None,
            network: None,
            seen_tx: Some(tx),
        })
    }
}
