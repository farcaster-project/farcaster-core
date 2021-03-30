use bitcoin::blockdata::transaction::{OutPoint, Transaction};
use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin::util::address::Address;
use bitcoin::util::key::PublicKey;

use farcaster_core::blockchain::Network;
use farcaster_core::transaction::{Failable, Fundable, Linkable};

use crate::bitcoin::transaction::{Error, MetadataOutput};
use crate::bitcoin::Bitcoin;

#[derive(Debug, Clone)]
pub struct Funding {
    pubkey: PublicKey,
    network: Network,
    seen_tx: Option<Transaction>,
}

impl Failable for Funding {
    type Error = Error;
}

impl Linkable<Bitcoin> for Funding {
    type Output = MetadataOutput;

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
                // vout is always 0 because output len is 1
                Ok(MetadataOutput {
                    out_point: OutPoint::new(t.txid(), 0),
                    tx_out: t.output[0].clone(),
                    script_pubkey: Some(
                        match self.network {
                            Network::Mainnet => Address::p2pkh(&self.pubkey, BtcNetwork::Bitcoin),
                            Network::Testnet => Address::p2pkh(&self.pubkey, BtcNetwork::Testnet),
                            Network::Local => Address::p2pkh(&self.pubkey, BtcNetwork::Regtest),
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

impl Fundable<Bitcoin> for Funding {
    fn initialize(pubkey: PublicKey, network: Network) -> Result<Self, Error> {
        Ok(Funding {
            pubkey,
            network,
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, Error> {
        match self.network {
            Network::Mainnet => Ok(Address::p2wpkh(&self.pubkey, BtcNetwork::Bitcoin)?),
            Network::Testnet => Ok(Address::p2wpkh(&self.pubkey, BtcNetwork::Testnet)?),
            Network::Local => Ok(Address::p2wpkh(&self.pubkey, BtcNetwork::Regtest)?),
        }
    }

    fn update(&mut self, args: Transaction) -> Result<(), Error> {
        self.seen_tx = Some(args);
        Ok(())
    }
}
