//! Implementation for handeling the funding transaction on-chain.

use bitcoin::blockdata::transaction::{OutPoint, Transaction};
use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;

use crate::blockchain::Network;
use crate::transaction::{Error as FError, Fundable, Linkable};

use crate::bitcoin::segwitv0::SegwitV0;
use crate::bitcoin::transaction::{Error, MetadataOutput};
use crate::bitcoin::Bitcoin;

/// Manages the steps to handle on-chain funding. Receives the public key derived from the key
/// manager, receives the network of operations and the raw funding transaction when seen.
#[derive(Debug, Clone)]
pub struct Funding {
    pubkey: Option<PublicKey>,
    network: Option<Network>,
    seen_tx: Option<Transaction>,
}

impl Linkable<MetadataOutput> for Funding {
    fn get_consumable_output(&self) -> Result<MetadataOutput, FError> {
        // Create a **COMPRESSED** ECDSA public key.
        let pubkey = match self.pubkey {
            Some(pubkey) => bitcoin::util::key::PublicKey::new(pubkey),
            None => return Err(FError::MissingPublicKey),
        };

        let (script_pubkey, network) = match self.network {
            Some(Network::Mainnet) => (
                Address::p2wpkh(&pubkey, BtcNetwork::Bitcoin),
                BtcNetwork::Bitcoin,
            ),
            Some(Network::Testnet) => (
                Address::p2wpkh(&pubkey, BtcNetwork::Testnet),
                BtcNetwork::Testnet,
            ),
            Some(Network::Local) => (
                Address::p2wpkh(&pubkey, BtcNetwork::Regtest),
                BtcNetwork::Regtest,
            ),
            None => return Err(FError::MissingNetwork),
        };

        // Safety: we can unwrap here as `Address::p2wpkh` only returns an error when
        // uncompressed public key is provided, but we construct the public key and we
        // ensure it is compressed.
        let script_pubkey = script_pubkey.unwrap().script_pubkey();

        match &self.seen_tx {
            Some(t) => t
                .output
                .iter()
                .enumerate()
                .find(|(_, tx_out)| tx_out.script_pubkey == script_pubkey)
                .map(|(ix, tx_out)| MetadataOutput {
                    out_point: OutPoint::new(t.txid(), ix as u32),
                    tx_out: tx_out.clone(),
                    script_pubkey: Some(Address::p2pkh(&pubkey, network).script_pubkey()),
                })
                .ok_or(FError::MissingUTXO),
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
            Some(pubkey) => Ok(bitcoin::util::key::PublicKey::new(pubkey)),
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

    fn was_seen(&self) -> bool {
        self.seen_tx.is_some()
    }
}
