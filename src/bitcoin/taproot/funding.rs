use bitcoin::blockdata::transaction::{OutPoint, Transaction};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, XOnlyPublicKey};

use crate::blockchain::Network;
use crate::transaction::{Error, Fundable, Linkable};

use crate::bitcoin::taproot::Taproot;
use crate::bitcoin::transaction::MetadataOutput;
use crate::bitcoin::Bitcoin;
use bitcoin::util::taproot::TaprootSpendInfo;

#[derive(Debug, Clone)]
pub struct Funding {
    untweaked_public_key: Option<XOnlyPublicKey>,
    network: Option<bitcoin::Network>,
    seen_tx: Option<Transaction>,
}

impl Linkable<MetadataOutput> for Funding {
    fn get_consumable_output(&self) -> Result<MetadataOutput, Error> {
        let secp = Secp256k1::new();

        let address = Address::p2tr(
            &secp,
            self.untweaked_public_key.ok_or(Error::MissingPublicKey)?,
            None,
            self.network.ok_or(Error::MissingNetwork)?,
        );
        let script_pubkey = address.script_pubkey();

        match &self.seen_tx {
            Some(t) => t
                .output
                .iter()
                .enumerate()
                .find(|(_, tx_out)| tx_out.script_pubkey == script_pubkey)
                .map(|(ix, tx_out)| MetadataOutput {
                    out_point: OutPoint::new(t.txid(), ix as u32),
                    tx_out: tx_out.clone(),
                    script_pubkey: Some(script_pubkey),
                })
                .ok_or(Error::MissingUTXO),
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(Error::MissingOnchainTransaction),
        }
    }
}

impl Fundable<Bitcoin<Taproot>, MetadataOutput> for Funding {
    fn initialize(pubkey: XOnlyPublicKey, network: Network) -> Result<Self, Error> {
        let network = match network {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Local => bitcoin::Network::Regtest,
        };
        Ok(Funding {
            untweaked_public_key: Some(pubkey),
            network: Some(network),
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, Error> {
        let secp = Secp256k1::new();
        let taproot_info = TaprootSpendInfo::new_key_spend(
            &secp,
            self.untweaked_public_key.ok_or(Error::MissingPublicKey)?,
            None,
        );

        Ok(Address::p2tr(
            &secp,
            taproot_info.internal_key(),
            taproot_info.merkle_root(),
            self.network.ok_or(Error::MissingNetwork)?,
        ))
    }

    fn update(&mut self, tx: Transaction) -> Result<(), Error> {
        self.seen_tx = Some(tx);
        Ok(())
    }

    fn raw(tx: Transaction) -> Result<Self, Error> {
        Ok(Self {
            untweaked_public_key: None,
            network: None,
            seen_tx: Some(tx),
        })
    }

    fn was_seen(&self) -> bool {
        self.seen_tx.is_some()
    }
}
