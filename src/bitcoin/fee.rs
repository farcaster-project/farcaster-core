//! Transaction fee unit type and implementation. Defines the [`SatPerVByte`] unit used in methods
//! that set the fee and check the fee on transactions given a [`FeeStrategy`] and a
//! [`FeePriority`].
//!
//! ```rust
//! use farcaster_core::bitcoin::fee::SatPerVByte;
//!
//!# fn main() -> Result<(), farcaster_core::consensus::Error> {
//! // Parse a Bitcoin amount suffixed with '/vByte'
//! let rate = "100 satoshi/vByte".parse::<SatPerVByte>()?;
//! // ...also work with any other valid Bitcoin denomination
//! let rate = "0.000001 BTC/vByte".parse::<SatPerVByte>()?;
//!
//! // Always displayed as 'statoshi/vByte'
//! assert_eq!("100 satoshi/vByte", format!("{}", rate));
//!# Ok(())
//!# }
//! ```

use bitcoin::blockdata::transaction::TxOut;
use bitcoin::util::amount::Denomination;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Amount;

use crate::blockchain::{Fee, FeePriority, FeeStrategy, FeeStrategyError};
use crate::consensus::{self, CanonicalBytes};

use crate::bitcoin::{transaction, Bitcoin, Strategy};

use std::str::FromStr;

/// An amount of Bitcoin (internally in satoshis) representing the number of satoshis per virtual
/// byte a transaction must use for its fee. A [`FeeStrategy`] can use one of more of this type
/// depending of its complexity (fixed, range, etc).
#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, Display)]
#[display(display_sats_per_vbyte)]
pub struct SatPerVByte(Amount);

fn display_sats_per_vbyte(rate: &SatPerVByte) -> String {
    format!(
        "{}/vByte",
        rate.as_native_unit()
            .to_string_with_denomination(Denomination::Satoshi)
    )
}

impl SatPerVByte {
    /// Create a fee quantity per virtual byte of given satoshis.
    pub fn from_sat(satoshis: u64) -> Self {
        SatPerVByte(Amount::from_sat(satoshis))
    }

    /// Return the number of satoshis per virtual byte to use for calculating the fee.
    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    /// Create a fee quantity per virtual byte of given `bitcoin` crate amount.
    pub fn from_native_unit(amount: Amount) -> Self {
        SatPerVByte(amount)
    }

    /// Return the number of bitcoins per virtual byte to use for calculating the fee as the native
    /// `bitcoin` crate amount.
    pub fn as_native_unit(&self) -> Amount {
        self.0
    }
}

impl CanonicalBytes for SatPerVByte {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self.0.as_sat())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(SatPerVByte(Amount::from_sat(
            bitcoin::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)?,
        )))
    }
}

impl FromStr for SatPerVByte {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split("/").collect::<Vec<&str>>();
        if parts.len() != 2 {
            return Err(consensus::Error::ParseFailed(
                "SatPerVByte format is not respected",
            ));
        }
        let amount = parts[0].parse::<Amount>().map_err(consensus::Error::new)?;
        match parts[1] {
            "vByte" => Ok(Self(amount)),
            _ => Err(consensus::Error::ParseFailed("SatPerVByte parse failed"))?,
        }
    }
}

fn get_available_input_sat(tx: &PartiallySignedTransaction) -> Result<Amount, FeeStrategyError> {
    // Get the available amount on the transaction
    let inputs: Result<Vec<TxOut>, FeeStrategyError> = tx
        .inputs
        .iter()
        .map(|psbt_in| {
            psbt_in
                .witness_utxo
                .clone()
                .ok_or(FeeStrategyError::MissingInputsMetadata)
        })
        .collect();
    Ok(Amount::from_sat(
        inputs?.iter().map(|txout| txout.value).sum(),
    ))
}

impl<S: Strategy> Fee for Bitcoin<S> {
    type FeeUnit = SatPerVByte;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fee(
        tx: &mut PartiallySignedTransaction,
        strategy: &FeeStrategy<SatPerVByte>,
        politic: FeePriority,
    ) -> Result<Amount, FeeStrategyError> {
        if tx.global.unsigned_tx.output.len() != 1 {
            return Err(FeeStrategyError::new(
                transaction::Error::MultiUTXOUnsuported,
            ));
        }

        let input_sum = get_available_input_sat(&tx)?;

        // FIXME This does not account for witnesses
        // currently the fees are wrong
        // Get the transaction weight
        let weight = tx.global.unsigned_tx.get_weight() as u64;

        // Compute the fee amount to set in total
        let fee_amount = match strategy {
            FeeStrategy::Fixed(sat_per_vbyte) => sat_per_vbyte.as_native_unit().checked_mul(weight),
            FeeStrategy::Range(range) => match politic {
                FeePriority::Low => range.start.as_native_unit().checked_mul(weight),
                FeePriority::High => range.end.as_native_unit().checked_mul(weight),
            },
        }
        .ok_or_else(|| FeeStrategyError::AmountOfFeeTooHigh)?;

        // Apply the fee on the first output
        tx.global.unsigned_tx.output[0].value = input_sum
            .checked_sub(fee_amount)
            .ok_or_else(|| FeeStrategyError::NotEnoughAssets)?
            .as_sat();

        // Return the fee amount set in native blockchain asset unit
        Ok(fee_amount)
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(
        tx: &PartiallySignedTransaction,
        strategy: &FeeStrategy<SatPerVByte>,
    ) -> Result<bool, FeeStrategyError> {
        if tx.global.unsigned_tx.output.len() != 1 {
            return Err(FeeStrategyError::new(
                transaction::Error::MultiUTXOUnsuported,
            ));
        }

        let input_sum = get_available_input_sat(&tx)?.as_sat();
        let output_sum = tx.global.unsigned_tx.output[0].value;
        let fee = input_sum
            .checked_sub(output_sum)
            .ok_or_else(|| FeeStrategyError::AmountOfFeeTooHigh)?;
        let weight = tx.global.unsigned_tx.get_weight() as u64;

        let effective_sat_per_vbyte = SatPerVByte::from_sat(
            weight
                .checked_div(fee)
                .ok_or(FeeStrategyError::AmountOfFeeTooLow)?,
        );

        Ok(match strategy {
            FeeStrategy::Fixed(fee_strat) => &effective_sat_per_vbyte == fee_strat,
            FeeStrategy::Range(range) => range.contains(&effective_sat_per_vbyte),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sats_per_vbyte() {
        for s in [
            "0.0001 BTC/vByte",
            "100 satoshi/vByte",
            "10 satoshi/vByte",
            "1 satoshi/vByte",
        ]
        .iter()
        {
            let parse = SatPerVByte::from_str(s);
            assert!(parse.is_ok());
        }
        // MUST fail
        for s in ["100 satoshis/vByte", "1 satoshi", "100 vByte"].iter() {
            let parse = SatPerVByte::from_str(s);
            assert!(parse.is_err());
        }
    }

    #[test]
    fn display_sats_per_vbyte() {
        let fee_rate = SatPerVByte::from_sat(100);
        assert_eq!(format!("{}", fee_rate), format!("100 satoshi/vByte"));
    }
}
