// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

//! Transaction fee unit type and implementation. Defines the [`SatPerKvB`] unit used in methods
//! that set the fee and check the fee on transactions given a [`FeeStrategy`] and a
//! [`FeePriority`].
//!
//! ```rust
//! use farcaster_core::bitcoin::fee::SatPerKvB;
//!
//!# fn main() -> Result<(), farcaster_core::consensus::Error> {
//! // Parse a Bitcoin amount suffixed with '/vByte'
//! let rate = "100 satoshi/kvB".parse::<SatPerKvB>()?;
//! // ...also work with any other valid Bitcoin denomination
//! let rate = "0.000001 BTC/kvB".parse::<SatPerKvB>()?;
//!
//! // Always displayed as 'statoshi/vByte'
//! assert_eq!("100 satoshi/kvB", format!("{}", rate));
//!# Ok(())
//!# }
//! ```

use bitcoin::blockdata::transaction::TxOut;
use bitcoin::util::amount::Denomination;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Amount;

use crate::bitcoin::transaction;
use crate::blockchain::{Fee, FeePriority, FeeStrategy, FeeStrategyError};
use crate::consensus::{self, CanonicalBytes};

use std::str::FromStr;

use serde::ser::{Serialize, Serializer};
use serde::{de, Deserialize, Deserializer};

/// The unit used to mesure a quantity, or weight, for a Bitcoin transaction. This represent a
/// 1'000 of virtual Bytes.
pub const WEIGHT_UNIT: &str = "kvB";

/// An amount of Bitcoin (internally in satoshis) representing the number of satoshis per virtual
/// byte a transaction must use for its fee. A [`FeeStrategy`] can use one of more of this type
/// depending of its complexity (fixed, range, etc).
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Hash, Eq, Display)]
#[display(display_sats_per_vbyte)]
pub struct SatPerKvB(Amount);

fn display_sats_per_vbyte(rate: &SatPerKvB) -> String {
    format!(
        "{}/{}",
        rate.as_native_unit()
            .to_string_with_denomination(Denomination::Satoshi),
        WEIGHT_UNIT
    )
}

impl SatPerKvB {
    /// Create a fee quantity per virtual byte of given satoshis.
    pub fn from_sat(satoshis: u64) -> Self {
        SatPerKvB(Amount::from_sat(satoshis))
    }

    /// Return the number of satoshis per virtual byte to use for calculating the fee.
    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    /// Create a fee quantity per virtual byte of given `bitcoin` crate amount.
    pub fn from_native_unit(amount: Amount) -> Self {
        SatPerKvB(amount)
    }

    /// Return the number of bitcoins per virtual byte to use for calculating the fee as the native
    /// `bitcoin` crate amount.
    pub fn as_native_unit(&self) -> Amount {
        self.0
    }
}

impl Serialize for SatPerKvB {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_ref())
    }
}

impl<'de> Deserialize<'de> for SatPerKvB {
    fn deserialize<D>(deserializer: D) -> Result<SatPerKvB, D::Error>
    where
        D: Deserializer<'de>,
    {
        SatPerKvB::from_str(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalBytes for SatPerKvB {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self.0.as_sat())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(SatPerKvB(Amount::from_sat(
            bitcoin::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)?,
        )))
    }
}

impl FromStr for SatPerKvB {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('/').collect::<Vec<&str>>();
        if parts.len() != 2 {
            return Err(consensus::Error::ParseFailed(
                "sat/kvB format is not respected",
            ));
        }
        let amount = parts[0].parse::<Amount>().map_err(consensus::Error::new)?;
        match parts[1] {
            WEIGHT_UNIT => Ok(Self(amount)),
            _ => Err(consensus::Error::ParseFailed("Weight unit parse failed")),
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

impl Fee for PartiallySignedTransaction {
    type FeeUnit = SatPerKvB;

    type Amount = Amount;

    /// Calculates and sets the fees on the given transaction and return the fees set
    #[allow(unused_variables)]
    fn set_fee(
        &mut self,
        strategy: &FeeStrategy<SatPerKvB>,
        politic: FeePriority,
    ) -> Result<Self::Amount, FeeStrategyError> {
        if self.unsigned_tx.output.len() != 1 {
            return Err(FeeStrategyError::new(
                transaction::Error::MultiUTXOUnsuported,
            ));
        }

        let input_sum = get_available_input_sat(self)?;

        // FIXME This does not account for witnesses
        // currently the fees are wrong
        // Get the transaction weight
        //
        // For transactions with an empty witness, this is simply the consensus-serialized size
        // times four. For transactions with a witness, this is the non-witness
        // consensus-serialized size multiplied by three plus the with-witness consensus-serialized
        // size.
        let weight = self.unsigned_tx.weight() as u64;

        // Compute the fee amount to set in total
        let fee_amount = match strategy {
            FeeStrategy::Fixed(sat_per_vbyte) => sat_per_vbyte.as_native_unit().checked_mul(weight),
            #[cfg(feature = "fee_range")]
            FeeStrategy::Range { min_inc, max_inc } => match politic {
                FeePriority::Low => min_inc.as_native_unit().checked_mul(weight),
                FeePriority::High => max_inc.as_native_unit().checked_mul(weight),
            },
        }
        .ok_or(FeeStrategyError::AmountOfFeeTooHigh)?;

        // Apply the fee on the first output
        self.unsigned_tx.output[0].value = input_sum
            .checked_sub(fee_amount)
            .ok_or(FeeStrategyError::NotEnoughAssets)?
            .as_sat();

        // Return the fee amount set in native blockchain asset unit
        Ok(fee_amount)
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(&self, strategy: &FeeStrategy<SatPerKvB>) -> Result<bool, FeeStrategyError> {
        if self.unsigned_tx.output.len() != 1 {
            return Err(FeeStrategyError::new(
                transaction::Error::MultiUTXOUnsuported,
            ));
        }

        let input_sum = get_available_input_sat(self)?.as_sat();
        let output_sum = self.unsigned_tx.output[0].value;
        let fee = input_sum
            .checked_sub(output_sum)
            .ok_or(FeeStrategyError::AmountOfFeeTooHigh)?;
        let weight = self.unsigned_tx.weight() as u64;

        let effective_sat_per_vbyte = SatPerKvB::from_sat(
            weight
                .checked_div(fee)
                .ok_or(FeeStrategyError::AmountOfFeeTooLow)?,
        );

        Ok(strategy.check(&effective_sat_per_vbyte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct SerdeTest {
        fee: SatPerKvB,
    }

    #[test]
    fn parse_sats_per_vbyte() {
        for s in [
            "0.0001 BTC/kvB",
            "100 satoshi/kvB",
            "100 satoshis/kvB",
            "10 satoshi/kvB",
            "1 satoshi/kvB",
        ]
        .iter()
        {
            let parse = SatPerKvB::from_str(s);
            assert!(parse.is_ok());
        }
        // MUST fail
        for s in ["1 satoshi", "100 kvB"].iter() {
            let parse = SatPerKvB::from_str(s);
            assert!(parse.is_err());
        }
    }

    #[test]
    fn display_sats_per_vbyte() {
        let fee_rate = SatPerKvB::from_sat(100);
        assert_eq!(format!("{}", fee_rate), "100 satoshi/kvB".to_string());
    }

    #[test]
    fn serialize_fee_rate_in_yaml() {
        let fee_rate = SerdeTest {
            fee: SatPerKvB::from_sat(10),
        };
        let s = serde_yaml::to_string(&fee_rate).expect("Encode fee rate in yaml");
        assert_eq!("---\nfee: 10 satoshi/kvB\n", s);
    }

    #[test]
    fn deserialize_fee_rate_in_yaml() {
        let s = "---\nfee: 10 satoshi/kvB\n";
        let fee_rate = serde_yaml::from_str(&s).expect("Decode fee rate from yaml");
        assert_eq!(
            SerdeTest {
                fee: SatPerKvB::from_sat(10)
            },
            fee_rate
        );
    }
}
