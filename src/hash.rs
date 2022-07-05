use std::fmt;

use serde::de::{self, Unexpected, Visitor};

/// A visitor that deserializes a long string - a string containing at least
/// some minimum number of bytes.
pub(crate) struct HashString;

impl<'de> Visitor<'de> for HashString {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a string representing a hash in hex value prefixed with 0x"
        )
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s.len() == 66 {
            Ok(s.to_string())
        } else {
            Err(de::Error::invalid_value(Unexpected::Str(s), &self))
        }
    }
}

/// A visitor that deserializes a public offer
pub(crate) struct OfferString;

impl<'de> Visitor<'de> for OfferString {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a string representing a public offer in Base58 value"
        )
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s.len() == 195 {
            Ok(s.to_string())
        } else {
            Err(de::Error::invalid_length(s.len(), &self))
        }
    }
}
