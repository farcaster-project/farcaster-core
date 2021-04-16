//! Farcaster consensus encoding used to strictly encode and decode data such as public offers
//! amoung swap participants.
//!
//! Implementation on blockchain foreign types must follow the strict consensus encoding from the
//! blockchain itself, Farcaster core will then wrap the serialization and treat it as a lenght
//! prefixed vector of bytes when needed.

use hex::encode as hex_encode;
use thiserror::Error;

use std::io;
use std::io::prelude::*;

use crate::crypto;
use crate::negotiation;

/// Encoding error
#[derive(Error, Debug)]
pub enum Error {
    /// The type is not defined in the consensus
    #[error("Unknown consensus type")]
    UnknownType,
    /// The type is not the one expected
    #[error("Type mismatch, not the one expected")]
    TypeMismatch,
    /// Error related to Farcaster negotiation
    #[error("Negotiation error: {0}")]
    Negotiation(#[from] negotiation::Error),
    /// Error related to Farcaster cryptography
    #[error("Cryptography error: {0}")]
    Crypto(#[from] crypto::Error),
    /// And I/O error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// Parsing error
    #[error("Parsing error: {0}")]
    ParseFailed(&'static str),
    /// Strict encoding wrapping error
    #[error("Strict encoding error: {0}")]
    StrictEncoding(#[from] strict_encoding::Error),
}

/// Encode an object into a vector
pub fn serialize<T: Encodable + std::fmt::Debug + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).unwrap();
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: Encodable + std::fmt::Debug + ?Sized>(data: &T) -> String {
    hex_encode(serialize(data))
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        ))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = io::Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

/// Data which can be encoded in a consensus-consistent way
///
/// **When implemented on foreign blockchain specific types such as `Amount` from the bitcoin
/// crate, the implementer MUST use the strict encoding dictated by the blockchain consensus
/// without any lenght prefix. Lenght prefix is done by Farcaster core after this serialization.**
pub trait Encodable {
    /// Encode an object with a well-defined format, should only ever error if
    /// the underlying encoder errors.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Data which can be encoded in a consensus-consistent way
///
/// **When implemented on foreign blockchain specific types such as `Amount` from the bitcoin
/// crate, the implementer MUST use the strict encoding dictated by the blockchain consensus
/// without any lenght prefix. Lenght prefix is done by Farcaster core after this serialization.**
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error>;
}

impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        if self.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::Other, "Value is too long"));
        }
        (self.len() as u16).consensus_encode(s)?;
        s.write_all(&self[..])?;
        Ok(self.len() + 2)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let len = u16::consensus_decode(d)?;
        let mut ret = Vec::<u8>::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(d)?);
        }
        Ok(ret)
    }
}

impl Encodable for [u8; 6] {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self[..])?;
        Ok(6)
    }
}

impl Decodable for [u8; 6] {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 6];
        d.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

macro_rules! wrap_in_vec {
    (wrap $name: ident in $writer: ident) => {{
        let mut encoder = ::std::io::Cursor::new(vec![]);
        $name.consensus_encode(&mut encoder)?;
        encoder.into_inner().consensus_encode($writer)?
    }};

    (wrap $name: ident for $self: ident in $writer: ident) => {{
        let mut encoder = ::std::io::Cursor::new(vec![]);
        $self.$name.consensus_encode(&mut encoder)?;
        encoder.into_inner().consensus_encode($writer)?
    }};
}

macro_rules! unwrap_from_vec {
    ($reader: ident) => {{
        let v: Vec<u8> = $crate::consensus::Decodable::consensus_decode($reader)?;
        let mut reader = ::std::io::Cursor::new(v);
        $crate::consensus::Decodable::consensus_decode(&mut reader)?
    }};
}

impl Encodable for u8 {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self.to_le_bytes())?;
        Ok(1)
    }
}

impl Decodable for u8 {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 1];
        d.read_exact(&mut buffer)?;
        Ok(u8::from_le_bytes(buffer))
    }
}

impl Encodable for u16 {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self.to_le_bytes())?;
        Ok(2)
    }
}

impl Decodable for u16 {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 2];
        d.read_exact(&mut buffer)?;
        Ok(u16::from_le_bytes(buffer))
    }
}

impl Encodable for u32 {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl Decodable for u32 {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 4];
        d.read_exact(&mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }
}

impl Encodable for u64 {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl Decodable for u64 {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 8];
        d.take(8).read(&mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn little_endianness_test() {
        assert_eq!(&[0xef, 0xbe, 0xad, 0xde], &serialize(&0xdeadbeefu32)[..]);
        assert_eq!(
            deserialize::<u32>(&[0xef, 0xbe, 0xad, 0xde]).unwrap(),
            0xdeadbeef
        );
        assert_eq!(&[0x01], &serialize(&0x01u8)[..]);
        assert_eq!(deserialize::<u8>(&[0x01]).unwrap(), 0x01);
    }

    #[test]
    fn simple_vec() {
        let vec = vec![0xde, 0xad, 0xbe, 0xef];
        // len of 4 as u16 in little endian = 0400
        assert_eq!(serialize_hex(&vec), "0400deadbeef");
        // test max size vec
        let vec = vec![0x41; u16::MAX.into()];
        assert_eq!(deserialize::<Vec<u8>>(&serialize(&vec)[..]).unwrap(), vec);
    }
}
