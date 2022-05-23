//! Farcaster consensus encoding used to strictly encode and decode data such as public offers,
//! bundles or other messages defined in the RFCs.
//!
//! Implementation on blockchain foreign types with [`CanonicalBytes`] must follow the strict
//! consensus encoding from the blockchain itself, Farcaster core will then wrap the serialization
//! and treat it as a length prefixed vector of bytes when needed.

use hex::encode as hex_encode;
use thiserror::Error;

use std::error;
use std::io;
use std::str;

/// Encoding and decoding errors and data transformation errors (when converting data from one
/// message type to another).
#[derive(Error, Debug)]
pub enum Error {
    /// The type is not defined in the consensus.
    #[error("Unknown consensus type")]
    UnknownType,
    /// The type is not the one expected.
    #[error("Type mismatch, the given type does not match the expected one")]
    TypeMismatch,
    /// The magic bytes expected does not match.
    #[error("Incorrect magic bytes")]
    IncorrectMagicBytes,
    /// And I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// A generic parsing error.
    #[error("Parsing error: {0}")]
    ParseFailed(&'static str),
    /// Any Consensus error not part of this list.
    #[error("Consensus error: {0}")]
    Other(Box<dyn error::Error + Send + Sync>),
}

impl Error {
    /// Creates a new error of type [`Self::Other`] with an arbitrary payload. Useful to carry
    /// lower-level errors.
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::Other(error.into())
    }

    /// Consumes the `Error`, returning its inner error (if any).
    ///
    /// If this [`enum@Error`] was constructed via [`new`] then this function will return [`Some`],
    /// otherwise it will return [`None`].
    ///
    /// [`new`]: Error::new
    ///
    pub fn into_inner(self) -> Option<Box<dyn error::Error + Send + Sync>> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

/// Data represented in a canonical bytes format. The implementer **MUST** use the strict encoding
/// dictated by the blockchain consensus without any length prefix. Length prefix is done by
/// Farcaster core during the serialization. This trait is required on foreign types used inside
/// core messages (bundles, protocol messages, etc).
pub trait CanonicalBytes {
    /// Returns the canonical bytes representation of the element.
    fn as_canonical_bytes(&self) -> Vec<u8>;

    /// Parse a supposedly canonical bytes representation of an element and return it, return an
    /// error if not canonical.
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

impl<T> CanonicalBytes for Option<T>
where
    T: CanonicalBytes,
{
    fn as_canonical_bytes(&self) -> Vec<u8> {
        match self {
            Some(t) => t.as_canonical_bytes(),
            None => vec![],
        }
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match bytes.len() {
            0 => Ok(None),
            _ => Ok(Some(T::from_canonical_bytes(bytes)?)),
        }
    }
}

/// Encode an object into a vector of bytes. The vector can be [`deserialize`]d to retrieve the
/// data.
pub fn serialize<T: Encodable + std::fmt::Debug + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).unwrap();
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encode an object into a hex-encoded string.
pub fn serialize_hex<T: Encodable + std::fmt::Debug + ?Sized>(data: &T) -> String {
    hex_encode(serialize(data))
}

/// Deserialize an object from a vector of bytes, will error if said deserialization doesn't
/// consume the entire vector.
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

/// Deserialize an object from a vector of bytes, but will not report an error if said
/// deserialization doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = io::Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

/// Data which can be encoded in a consensus-consistent way. Used to implement `StrictEncode` on
/// messages passed around by the node.
pub trait Encodable {
    /// Encode an object with a well-defined format, should only ever error if the underlying
    /// encoder errors. If successful, returns size of the encoded object in bytes.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Data which can be decoded in a consensus-consistent way. Used to implement `StrictDecode` on
/// messages passed around by the node.
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error>;
}

impl<T> Encodable for Vec<T>
where
    T: Encodable,
{
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        if self.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::Other, "Value is too long"));
        }
        let mut len = (self.len() as u16).consensus_encode(s)?;
        for t in self {
            len += t.consensus_encode(s)?;
        }
        Ok(len)
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable,
{
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let len = u16::consensus_decode(d)?;
        let mut ret = Vec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(d)?);
        }
        Ok(ret)
    }
}

macro_rules! impl_fixed_array {
    ($len: expr) => {
        impl Encodable for [u8; $len] {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
                s.write_all(&self[..])?;
                Ok($len)
            }
        }

        impl Decodable for [u8; $len] {
            #[inline]
            fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
                let mut buffer = [0u8; $len];
                d.read_exact(&mut buffer)?;
                Ok(buffer)
            }
        }
    };
}

impl_fixed_array!(6);
impl_fixed_array!(32);
impl_fixed_array!(33);
impl_fixed_array!(64);

#[macro_export]
macro_rules! unwrap_vec_ref {
    ($reader: ident) => {{
        let v: Vec<u8> = $crate::consensus::Decodable::consensus_decode($reader)?;
        v
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

impl Encodable for i16 {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self.to_le_bytes())?;
        Ok(2)
    }
}

impl Decodable for i16 {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 2];
        d.read_exact(&mut buffer)?;
        Ok(i16::from_le_bytes(buffer))
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

impl Encodable for i32 {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl Decodable for i32 {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut buffer = [0u8; 4];
        d.read_exact(&mut buffer)?;
        Ok(i32::from_le_bytes(buffer))
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
        d.read_exact(&mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }
}

impl<T> Encodable for Option<T>
where
    T: Encodable,
{
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        match self {
            Some(t) => {
                s.write_all(&[1u8])?;
                let len = t.consensus_encode(s)?;
                Ok(1 + len)
            }
            None => s.write_all(&[0u8]).map(|_| 1),
        }
    }
}

impl<T> Decodable for Option<T>
where
    T: Decodable,
{
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        match u8::consensus_decode(d)? {
            1u8 => Ok(Some(Decodable::consensus_decode(d)?)),
            0u8 => Ok(None),
            _ => Err(Error::UnknownType),
        }
    }
}

impl CanonicalBytes for String {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.as_bytes().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(str::from_utf8(bytes).map_err(Error::new)?.into())
    }
}

impl Encodable for String {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        Vec::<u8>::from(self.as_bytes()).consensus_encode(s)
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        Ok(str::from_utf8(unwrap_vec_ref!(d).as_ref())
            .map_err(Error::new)?
            .into())
    }
}

#[macro_export]
macro_rules! impl_strict_encoding {
    ($thing:ty, $($args:tt)*) => {
        impl<$($args)*> ::strict_encoding::StrictEncode for $thing {
            fn strict_encode<E: ::std::io::Write>(
                &self,
                mut e: E,
            ) -> Result<usize, strict_encoding::Error> {
                $crate::consensus::Encodable::consensus_encode(self, &mut e)
                    .map_err(strict_encoding::Error::from)
            }
        }

        impl<$($args)*> ::strict_encoding::StrictDecode for $thing {
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
                $crate::consensus::Decodable::consensus_decode(&mut d)
                    .map_err(|e| strict_encoding::Error::DataIntegrityError(e.to_string()))
            }
        }
    };
    ($thing:ty) => {
        impl strict_encoding::StrictEncode for $thing {
            fn strict_encode<E: ::std::io::Write>(
                &self,
                mut e: E,
            ) -> Result<usize, strict_encoding::Error> {
                $crate::consensus::Encodable::consensus_encode(self, &mut e)
                    .map_err(strict_encoding::Error::from)
            }
        }

        impl strict_encoding::StrictDecode for $thing {
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
                $crate::consensus::Decodable::consensus_decode(&mut d)
                    .map_err(|e| strict_encoding::Error::DataIntegrityError(e.to_string()))
            }
        }
    };
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
        let vec: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        // len of 4 as u16 in little endian = 0400
        assert_eq!(serialize_hex(&vec), "0400deadbeef");
        // test max size vec
        let vec = vec![0x41; u16::MAX.into()];
        assert_eq!(deserialize::<Vec<u8>>(&serialize(&vec)[..]).unwrap(), vec);
    }
}
