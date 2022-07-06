//! SLIP-10 implementation for secp256k1 and ed25519. This implementation does not support NIST
//! P-256 curve.
//!
//! ```rust
//! use farcaster_core::crypto::slip10::{DerivationPath, ExtSecretKey};
//! use std::str::FromStr;
//!
//! let seed = hex::decode("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
//! let master = ExtSecretKey::new_master_secp256k1(&seed);
//! let path = DerivationPath::from_str("m/0'/1/2'/2/1000000000").unwrap();
//! let derived_key = master.derive_priv(&path).unwrap();
//!
//! assert!(derived_key.to_secp256k1().is_some());
//! ```

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{self, Secp256k1};

use thiserror::Error;

pub use bitcoin::hash_types::XpubIdentifier;
/// The 32-bytes entropy extention called chain code.
pub use bitcoin::util::bip32::ChainCode;
/// A public key fingerprint, the first four bytes of the identifier.
pub use bitcoin::util::bip32::Fingerprint;
pub use bitcoin::util::bip32::{ChildNumber, DerivationPath};

/// Possible errors when deriving keys as described in SLIP-10.
#[derive(Error, Debug)]
pub enum Error {
    /// Secp256k1 curve error.
    #[error("Secp256k1 curve error: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    /// Hardened not supported in ed25519.
    #[error("Hardened not supported in ed25519")]
    HardenedNotSupportedForEd25519,
}

/// Ed25519 extended secret key. The extended secret key contains its depth, parent figerprint,
/// child number, the derived secret key, and the chain code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ed25519ExtSecretKey {
    /// The depth of this extended key, start with 0 for the master.
    pub depth: u8,
    /// The parent fingerprint, 0 for the master.
    pub parent_fingerprint: Fingerprint,
    /// The child number, with a hardened or non-hardened value.
    pub child_number: ChildNumber,
    /// The secret key, a 32-bytes value. In Ed25519 any 32-bytes long value is considered as valid
    /// secret key, computation is done on-top before using that value.
    pub secret_key: [u8; 32],
    /// The 32-bytes entropy extention called chain code.
    pub chain_code: ChainCode,
}

impl Ed25519ExtSecretKey {
    /// Construct a new master key from a seed value, as defined in SLIP10 the HMAC engine is setup
    /// with the value `"ed25519 seed"`.
    pub fn new_master(seed: impl AsRef<[u8]>) -> Self {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"ed25519 seed");
        hmac_engine.input(seed.as_ref());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let mut secret_key = [0u8; 32];
        secret_key.clone_from_slice(&hmac_result[..32]);

        Ed25519ExtSecretKey {
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            secret_key,
            chain_code: ChainCode::from(&hmac_result[32..]),
        }
    }

    /// Derive the extended secret key from `&self` up to the given `path`.
    pub fn derive_priv(&self, path: &impl AsRef<[ChildNumber]>) -> Result<Self, Error> {
        let mut sk = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(*cnum)?;
        }
        Ok(sk)
    }

    /// Derive the next extended secret key given the child number.
    ///
    /// ## Error
    /// Returns an error if the child number is not hardened. As defined in SLIP10, ed25519 cannot
    /// be derived in a non-hardened way.
    pub fn ckd_priv(&self, i: ChildNumber) -> Result<Ed25519ExtSecretKey, Error> {
        if i.is_normal() {
            return Err(Error::HardenedNotSupportedForEd25519);
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        // Hardened key: use only secret data to prevent public derivation
        // Pad the secret key to make it 33 bytes long
        hmac_engine.input(&[0u8]);
        hmac_engine.input(self.secret_key.as_ref());
        hmac_engine.input(u32::from(i).to_be_bytes().as_ref());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let mut secret_key = [0u8; 32];
        secret_key.clone_from_slice(&hmac_result[..32]);

        Ok(Ed25519ExtSecretKey {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            secret_key,
            chain_code: ChainCode::from(&hmac_result[32..]),
        })
    }

    /// Get the associated public key to the extended secret key as defined in SLIP10 and ed25519
    /// scheme. This might be used in schemes like EdDSA or X25519.
    pub fn public_key(&self) -> CompressedEdwardsY {
        let mut h = sha512::HashEngine::default();
        let mut bits: [u8; 32] = [0u8; 32];

        h.input(self.secret_key.as_ref());
        let hash = sha512::Hash::from_engine(h).into_inner();
        bits.copy_from_slice(&hash[..32]);

        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let scalar = Scalar::from_bits(bits);
        let point = &scalar * &ED25519_BASEPOINT_TABLE;
        point.compress()
    }

    /// Returns the serialized public key, begins with a null byte.
    pub fn serialized_public_key(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[1..].copy_from_slice(self.public_key().as_bytes().as_ref());
        bytes
    }

    /// Returns the HASH160 of the serialized public key belonging to the xpriv.
    pub fn identifier(&self) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        engine.input(self.serialized_public_key().as_ref());
        XpubIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.identifier()[0..4])
    }
}

/// Secp256k1 extended secret key. The extended secret key contains its depth, parent figerprint,
/// child number, the derived secret key, and the chain code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Secp256k1ExtSecretKey {
    /// The depth of this extended key, start with 0 for the master.
    pub depth: u8,
    /// The parent fingerprint, 0 for the master.
    pub parent_fingerprint: Fingerprint,
    /// The child number, with a hardened or non-hardened value.
    pub child_number: ChildNumber,
    /// The secret key value, a valid secp256k1 secret key.
    pub secret_key: secp256k1::SecretKey,
    /// The 32-bytes entropy extention called chain code.
    pub chain_code: ChainCode,
}

impl Secp256k1ExtSecretKey {
    /// Construct a new master key from a seed value, as defined in SLIP10 if secret key is not
    /// valid retry with a new round on the HMAC engine.
    pub fn new_master(seed: impl AsRef<[u8]>) -> Secp256k1ExtSecretKey {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed.as_ref());
        let mut hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let (secret_key, chain_code) = loop {
            match secp256k1::SecretKey::from_slice(&hmac_result[..32]) {
                Ok(key) => break (key, ChainCode::from(&hmac_result[32..])),
                Err(_) => {
                    hmac_engine = HmacEngine::new(b"Bitcoin seed");
                    hmac_engine.input(&hmac_result[..32]);
                    hmac_result = Hmac::from_engine(hmac_engine);
                }
            }
        };

        Secp256k1ExtSecretKey {
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            secret_key,
            chain_code,
        }
    }

    /// Derive the extended secret key from `&self` up to the given `path`.
    pub fn derive_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        path: &impl AsRef<[ChildNumber]>,
    ) -> Result<Self, Error> {
        let mut sk = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Derive the next extended secret key given the child number. The derivation can be hardened
    /// or non-hardened as defined in BIP32.
    ///
    /// ## SLIP10
    /// The computation is executed multiple times until a valid secret key is found and should
    /// never fail.
    ///
    /// ## Safety
    /// An error might be returned if `add_assign` from the `libsecp` fails, but this should not
    /// arrive.
    pub fn ckd_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<Secp256k1ExtSecretKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.secret_key).serialize()[..],
                );
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.secret_key[..]);
            }
        }

        hmac_engine.input(u32::from(i).to_be_bytes().as_ref());
        let mut hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let (mut secret_key, chain_code) = loop {
            match secp256k1::SecretKey::from_slice(&hmac_result[..32]) {
                Ok(key) => break (key, ChainCode::from(&hmac_result[32..])),
                Err(_) => {
                    // let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2.
                    hmac_engine = HmacEngine::new(&self.chain_code[..]);
                    hmac_engine.input(&[1u8]);
                    hmac_engine.input(&hmac_result[32..]);
                    hmac_engine.input(u32::from(i).to_be_bytes().as_ref());
                    hmac_result = Hmac::from_engine(hmac_engine);
                }
            }
        };

        secret_key.add_assign(&self.secret_key[..])?;

        Ok(Secp256k1ExtSecretKey {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            secret_key,
            chain_code,
        })
    }

    /// Returns the public key computed from the secret key.
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(secp, &self.secret_key)
    }

    /// Returns the HASH160 of the serialized public key belonging to the xpriv.
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        engine.input(self.public_key(secp).serialize().as_ref());
        XpubIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier.
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        Fingerprint::from(&self.identifier(secp)[0..4])
    }
}

/// An extended secret key. Generic interface for creating either a secp256k1 extended secret key
/// or an ed25519 extended secret key and deriving sub-keys.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExtSecretKey {
    /// An extended secret key of type secp256k1.
    Secp256k1(Secp256k1ExtSecretKey),
    /// An extended secret key of type ed25519.
    Ed25519(Ed25519ExtSecretKey),
}

impl ExtSecretKey {
    /// Create a new internal secp256k1 extended secret key.
    pub fn new_master_secp256k1(seed: impl AsRef<[u8]>) -> Self {
        ExtSecretKey::Secp256k1(Secp256k1ExtSecretKey::new_master(seed))
    }

    /// Create a new internal ed25519 extended secret key.
    pub fn new_master_ed25519(seed: impl AsRef<[u8]>) -> Self {
        ExtSecretKey::Ed25519(Ed25519ExtSecretKey::new_master(seed))
    }

    /// Derive the extended secret key given the path. When operating on Bitcoin curve a new
    /// `secp256k1` context is created.
    pub fn derive_priv(&self, path: &impl AsRef<[ChildNumber]>) -> Result<Self, Error> {
        let mut sk = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(*cnum)?;
        }
        Ok(sk)
    }

    /// Derive the secret key given the provided child number. When operating on Bitcoin curve
    /// a new `secp256k1` context is created.
    pub fn ckd_priv(&self, i: ChildNumber) -> Result<Self, Error> {
        match &self {
            Self::Secp256k1(extended_key) => {
                let secp = Secp256k1::new();
                Ok(Self::Secp256k1(extended_key.ckd_priv(&secp, i)?))
            }
            Self::Ed25519(extended_key) => Ok(Self::Ed25519(extended_key.ckd_priv(i)?)),
        }
    }

    /// Return some inner secp256k1 extended secret key, `None` oterhwise.
    pub fn to_secp256k1(self) -> Option<Secp256k1ExtSecretKey> {
        match self {
            Self::Secp256k1(extended_key) => Some(extended_key),
            _ => None,
        }
    }

    /// Return some inner ed25519 extended secret key, `None` oterhwise.
    pub fn to_ed25519(self) -> Option<Ed25519ExtSecretKey> {
        match self {
            Self::Ed25519(extended_key) => Some(extended_key),
            _ => None,
        }
    }

    /// Returns the HASH160 of the public key belonging to the xpriv.
    pub fn identifier(&self) -> XpubIdentifier {
        match self {
            Self::Secp256k1(extended_key) => {
                let secp = Secp256k1::new();
                extended_key.identifier(&secp)
            }
            Self::Ed25519(extended_key) => extended_key.identifier(),
        }
    }

    /// Returns the first four bytes of the identifier.
    pub fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Secp256k1(extended_key) => {
                let secp = Secp256k1::new();
                extended_key.fingerprint(&secp)
            }
            Self::Ed25519(extended_key) => extended_key.fingerprint(),
        }
    }

    /// Returns the chain code of the extended secret key.
    pub fn chain_code(&self) -> ChainCode {
        match self {
            Self::Secp256k1(Secp256k1ExtSecretKey { chain_code, .. }) => *chain_code,
            Self::Ed25519(Ed25519ExtSecretKey { chain_code, .. }) => *chain_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    fn assert_secp256k1_curve(master: &ExtSecretKey, asserts: Vec<Vec<&str>>) {
        for mut assert in asserts {
            let chain = master
                .derive_priv(&DerivationPath::from_str(assert[0]).unwrap())
                .unwrap()
                .to_secp256k1()
                .unwrap();
            assert_eq_secp256k1_elem(&chain, assert.drain(1..).collect());
        }
    }

    fn assert_eq_secp256k1_elem(res: &Secp256k1ExtSecretKey, asserts: Vec<&str>) {
        let ctx = Secp256k1::new();

        assert_eq!(asserts[0], res.parent_fingerprint.to_string());
        assert_eq!(asserts[1], res.chain_code.to_string());
        assert_eq!(asserts[2], res.secret_key.display_secret().to_string());
        assert_eq!(asserts[3], res.public_key(&ctx).to_string());
    }

    #[test]
    fn secp256k1_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtSecretKey::new_master_secp256k1(&seed);

        assert_secp256k1_curve(
            &master,
            vec![
                vec![
                    "m",
                    "00000000",
                    "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                ],
                vec![
                    "m/0'",
                    "3442193e",
                    "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                    "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                ],
                vec![
                    "m/0'/1",
                    "5c1bd648",
                    "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                    "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
                ],
                vec![
                    "m/0'/1/2'",
                    "bef5a2f9",
                    "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                    "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                    "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
                ],
                vec![
                    "m/0'/1/2'/2",
                    "ee7ab90c",
                    "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                    "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                    "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
                ],
                vec![
                    "m/0'/1/2'/2/1000000000",
                    "d880d7d8",
                    "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                    "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                    "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
                ],
            ],
        );
    }

    #[test]
    fn secp256k1_vector_2() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = ExtSecretKey::new_master_secp256k1(&seed);

        assert_secp256k1_curve(
            &master,
            vec![
                vec![
                    "m",
                    "00000000",
                    "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                    "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                    "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
                ],
                vec![
                    "m/0",
                    "bd16bee5",
                    "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                    "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                    "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
                ],
                vec![
                    "m/0/2147483647'",
                    "5a61ff8e",
                    "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                    "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                    "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
                ],
                vec![
                    "m/0/2147483647'/1",
                    "d8ab4937",
                    "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                    "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                    "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
                ],
                vec![
                    "m/0/2147483647'/1/2147483646'",
                    "78412e3a",
                    "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                    "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                    "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
                ],
                vec![
                    "m/0/2147483647'/1/2147483646'/2",
                    "31a507b8",
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                    "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
                ],
            ],
        );
    }

    fn assert_ed25519_curve(master: &ExtSecretKey, asserts: Vec<Vec<&str>>) {
        for mut assert in asserts {
            let chain = master
                .derive_priv(&DerivationPath::from_str(assert[0]).unwrap())
                .unwrap()
                .to_ed25519()
                .unwrap();
            assert_eq_ed25519_elem(&chain, assert.drain(1..).collect());
        }
    }

    fn assert_eq_ed25519_elem(res: &Ed25519ExtSecretKey, asserts: Vec<&str>) {
        assert_eq!(asserts[0], res.parent_fingerprint.to_string());
        assert_eq!(asserts[1], res.chain_code.to_string());
        assert_eq!(asserts[2], hex::encode(res.secret_key));
        assert_eq!(asserts[3], hex::encode(res.serialized_public_key()));
    }

    #[test]
    fn ed25519_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtSecretKey::new_master_ed25519(&seed);

        assert_ed25519_curve(
            &master,
            vec![
                vec![
                    "m",
                    "00000000",
                    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                    "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
                ],
                vec![
                    "m/0'",
                    "ddebc675",
                    "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                ],
                vec![
                    "m/0'/1'",
                    "13dab143",
                    "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                ],
                vec![
                    "m/0'/1'/2'",
                    "ebe4cb29",
                    "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                ],
                vec![
                    "m/0'/1'/2'/2'",
                    "316ec1c6",
                    "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                ],
                vec![
                    "m/0'/1'/2'/2'/1000000000'",
                    "d6322ccd",
                    "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                ],
            ],
        );
    }

    #[test]
    fn ed25519_vector_2() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = ExtSecretKey::new_master_ed25519(&seed);

        assert_ed25519_curve(
            &master,
            vec![
                vec![
                    "m",
                    "00000000",
                    "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                    "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                    "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
                ],
                vec![
                    "m/0'",
                    "31981b50",
                    "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                    "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                    "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
                ],
                vec![
                    "m/0'/2147483647'",
                    "1e9411b1",
                    "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                    "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                    "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
                ],
                vec![
                    "m/0'/2147483647'/1'",
                    "fcadf38c",
                    "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                    "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                    "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
                ],
                vec![
                    "m/0'/2147483647'/1'/2147483646'",
                    "aca70953",
                    "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                    "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                    "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                ],
                vec![
                    "m/0'/2147483647'/1'/2147483646'/2'",
                    "422c654b",
                    "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                    "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                    "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                ],
            ],
        );
    }
}
