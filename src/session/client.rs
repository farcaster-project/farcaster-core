//! Pre-session and session living in the client.
//! Manage private keys.

use curve25519_dalek::scalar::Scalar;
use monero::util::key::PrivateKey;
use secp256k1::key::SecretKey;

use crate::blockchain::{bitcoin::Bitcoin, monero::Monero};
use crate::crypto::{Crypto, CryptoEngine, ECDSAScripts};
use crate::role::{Accordant, Arbitrating};

#[derive(Clone)]
pub struct AlicePreSessionParameters<Ar>
where
    Ar: Arbitrating,
{
    pub destination_address: Ar::Address,
}

//impl PreSessionParameters for Alice {
//    type Parameters = AlicePreSessionParameters<Bitcoin>;
//}

#[derive(Clone)]
pub struct BobPreSessionParameters<Ar>
where
    Ar: Arbitrating,
{
    pub refund_address: Ar::Address,
}

//impl PreSessionParameters for Bob {
//    type Parameters = BobPreSessionParameters<A>;
//}

pub struct AliceSessionParameters<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    pub buy: Ar::PrivateKey,
    pub cancel: Ar::PrivateKey,
    pub refund: Ar::PrivateKey,
    pub punish: Ar::PrivateKey,
    pub spend: Ac::PrivateKey,
    pub view: Ac::PrivateKey,
}

impl AliceSessionParameters<Bitcoin, Monero, ECDSAScripts> {
    pub fn new() -> Self {
        let (buy, cancel, refund, punish) = {
            use secp256k1::rand::rngs::OsRng;
            let mut rng = OsRng::new().expect("OsRng");

            (
                SecretKey::new(&mut rng),
                SecretKey::new(&mut rng),
                SecretKey::new(&mut rng),
                SecretKey::new(&mut rng),
            )
        };

        let (spend, view) = {
            let mut csprng = rand_core::OsRng;

            (
                PrivateKey::from_scalar(Scalar::random(&mut csprng)),
                PrivateKey::from_scalar(Scalar::random(&mut csprng)),
            )
        };

        AliceSessionParameters {
            buy,
            cancel,
            refund,
            punish,
            spend,
            view,
        }
    }
}

//impl SessionParameters for Alice {
//    type Parameters = AliceSessionParameters<Bitcoin, Monero, ECDSAScripts>;
//}

pub struct BobSessionParameters<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    pub fund: Ar::PrivateKey,
    pub buy: Ar::PrivateKey,
    pub cancel: Ar::PrivateKey,
    pub refund: Ar::PrivateKey,
    pub spend: Ac::PrivateKey,
    pub view: Ac::PrivateKey,
}

impl BobSessionParameters<Bitcoin, Monero, ECDSAScripts> {
    pub fn new() -> Self {
        let (fund, buy, cancel, refund) = {
            use secp256k1::rand::rngs::OsRng;
            let mut rng = OsRng::new().expect("OsRng");

            (
                SecretKey::new(&mut rng),
                SecretKey::new(&mut rng),
                SecretKey::new(&mut rng),
                SecretKey::new(&mut rng),
            )
        };

        let (spend, view) = {
            let mut csprng = rand_core::OsRng;

            (
                PrivateKey::from_scalar(Scalar::random(&mut csprng)),
                PrivateKey::from_scalar(Scalar::random(&mut csprng)),
            )
        };

        BobSessionParameters {
            fund,
            buy,
            cancel,
            refund,
            spend,
            view,
        }
    }
}

//impl SessionParameters for Bob {
//    type Parameters = BobSessionParameters;
//}

//#[cfg(test)]
//mod tests {
//    use super::{Alice, AlicePreSessionParameters, AliceSessionParameters, PreSession};
//
//    #[test]
//    fn create_presession() {
//        let params = AlicePreSessionParameters {
//            destination_address: String::from("bc1qndk902ka3266wzta9cnl4fgfcmhy7xqrdh26ka"),
//        };
//        let pre_session = PreSession::<Alice>::new(params);
//        let session_params = AliceSessionParameters::new();
//        let _session = pre_session.into_session(session_params);
//    }
//}
