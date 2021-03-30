use bitcoincore_rpc::{Auth, Client};

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::key::{PrivateKey, PublicKey};

pub fn setup() -> Result<Client, bitcoincore_rpc::Error> {
    Client::new(
        "http://127.0.0.1:18443".into(),
        Auth::UserPass(
            "test".into(),
            "cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=".into(),
        ),
    )
}

pub fn keys() -> (
    Secp256k1<All>,
    PrivateKey,
    PublicKey,
    PrivateKey,
    PublicKey,
    PrivateKey,
    PublicKey,
    PrivateKey,
    PublicKey,
) {
    let secp = Secp256k1::new();

    let privkey_a: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let pubkey_a = PublicKey::from_private_key(&secp, &privkey_a);

    let privkey_b: PrivateKey =
        PrivateKey::from_wif("Kwe6eTweXYHsWX1yazBBCqB2eBSnqK6m8BPBvpJmv5pmuWi8nx1w").unwrap();
    let pubkey_b = PublicKey::from_private_key(&secp, &privkey_b);

    let privkey_a2: PrivateKey =
        PrivateKey::from_wif("Kx9uWX33oa5TbCc7Mo7vCM7yN75mehEw9aSkAeqJdC2kd1YKuKXR").unwrap();
    let pubkey_a2 = PublicKey::from_private_key(&secp, &privkey_a2);

    let privkey_b2: PrivateKey =
        PrivateKey::from_wif("L3ienZ4Zg1EP2HiiqsWih1Wkr3yuKJwTV5svqGMry1dYdrXQED8Q").unwrap();
    let pubkey_b2 = PublicKey::from_private_key(&secp, &privkey_b2);

    (
        secp, privkey_a, pubkey_a, privkey_b, pubkey_b, privkey_a2, pubkey_a2, privkey_b2,
        pubkey_b2,
    )
}

macro_rules! gen_to_add {
    ($num:expr => $add:ident with $client:ident) => (
        $client.generate_to_address($num, &$add).unwrap()
    );
    ($add:ident with $client:ident) => (
        gen_to_add!(1 => $add with $client)
    );
}

macro_rules! gen_new_add {
    () => {{
        use bitcoin::network::constants::Network;
        use bitcoin::secp256k1::rand::thread_rng;
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::util::address::Address;
        use bitcoin::util::key;

        // Generate random key pair
        let s = Secp256k1::new();
        let public_key = key::PublicKey {
            compressed: true,
            key: s.generate_keypair(&mut thread_rng()).1,
        };

        // Generate pay-to-pubkey-hash address
        Address::p2pkh(&public_key, Network::Regtest)
    }};
}

macro_rules! send {
    ($tx:ident with $client:ident) => {
        $client.send_raw_transaction(&$tx).unwrap()
    };
}
