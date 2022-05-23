use bitcoincore_rpc::{Auth, Client};
use std::env;
use std::path::PathBuf;

lazy_static::lazy_static! {
    pub static ref CLIENT: Client =  {
        let ctx = env::var("CI").unwrap_or("false".into());
        let host = env::var("RPC_HOST").unwrap_or("127.0.0.1".into());
        let port = env::var("RPC_PORT").unwrap_or("18443".into());
        if ctx == "false" {
            let u = env::var("RPC_USER").unwrap();
            let p = env::var("RPC_PASS").unwrap();
            Client::new(
                format!("http://{}:{}", host, port).as_str(),
                Auth::UserPass(u, p),
            ).unwrap()
        } else {
            let cookie = env::var("RPC_COOKIE").unwrap_or("/data/regtest/.cookie".into());
            let path = PathBuf::from(cookie);
            Client::new(
                format!("http://{}:{}", host, port).as_str(),
                Auth::CookieFile(path),
            ).unwrap()
        }
    };
}

macro_rules! gen_to_add {
    ($num:expr => $add:expr) => (
        rpc::CLIENT.generate_to_address($num, &$add).unwrap()
    );
    ($add:expr) => (
        gen_to_add!(1 => $add)
    );
}

macro_rules! get_block {
    ($block:expr) => {
        rpc::CLIENT.get_block(&$block).unwrap()
    };
}

macro_rules! fund_address {
    ($add:expr) => {{
        let blocks = gen_to_add!($add);
        let block = get_block!(blocks[0]);
        block.coinbase().unwrap().clone()
    }};
}

macro_rules! new_address {
    () => {{
        use bitcoin::network::constants::Network;
        use bitcoin::secp256k1::rand::thread_rng;
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::util::address::Address;
        use bitcoin::util::key;

        // Generate random key pair
        let s = Secp256k1::new();
        let pair = s.generate_keypair(&mut thread_rng());
        let public_key = key::PublicKey {
            compressed: true,
            inner: pair.1,
        };

        // Generate pay-to-pubkey-hash address
        (
            Address::p2pkh(&public_key, Network::Regtest),
            pair.1,
            pair.0,
        )
    }};
}

macro_rules! send {
    ($tx:expr) => {
        rpc::CLIENT.send_raw_transaction(&$tx).unwrap()
    };
}

macro_rules! mine {
    () => {{
        mine!(1)
    }};

    ($num:literal) => {{
        gen_to_add!($num => new_address!().0)
    }};
}

macro_rules! rpc {
    () => {};

    ( $(then)? mine $nb:expr; $($tail:tt)* ) => {
        {
            mine!($nb);
            rpc!($($tail)*);
        }
    };

    ( $(then)? broadcast $tx:expr; $($tail:tt)* ) => {
        {
            send!($tx);
            rpc!($($tail)*);
        }
    };
}
