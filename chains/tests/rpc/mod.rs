use bitcoincore_rpc::{Auth, Client};

lazy_static::lazy_static! {
    pub static ref CLIENT: Client =  {
        Client::new(
            "http://127.0.0.1:18443".into(),
            Auth::UserPass(
                "test".into(),
                "cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=".into(),
            ),
        ).unwrap()
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
            key: pair.1,
        };
        let private_key = key::PrivateKey {
            compressed: true,
            network: Network::Regtest,
            key: pair.0,
        };

        // Generate pay-to-pubkey-hash address
        (
            Address::p2pkh(&public_key, Network::Regtest),
            public_key,
            private_key,
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
