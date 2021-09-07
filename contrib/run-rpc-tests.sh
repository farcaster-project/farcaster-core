#!/bin/bash

cd ..

ID=$(docker run --rm -d -p 18443:18443 coblox/bitcoin-core\
    -regtest\
    -server\
    -fallbackfee=0.00001\
    -rpcbind=0.0.0.0\
    -rpcallowip=0.0.0.0/0\
    -rpcuser=test\
    -rpcpassword=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=)

export CI=false RPC_USER=test RPC_PASS=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=
cargo test --test transactions --features rpc -- --test-threads=1

docker kill $ID

cd -
