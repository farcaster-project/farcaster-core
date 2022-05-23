#!/bin/bash

cd ..

docker pull ghcr.io/farcaster-project/containers/bitcoin-core:23.0
docker run --rm -d -p 18443:18443 --name=bitcoind ghcr.io/farcaster-project/containers/bitcoin-core:23.0\
    /usr/bin/bitcoind\
    -regtest\
    -server\
    -fallbackfee=0.00001\
    -rpcbind=0.0.0.0\
    -rpcallowip=0.0.0.0/0\
    -rpcuser=test\
    -rpcpassword=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=

res="null"
while [[ "$res" = "null" ]]
do
    echo "Wating for node to start..."
    rpc=$(curl --user test:cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k= --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockhash", "params": [0]}' -H 'content-type: text/plain;' http://127.0.0.1:18443/) || sleep 1
    if [ "$rpc" = "" ]; then
        continue
    fi
    res=$(echo "$rpc" | jq '.result')
done

export CI=false RPC_USER=test RPC_PASS=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=
cargo test --test transactions --features rpc -- --test-threads=1

docker kill bitcoind

cd -
