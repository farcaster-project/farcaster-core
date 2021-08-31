#!/bin/bash

cd ..

ID=$(docker create -p 18443:18443\
    --env NETWORK=regtest\
    --env RPC_USER=test\
    --env RPC_PASS=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=\
    --env FALLBACKFEE=0.00001\
    ghcr.io/farcaster-project/containers/bitcoin-core:latest)

docker start $ID

export RPC_HOST=127.0.0.1 RPC_PORT=18443 RPC_USER=test RPC_PASS=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=
cargo test --test transactions --features rpc -- --test-threads=1

docker kill $ID
docker container rm $ID
cd -
