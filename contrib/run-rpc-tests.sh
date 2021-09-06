#!/bin/bash

cd ..

docker volume create --name bitcoind-data

ID=$(docker create -p 18443:18443\
    --name bitcoind\
    --env NETWORK=regtest\
    --env FALLBACKFEE=0.00001\
    --env RPC_PORT=18443\
    -v bitcoind-data:/data\
    ghcr.io/farcaster-project/containers/bitcoin-core:latest)

docker start $ID

docker run --rm\
    --link bitcoind\
    --volumes-from bitcoind\
    -v "$PWD":/usr/src/myapp\
    -w /usr/src/myapp\
    --env RPC_HOST=bitcoind\
    rust:1.54.0\
    cargo test --test transactions --features rpc -- --test-threads=1

docker kill $ID
docker container rm $ID

docker volume rm bitcoind-data

cd -
