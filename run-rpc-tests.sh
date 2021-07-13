#!/bin/bash

ID=$(docker run --rm -d -p 18443:18443 coblox/bitcoin-core\
    -regtest\
    -server\
    -rpcbind=0.0.0.0\
     -rpcallowip=0.0.0.0/0\
    -rpcuser=test\
    -rpcpassword=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=)

RPC_HOST=127.0.0.1 RPC_PORT=18443 RPC_USER=ci RPC_PASS=cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k= cargo test --test transactions --features rpc -- --test-threads=1 --nocapture


docker kill $ID
