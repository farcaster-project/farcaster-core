#!/bin/bash

cd ~/.bitcoin
rm -rf regtest
cd -
bitcoind > /dev/null&
cargo test --test transactions --features rpc -- --test-threads=1
pkill bitcoind
