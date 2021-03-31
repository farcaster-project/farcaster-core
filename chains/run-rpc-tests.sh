#!/bin/bash

cargo test --test transactions --features rpc -- --show-output --test-threads=1
