#!/bin/bash

cargo test --test transactions --features rpc -- --test-threads=1
