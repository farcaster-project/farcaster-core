#!/bin/bash

cd ..
cargo test -- --show-output --ignored --test-threads=1
