#!/bin/bash

export CARGO_TARGET_DIR=/data/plonk-verifier/target
RUSTFLAGS=-Awarnings cargo test util::parser::tests::test -- --nocapture 
