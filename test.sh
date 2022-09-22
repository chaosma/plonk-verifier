#!/bin/bash

#export CARGO_TARGET_DIR=/data/plonk-verifier/target
#RUSTFLAGS=-Awarnings cargo test util::parser::tests::test -- --nocapture 
#RUSTFLAGS=-Awarnings cargo test protocol::halo2::test::kzg::native::test_kzg_plonk_zk_main_gate_with_range_with_mock_kzg_accumulator -- --nocapture

RUSTFLAGS=-Awarnings cargo test protocol::halo2::test::kzg::circom_plonk::tests::circom_accumulation_native -- --nocapture
#RUSTFLAGS=-Awarnings cargo test protocol::halo2::test::kzg::circom_plonk::tests::transcript_squeeze -- --nocapture
