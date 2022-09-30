#!/bin/bash

RUSTFLAGS=-Awarnings cargo test protocol::halo2::test::kzg::circom_plonk::tests::circom_accumulation_native -- --nocapture
#RUSTFLAGS=-Awarnings cargo test protocol::halo2::test::kzg::circom_plonk::tests::transcript_squeeze -- --nocapture
#RUSTFLAGS=-Awarnings cargo test util::parser::tests::test_squeeze -- --nocapture
#RUSTFLAGS=-Awarnings cargo test util::parser::tests::test_to_affine -- --nocapture

#RUSTFLAGS=-Awarnings cargo test protocol::halo2::test::kzg::circom_plonk::tests::circom_accumulation_halo2_constraints -- --nocapture
