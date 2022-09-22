#!/bin/bash

power=8
cli="/Users/chao/opensource/appliedzkp/snarkjs/cli.cjs"

echo $snarkjs
echo "powers of tau ceremony..."
node $cli powersoftau new bn128 $power "pot"$power"_0.ptau" -v

echo "phase2..."
node $cli powersoftau prepare phase2 "pot"$power"_0.ptau" "pot"$power"_final.ptau" -v




