#!/bin/bash

input="input"$2".json"
vkey="vkey"$2".json"

power=8
cli="/Users/chao/opensource/appliedzkp/snarkjs/cli.cjs"

echo "removing old folder..."
rm -r $1_js
echo "compiling..."
circom $1.circom --r1cs --wasm --sym 
echo "gen witness..."
node $1_js/generate_witness.js $1_js/$1.wasm $input witness.wtns

# groth16
#echo "setup zkeys..."
#snarkjs groth16 setup $1.r1cs "pot"$power"_final.ptau" $1_0.zkey
#echo "verify zkeys..."
#snarkjs zkv $1.r1cs "pot"$power"_final.ptau" $1_0.zkey
#echo "export vkeys..."
#snarkjs zkey export verificationkey $1_0.zkey vkey.json
#echo "prove..."
#snarkjs groth16 prove $1_0.zkey witness.wtns proof.json public.json
#echo "verify..."
#snarkjs groth16 verify vkey.json public.json proof.json

# plonk
echo "create plonk zkey..."
node $cli plonk setup $1.r1cs "pot"$power"_final.ptau" $1_p.zkey
echo "export plonk vkey..."
node $cli zkey export verificationkey $1_p.zkey $vkey
echo "prove..."
node $cli -v plonk prove $1_p.zkey witness.wtns proof.json public.json
echo "verify..."
node $cli -v plonk verify $vkey public.json proof.json

#rm proof"$2".json public"$2".json
#cp proof.json  proof"$2".json
#cp public.json  public"$2".json
#cp public"$2".json proof"$2".json ../src/fixture/
