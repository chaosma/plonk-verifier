use std::{rc::Rc, vec};

use crate::{
    loader::halo2::{self},
    protocol::halo2::test::{
        kzg::{BITS, LIMBS},
        MainGateWithRangeConfig,
    },
    scheme::kzg::{self, CircomPlonkAccumulationScheme},
};
use group::Curve;
use halo2_curves::CurveAffine;
use halo2_curves::bn256::{Fr, Fq, G1Affine, G1};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{self, Circuit},
};
//use halo2_wrong_maingate::RegionCtx;
use halo2_wrong_transcript::NativeRepresentation;
use itertools::Itertools;
use halo2_wrong_ecc::{
    integer::rns::Rns,
    maingate::{RangeInstructions, RegionCtx},
};

const T: usize = 17;
const RATE: usize = 16;
const R_F: usize = 8;
const R_P: usize = 10;

type SameCurveAccumulation<C, L> = kzg::SameCurveAccumulation<C, L, LIMBS, BITS>;
type PoseidonTranscript<C, L, S, B> =
    halo2::PoseidonTranscript<C, <C as CurveAffine>::ScalarExt, NativeRepresentation, L, S, B, LIMBS, BITS, T, RATE, R_F, R_P>;
type BaseFieldEccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<C, LIMBS, BITS>;
type Halo2Loader<'a, C> =
    halo2::Halo2Loader<'a, C, <C as CurveAffine>::ScalarExt, BaseFieldEccChip<C>>;

pub struct SnarkWitness<C: Curve> {
    protocol: kzg::CircomProtocol<C>,
    proof: Value<Vec<u8>>,
    public_signals: Vec<Value<C::Scalar>>,
}

impl<C: Curve> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            proof: Value::unknown(),
            public_signals: vec![Value::unknown(); self.public_signals.len()],
        }
    }
}

fn accumulate<'a>(
    loader: &Rc<Halo2Loader<'a, G1Affine>>,
    strategy: &mut SameCurveAccumulation<G1, Rc<Halo2Loader<'a, G1Affine>>>,
    snark: &SnarkWitness<G1>,
) -> Result<(), plonk::Error> {
    let mut transcript = PoseidonTranscript::<G1Affine, Rc<Halo2Loader<G1Affine>>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let public_signals = snark
        .public_signals
        .iter()
        .map(|signal| loader.assign_scalar(*signal))
        .collect_vec();

    CircomPlonkAccumulationScheme::accumulate(
        &snark.protocol,
        loader,
        &public_signals,
        &mut transcript,
        strategy,
    )
    .map_err(|_| plonk::Error::Synthesis)?;

    Ok(())
}

struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
}

impl Accumulation {}

impl Circuit<Fr> for Accumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::configure::<Fr>(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        //let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        println!("snrks {}", self.snarks.len());
        let (lhs, rhs) = layouter.assign_region(
            || "",
            |region| {
                let offset = 0;
                let ctx = RegionCtx::new(region, offset);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::<G1Affine>::new(ecc_chip, ctx);
                let mut strategy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    accumulate(&loader, &mut strategy, snark)?;
                }
                let (lhs, rhs) = strategy.finalize(self.g1);

                loader.print_row_metering();
                println!("Total row cost: {}", loader.ctx().offset());

                Ok((lhs, rhs))
            },
        )?;

        let ecc_chip = config.ecc_chip::<G1Affine, LIMBS, BITS>();
        //let ecc_chip = BaseFieldEccChip::<G1Affine>::new(config);
        ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        loader::{native::NativeLoader, ScalarLoader},
        util::{fe_to_limbs, read_proof_instances, read_protocol, read_public_signals},
    };
    use halo2_curves::bn256::{Bn256, Fq, G2Affine};
    use halo2_kzg_srs::{Srs, SrsFormat};
    use halo2_proofs::dev::MockProver;
    use std::fs::File;

    fn prepare(
        protocol: &str,
        proofs: Vec<String>,
        public_singals: Vec<String>,
    ) -> (
        kzg::CircomProtocol<G1>,
        Vec<(Vec<u8>, Vec<Fr>)>,
        SameCurveAccumulation<G1, NativeLoader>,
    ) {
        let protocol = read_protocol(protocol);
        let native_snarks: Vec<(Vec<u8>, Vec<Fr>)> = read_proof_instances(proofs)
            .iter()
            .zip(read_public_signals(public_singals))
            .map(|(proof, public)| (proof.clone(), public))
            .collect();

        // Perform `Native` to check validity and calculate instance values.
        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        let native_loader = NativeLoader {};
        for snark in native_snarks.clone() {
            CircomPlonkAccumulationScheme::accumulate(
                &protocol,
                &native_loader,
                &snark
                    .1
                    .iter()
                    .map(|el| native_loader.load_const(el))
                    .collect(),
                &mut PoseidonTranscript::<G1Affine, NativeLoader, _, _>::new(snark.0.as_slice()),
                &mut strategy,
            )
            .unwrap();
        }

        (protocol, native_snarks, strategy)
    }

    #[test]
    fn circom_accumulation_halo2_constraints() {
        let (protocol, native_snarks, strategy) = prepare(
            "./src/fixture/verification_key.json",
            vec![
                "./src/fixture/proof1.json".to_string(),
                "./src/fixture/proof2.json".to_string(),
            ],
            vec![
                "./src/fixture/public1.json".to_string(),
                "./src/fixture/public2.json".to_string(),
            ],
        );

        // Obtain lhs and rhs accumulator
        let (lhs, rhs) = strategy.finalize(G1::generator());
        let instance = [
            lhs.to_affine().x,
            lhs.to_affine().y,
            rhs.to_affine().x,
            rhs.to_affine().y,
        ]
        .map(fe_to_limbs::<Fq, Fr, LIMBS, BITS>)
        .concat();

        // Test the circuit
        let snarks: Vec<SnarkWitness<G1>> = native_snarks
            .iter()
            .map(|(proof, public)| SnarkWitness {
                protocol: protocol.clone(),
                proof: Value::known(proof.clone()),
                public_signals: public.iter().map(|v| Value::known(*v)).collect(),
            })
            .collect();
        let circuit = Accumulation {
            g1: G1Affine::generator(),
            snarks,
        };
        let k = 20;
        MockProver::run(k, &circuit, vec![instance])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn circom_accumulation_native() {
        let (_, _, strategy) = prepare(
            "./src/fixture/verification_key.json",
            vec![
                "./src/fixture/proof1.json".to_string(),
                "./src/fixture/proof2.json".to_string(),
            ],
            vec![
                "./src/fixture/public1.json".to_string(),
                "./src/fixture/public2.json".to_string(),
            ],
        );

        let srs = Srs::<Bn256>::read(
            &mut File::open("./src/fixture/pot.ptau").unwrap(),
            SrsFormat::SnarkJs,
        );

        let d = strategy.decide::<Bn256>(G1Affine::generator(), G2Affine::generator(), srs.s_g2);
        println!("{} isValid", d);
        assert!(d);
    }

    #[test]
    fn transcript_squeeze() {
       use halo2_curves::bn256::Fr;
       use halo2_curves::CurveAffine;
       use poseidon::{Poseidon, Spec};
       let mut hasher = Poseidon::<Fr,T,RATE>::new(R_F, R_P);
       let trial:[[u8;32];3] = [[
          102, 220, 242, 23, 171, 87, 162, 223, 228, 126, 83, 45, 179, 123, 168,
          203, 227, 213, 116, 133, 203, 47, 118, 106, 119, 191, 140, 195, 126,
          190, 63, 38,
          ],
          [
          57, 71, 210, 142, 121, 28, 206, 98, 154, 21, 30, 215, 182, 239, 122,
          182, 24, 65, 34, 28, 85, 132, 222, 98, 140, 156, 140, 59, 183, 168, 240,
          6],
          [
          209, 235, 9, 194, 64, 193, 120, 96, 203, 189, 172, 74, 90, 238, 182, 8,
          204, 15, 73, 18, 159, 238, 224, 41, 65, 15, 53, 172, 208, 118, 244, 0,
      ]];
       let trial_r: Vec<_> = trial.into_iter().map(|elem|Fr::from_bytes(&elem).unwrap()).collect();
       hasher.update(&trial_r[..]);
       let res = hasher.squeeze();
       println!("res={:?}", res);
    }
}
