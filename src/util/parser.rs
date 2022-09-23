use super::{arithmetic::DomainType, Domain};
use crate::{scheme::kzg::CircomProtocol, util::GroupEncoding};
use ff::PrimeField;
use halo2_curves::bn256::{Fq, Fr, G1};
use itertools::Itertools;
use serde_json::Value;

pub fn json_to_bn256_g1(json: &Value, key: &str) -> G1 {
    let coords: Vec<String> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_string())
        .collect();
    assert_eq!(coords.len(), 3);

    let out = G1 {
        x: Fq::from_str_vartime(coords[0].as_str()).unwrap(),
        y: Fq::from_str_vartime(coords[1].as_str()).unwrap(),
        z: Fq::from_str_vartime(coords[2].as_str()).unwrap(),
    };

    out
}

pub fn json_to_bn256_fr(json: &Value, key: &str) -> Fr {
    let v = Fr::from_str_vartime(json.get(key).unwrap().as_str().unwrap()).unwrap();
    // println!("{}: {:#?}", key, v);
    v
}

pub fn json_to_proof_instance(json: &Value) -> Vec<u8> {
    std::iter::empty()
        .chain(json_to_bn256_g1(json, "A").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "B").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "C").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "Z").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "T1").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "T2").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "T3").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_fr(json, "eval_a").to_repr())
        .chain(json_to_bn256_fr(json, "eval_b").to_repr())
        .chain(json_to_bn256_fr(json, "eval_c").to_repr())
        .chain(json_to_bn256_fr(json, "eval_s1").to_repr())
        .chain(json_to_bn256_fr(json, "eval_s2").to_repr())
        .chain(json_to_bn256_fr(json, "eval_zw").to_repr())
        .chain(json_to_bn256_fr(json, "eval_r").to_repr())
        .chain(json_to_bn256_g1(json, "Wxi").to_bytes().as_ref().to_vec())
        .chain(json_to_bn256_g1(json, "Wxiw").to_bytes().as_ref().to_vec())
        .collect()
}

pub fn read_protocol(path: &str) -> CircomProtocol<G1> {
    let json = std::fs::read_to_string(path).unwrap();
    let json: Value = serde_json::from_str(&json).unwrap();

    CircomProtocol {
        domain: Domain::<Fr>::new(json.get("power").unwrap().as_u64().unwrap() as usize, DomainType::Circom),
        public_inputs_count: json.get("nPublic").unwrap().as_u64().unwrap() as usize,
        k1: json_to_bn256_fr(&json, "k1"),
        k2: json_to_bn256_fr(&json, "k2"),
        Qm: json_to_bn256_g1(&json, "Qm"),
        Ql: json_to_bn256_g1(&json, "Ql"),
        Qr: json_to_bn256_g1(&json, "Qr"),
        Qo: json_to_bn256_g1(&json, "Qo"),
        Qc: json_to_bn256_g1(&json, "Qc"),
        S1: json_to_bn256_g1(&json, "S1"),
        S2: json_to_bn256_g1(&json, "S2"),
        S3: json_to_bn256_g1(&json, "S3"),
    }
}

pub fn read_proof_instances(paths: Vec<String>) -> Vec<Vec<u8>> {
    paths
        .iter()
        .map(|path| {
            let json = std::fs::read_to_string(path.as_str()).unwrap();
            let json: Value = serde_json::from_str(&json).unwrap();
            json_to_proof_instance(&json)
        })
        .collect()
}

pub fn read_public_signals(paths: Vec<String>) -> Vec<Vec<Fr>> {
    paths
        .iter()
        .map(|path| {
            let json = std::fs::read_to_string(path.as_str()).unwrap();
            let json: Value = serde_json::from_str(&json).unwrap();
            json.as_array()
                .unwrap()
                .iter()
                .map(|i| i.as_str().unwrap())
                .into_iter()
                .map(|i| Fr::from_str_vartime(i).unwrap())
                .collect_vec()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read() {
        let protocol = read_protocol("./src/fixture/verification_key.json");
        println!("{:#?}", protocol.Qm);
    }

    #[test]
    fn test_squeeze() {
       use group::Curve;
       use halo2_wrong_transcript::PointRepresentation;
       use halo2_wrong_transcript::NativeRepresentation;
       use halo2_curves::bn256::Fr;
       use halo2_curves::CurveAffine;
       use poseidon::{Poseidon, Spec};
       use halo2_curves::bn256::G1Affine;

       const R_F: usize = 8;
       const R_P: usize = 10;
       const T: usize = 17;
       const RATE: usize = 16;
       const LIMBS: usize = 4;
       const BITS: usize = 68;
       let mut hasher = Poseidon::<Fr,T,RATE>::new(R_F, R_P);
       let coords:Vec<_> = vec![
           "14700933010115888325620158645526013374729828236601363662320783398388001474092",
           "16805675480775794632351858769706293094367449671446520952469983330053599939069",
           "1"
       ];
       let out = G1 {
            x: Fq::from_str_vartime(coords[0]).unwrap(),
            y: Fq::from_str_vartime(coords[1]).unwrap(),
            z: Fq::from_str_vartime(coords[2]).unwrap(),
        };
        let encoded = <NativeRepresentation as PointRepresentation<G1Affine, <G1Affine as CurveAffine>::ScalarExt, LIMBS, BITS>>::encode(out.to_affine()).unwrap();
        hasher.update(&encoded[..]);
        let res = hasher.squeeze();
        println!("res={:?}", res);

    }
}
