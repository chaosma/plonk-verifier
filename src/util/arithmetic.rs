use crate::util::Itertools;
use num_bigint::BigUint;
use num_traits::One;
use std::{
    cmp::Ordering,
    fmt::Debug,
    iter, mem,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub use ff::{BatchInvert, Field, PrimeField};
pub use group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding};

pub trait GroupOps:
    Sized
    + Add<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + AddAssign
    + SubAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
}

impl<T> GroupOps for T where
    T: Sized
        + Add<Output = Self>
        + Sub<Output = Self>
        + Neg<Output = Self>
        + for<'a> Add<&'a Self, Output = Self>
        + for<'a> Sub<&'a Self, Output = Self>
        + AddAssign
        + SubAssign
        + for<'a> AddAssign<&'a Self>
        + for<'a> SubAssign<&'a Self>
{
}

pub trait FieldOps:
    Sized
    + GroupOps
    + Mul<Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign
    + for<'a> MulAssign<&'a Self>
{
    fn invert(&self) -> Option<Self>;
}

pub fn batch_invert_and_mul<F: PrimeField>(values: &mut [F], coeff: &F) {
    let products = values
        .iter()
        .filter(|value| !value.is_zero_vartime())
        .scan(F::one(), |acc, value| {
            *acc *= value;
            Some(*acc)
        })
        .collect_vec();

    let mut all_product_inv = products.last().unwrap().invert().unwrap() * coeff;

    for (value, product) in values
        .iter_mut()
        .rev()
        .filter(|value| !value.is_zero_vartime())
        .zip(products.into_iter().rev().skip(1).chain(Some(F::one())))
    {
        let mut inv = all_product_inv * product;
        mem::swap(value, &mut inv);
        all_product_inv *= inv;
    }
}

pub fn batch_invert<F: PrimeField>(values: &mut [F]) {
    batch_invert_and_mul(values, &F::one())
}

pub fn root_of_unity<F: PrimeField>(k: usize) -> F {
    assert!(k <= F::S as usize);

    iter::successors(Some(F::root_of_unity()), |acc| Some(acc.square()))
        .take(F::S as usize - k + 1)
        .last()
        .unwrap()
}

pub trait UncompressedEncoding: Sized {
    type Uncompressed: AsRef<[u8]> + AsMut<[u8]>;

    fn to_uncompressed(&self) -> Self::Uncompressed;

    fn from_uncompressed(uncompressed: Self::Uncompressed) -> Option<Self>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rotation(pub i32);

impl Rotation {
    pub fn cur() -> Self {
        Rotation(0)
    }

    pub fn prev() -> Self {
        Rotation(-1)
    }

    pub fn next() -> Self {
        Rotation(1)
    }
}

impl From<i32> for Rotation {
    fn from(rotation: i32) -> Self {
        Self(rotation)
    }
}

pub enum DomainType {
    Circom,
    Halo2,
}

pub fn circom_gen<F: PrimeField>(k: usize) -> F {
    let modulus = BigUint::from_bytes_le((-F::one()).to_repr().as_ref()) + BigUint::one();
    let modulus_half = (modulus.clone() / BigUint::from(2_u32)).to_u64_digits();
    let t = ((modulus - BigUint::one()) / BigUint::from(2_u32).pow(F::S)).to_u64_digits();
    let mut nqr = F::one();
    while nqr.pow_vartime(modulus_half.clone()) == F::one() {
        nqr += F::one();
    }
    let mut omega = nqr.pow_vartime(t);
    (0..(F::S - k as u32)).for_each(|_| {
        omega = omega.square();
    });
    omega
}

pub fn halo2_gen<F: PrimeField>(k: usize) -> F {
    iter::successors(Some(F::root_of_unity()), |acc| Some(acc.square()))
        .take(F::S as usize - k + 1)
        .last()
        .unwrap()
}

#[derive(Clone, Debug)]
pub struct Domain<F: PrimeField> {
    pub k: usize,
    pub n: usize,
    pub n_inv: F,
    pub gen: F,
    pub gen_inv: F,
}

impl<F: PrimeField> Domain<F> {
    pub fn new(k: usize, gen_type: DomainType) -> Self {
        let n = 1 << k;
        let n_inv = F::from(n as u64).invert().unwrap();
        let gen = match gen_type {
            DomainType::Circom => circom_gen::<F>(k),
            DomainType::Halo2 => halo2_gen::<F>(k),
        };
        debug_assert_eq!(gen.pow_vartime([n as u64]), F::one());
        let gen_inv = gen.invert().unwrap();

        Self {
            k,
            n,
            n_inv,
            gen,
            gen_inv,
        }
    }

    pub fn rotate_scalar(&self, scalar: F, rotation: Rotation) -> F {
        match rotation.0.cmp(&0) {
            Ordering::Equal => scalar,
            Ordering::Greater => scalar * self.gen.pow_vartime(&[rotation.0 as u64]),
            Ordering::Less => scalar * self.gen_inv.pow_vartime(&[(-rotation.0) as u64]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Fraction<F> {
    numer: Option<F>,
    denom: F,
    inv: bool,
}

impl<F> Fraction<F> {
    pub fn new(numer: F, denom: F) -> Self {
        Self {
            numer: Some(numer),
            denom,
            inv: false,
        }
    }

    pub fn one_over(denom: F) -> Self {
        Self {
            numer: None,
            denom,
            inv: false,
        }
    }

    pub fn denom(&self) -> Option<&F> {
        if !self.inv {
            Some(&self.denom)
        } else {
            None
        }
    }

    pub fn denom_mut(&mut self) -> Option<&mut F> {
        if !self.inv {
            self.inv = true;
            Some(&mut self.denom)
        } else {
            None
        }
    }
}

impl<F: FieldOps + Clone> Fraction<F> {
    pub fn evaluate(&self) -> F {
        let denom = if self.inv {
            self.denom.clone()
        } else {
            self.denom.invert().unwrap()
        };
        self.numer
            .clone()
            .map(|numer| numer * &denom)
            .unwrap_or(denom)
    }
}

pub fn modulus<F: PrimeField>() -> BigUint {
    fe_to_big(-F::one()) + 1usize
}

pub fn fe_from_big<F: PrimeField>(big: BigUint) -> F {
    let bytes = big.to_bytes_le();
    let mut repr = F::Repr::default();
    assert!(bytes.len() <= repr.as_ref().len());
    repr.as_mut()[..bytes.len()].clone_from_slice(bytes.as_slice());
    F::from_repr(repr).unwrap()
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn fe_to_fe<F1: PrimeField, F2: PrimeField>(fe: F1) -> F2 {
    fe_from_big(fe_to_big(fe) % modulus::<F2>())
}

pub fn fe_from_limbs<F1: PrimeField, F2: PrimeField, const LIMBS: usize, const BITS: usize>(
    limbs: [F1; LIMBS],
) -> F2 {
    fe_from_big(
        limbs
            .iter()
            .map(|limb| BigUint::from_bytes_le(limb.to_repr().as_ref()))
            .zip((0usize..).step_by(BITS))
            .map(|(limb, shift)| limb << shift)
            .reduce(|acc, shifted| acc + shifted)
            .unwrap(),
    )
}

pub fn fe_to_limbs<F1: PrimeField, F2: PrimeField, const LIMBS: usize, const BITS: usize>(
    fe: F1,
) -> [F2; LIMBS] {
    let big = BigUint::from_bytes_le(fe.to_repr().as_ref());
    let mask = (BigUint::one() << BITS) - 1usize;
    (0usize..)
        .step_by(BITS)
        .take(LIMBS)
        .map(move |shift| fe_from_big((&big >> shift) & &mask))
        .collect_vec()
        .try_into()
        .unwrap()
}
