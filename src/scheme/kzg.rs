use crate::{
    protocol::Protocol,
    util::{Curve, Expression},
};

mod accumulation;
mod msm;

pub use accumulation::{
    plonk::PlonkAccumulationScheme, shplonk::ShplonkAccumulationScheme, AccumulationScheme,
    AccumulationStrategy, Accumulator, SameCurveAccumulation,
};
pub use msm::MSM;

/// chao: let [i,j] = [sum(relations), max(statement)], return l_i, l_j
pub fn lagranges<C: Curve, T>(
    protocol: &Protocol<C>,
    statements: &[Vec<T>],
) -> impl IntoIterator<Item = i32> {
    protocol
        .relations
        .iter()
        .cloned()
        .sum::<Expression<_>>()
        .used_langrange()
        .into_iter()
        .chain(
            0..statements
                .iter()
                .map(|statement| statement.len())
                .max()
                .unwrap_or_default() as i32,
        )
}
