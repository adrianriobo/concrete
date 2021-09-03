use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

engine_error! {
    "The error used in the [`GlweAllocationEngine`] trait.",
    GlweAllocationError @
    MemoryExhausted => "Not enough memory left to allocate the entity."
}
pub trait GlweAllocationEngine<Output>: AbstractEngine
where
    Output: GlweCiphertextEntity,
{
    fn allocate_glwe(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<Output, GlweAllocationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn allocate_glwe_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Output;
}
