use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweSecretKeyEntity;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

engine_error! {
    "The error used in the [`GlweSecretKeyGenerationEngine`] trait.",
    GlweSecretKeyGenerationError @
    MemoryExhausted => "Not enough memory left to allocate the entity."
}

pub trait GlweSecretKeyGenerationEngine<Output>: AbstractEngine
where
    Output: GlweSecretKeyEntity,
{
    fn generate_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<Output, GlweSecretKeyGenerationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn generate_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Output;
}
