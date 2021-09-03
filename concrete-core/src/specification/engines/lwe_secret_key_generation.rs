use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweSecretKeyEntity;
use concrete_commons::parameters::LweDimension;

engine_error! {
    "The error used in the [`LweSecretKeyGenerationEngine`] trait.",
    LweSecretKeyGenerationError @
    MemoryExhausted => "Not enough memory left to allocate the entity."
}

pub trait LweSecretKeyGenerationEngine<Output>: AbstractEngine
where
    Output: LweSecretKeyEntity,
{
    fn generate_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<Output, LweSecretKeyGenerationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn generate_lwe_secret_key_unchecked(&mut self, lwe_dimension: LweDimension) -> Output;
}
