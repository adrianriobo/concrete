use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;
use concrete_commons::parameters::LweDimension;

engine_error! {
    "The error used in the [`LweAllocationEngine`] trait.",
    LweAllocationError @
    MemoryExhausted => "Not enough memory left to allocate the entity."
}
/// A trait for engines performing allocations of lwe ciphertexts.
pub trait LweAllocationEngine<Output>: AbstractEngine
where
    Output: LweCiphertextEntity,
{
    /// A safe entry point for allocating lwe ciphertexts.
    fn allocate_lwe(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<Output, LweAllocationError<Self::EngineError>>;

    /// An unsafe entry point for allocating lwe ciphertexts.
    ///
    /// # Safety
    ///
    /// See the documentation of the implementation for the engine you intend to use for details on
    /// the safety of this function.
    unsafe fn allocate_lwe_unchecked(&mut self, lwe_dimension: LweDimension) -> Output;
}
