use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    "The error used in the [`LweAdditionInplaceEngine`] trait.",
    LweInplaceAdditionError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform inplace lwe addition.
pub trait LweAdditionInplaceEngine<Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    fn lwe_add_inplace(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_add_inplace_unchecked(&mut self, output: &mut Ciphertext, input: &Ciphertext);
}
