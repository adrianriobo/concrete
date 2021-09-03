use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    "The error used in the [`LweAdditionEngine`] trait.",
    LweAdditionError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform out-of-place lwe addition.
pub trait LweAdditionEngine<Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    fn lwe_add(
        &mut self,
        output: &mut Ciphertext,
        input_1: &Ciphertext,
        input_2: &Ciphertext,
    ) -> Result<(), LweAdditionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_add_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input_1: &Ciphertext,
        input_2: &Ciphertext,
    );
}
