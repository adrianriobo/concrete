use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    "The error used in the [`LweNegationEngine`] trait.",
    LweNegationError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform out-of-place lwe negation.
pub trait LweNegationEngine<Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    fn lwe_neg(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
    ) -> Result<(), LweNegationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_neg_unchecked(&mut self, output: &mut Ciphertext, input: &Ciphertext);
}
