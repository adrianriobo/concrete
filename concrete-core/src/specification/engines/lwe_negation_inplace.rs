use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    "The error used in the [`LweNegationInplaceEngine`] trait.",
    LweNegationInplaceError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform inplace lwe negation.
pub trait LweNegationInplaceEngine<Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    fn lwe_neg_inplace(
        &mut self,
        input: &mut Ciphertext,
    ) -> Result<(), LweNegationInplaceError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_neg_inplace_unchecked(&mut self, input: &mut Ciphertext);
}
