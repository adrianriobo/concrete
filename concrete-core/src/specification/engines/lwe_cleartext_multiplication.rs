use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{CleartextEntity, LweCiphertextEntity};

engine_error! {
    "The error used in the [`LweCleartextMultiplicationEngine`] trait.",
    LweCleartextMultiplicationError @
}
/// A trait for engines which perform out-of-place lwe scalar multiplication.
pub trait LweCleartextMultiplicationEngine<Ciphertext, Cleartext>: AbstractEngine
where
    Cleartext: CleartextEntity,
    Ciphertext: LweCiphertextEntity<Representation = Cleartext::Representation>,
{
    fn lwe_cleartext_mul(
        &mut self,
        output: &mut Ciphertext,
        input_1: &Ciphertext,
        input_2: &Cleartext,
    ) -> Result<(), LweCleartextMultiplicationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_cleartext_mul_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input_1: &Ciphertext,
        input_2: &Cleartext,
    );
}
