use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    "The error used in the [`LwePlaintextAdditionEngine`] trait.",
    LwePlaintextAdditionError @
}

/// A trait for engines which perform out-of-place lwe addition.
pub trait LwePlaintextAdditionEngine<Ciphertext, Plaintext>: AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity<Representation = Plaintext::Representation>,
{
    fn lwe_plaintext_add(
        &mut self,
        output: &mut Ciphertext,
        input_1: &Ciphertext,
        input_2: &Plaintext,
    ) -> Result<(), LwePlaintextAdditionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_plaintext_add_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input_1: &Ciphertext,
        input_2: &Plaintext,
    );
}
