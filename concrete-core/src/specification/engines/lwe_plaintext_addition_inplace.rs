use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    "The error used in the [`LwePlaintextAdditionInplaceEngine`] trait.",
    LwePlaintextAdditionInplaceError @
}

/// A trait for engines which perform inplace lwe addition.
pub trait LwePlaintextAdditionInplaceEngine<Ciphertext, Plaintext>: AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity<Representation = Plaintext::Representation>,
{
    fn lwe_plaintext_add_inplace(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    ) -> Result<(), LwePlaintextAdditionInplaceError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_plaintext_add_inplace_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    );
}
