use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GlweCiphertextEntity, LweCiphertextEntity};

engine_error! {
    "The error used in the [`LweBootstrapEngine`] trait.",
    LweBootstrapError @
    SizeMismatch => "The sizes of the output lwe does not match the size of the input glwe."
}

/// A trait
pub trait LweBootstrapEngine<Ciphertext, Accumulator>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    Accumulator:
        GlweCiphertextEntity<KeyFlavor = Ciphertext::KeyFlavor, Representation = Ciphertext::Representation>,
{
    fn lwe_bootstrap(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
        acc: &Accumulator,
    ) -> Result<(), LweBootstrapError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_bootstrap_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
        acc: &Accumulator,
    );
}
