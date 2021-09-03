use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{CleartextEntity, LweCiphertextEntity};

engine_error! {
    "The error used in the [`LweCleartextMultiplicationInplaceEngine`] trait.",
    LweCleartextMultitlicationInplaceError @
}

pub trait LweCleartextMultiplicationInplaceEngine<Ciphertext, Cleartext>: AbstractEngine
where
    Cleartext: CleartextEntity,
    Ciphertext: LweCiphertextEntity<Representation = Cleartext::Representation>,
{
    fn lwe_cleartext_mul_inplace(
        &mut self,
        output: &mut Ciphertext,
        input: &Cleartext,
    ) -> Result<(), LweCleartextMultitlicationInplaceError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_cleartext_mul_inplace_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Cleartext,
    );
}
