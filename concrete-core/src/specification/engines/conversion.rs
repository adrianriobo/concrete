use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::AbstractEntity;

engine_error! {
    "The error used in the [`ConversionEngine`] trait.",
    ConversionError @
    SizeMismatch => "The two entities have incompatible sizes."
}

/// A trait for engines which change the representation of an fhe object.
pub trait ConversionEngine<Kind, Input, Output, InputRepresentation, OutputRepresentation>:
    AbstractEngine
where
    Input: AbstractEntity<Kind = Kind, Representation = InputRepresentation>,
    Output: AbstractEntity<Kind = Kind, Representation = OutputRepresentation>,
{
    fn convert(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), ConversionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn convert_unchecked(&mut self, output: &mut Output, input: &Input);
}
