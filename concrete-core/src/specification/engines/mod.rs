//! This module contains the specification for fhe engines.
//!
//! Engines are types which can be used to perform operations on fhe entities. Those engines contain
//! the necessary side-resources needed to execute the operations they declare. Every operation is
//! defined by an operation trait. Those operation traits are meant to expose two entry points:
//!
//! + A safe entry point, returning a result, with an operation-dedicated error. When using this
//! entry point, concrete will ensure that the necessary invariants are verified at the beginning of
//! the operation. This can result in a small extra cost. This entry point is not expected to panic.
//! + An unsafe entry point, returning the raw result if any. When using this entry point, the user
//! must take care of guaranteeing that the invariants expected by the operation are verified.
//! Breaking one of those invariants will result in UB, from an FHE point of view. This entry point
//! may panic, depending on the broken invariant.

// We expect the different backends to each include, a single engine. This gives a single
// entry point for every operations made possible by a backend. This does not mean that a single
// instance of this object will live during the program execution, for example when working in a
// multithreaded environment.
use crate::specification::entities::{
    AbstractEntity, LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};
use concrete_commons::parameters::LweSize;

/// This trait is the top-level abstraction for engines.
///
/// An `AbstractEngine` is nothing more than a type with an associated error type. This error type
/// encodes the failure cases _specific_ to the engine.
pub trait AbstractEngine: sealed::AbstractEngineSeal {
    // # Why putting the error type in an abstract super trait ?
    //
    // This error is supposed to be reduced to only engine related errors, and not ones related to
    // the operations. For this reason, it is better for an engine to only have one error shared
    // among all the operations. If a variant of this error can only be triggered for a single
    // operation implemented by the engine, then it should probably be moved upstream, in the
    // operation-dedicated error.

    /// The error associated to the engine.
    type EngineError: std::error::Error;
}

macro_rules! engine_error{
    ($doc:literal, $name:ident @ $($variants:ident => $messages:literal),*) =>{
        #[doc=$doc]
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub enum $name<EngineError: std::error::Error> {
            $(
                $variants,
            )*
            Engine(EngineError),
        }
        impl<EngineError: std::error::Error> std::fmt::Display for $name<EngineError>{
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$variants => write!(f, $messages),
                    )*
                    Self::Engine(error) => write!(f, "Error occured in the engine: {}", error),
                }
            }
        }
        impl<EngineError: std::error::Error> std::error::Error for $name<EngineError>{}
    }
}

engine_error! {
    "The error used in the `LweAllocationEngine` trait.",
    LweAllocationError @
    MemoryExhausted => "Not enough memory left to allocate the entity."
}

/// A trait for engines performing allocations of lwe ciphertexts.
pub trait LweAllocationEngine<Output, Representation>: AbstractEngine
where
    Output: LweCiphertextEntity<Representation = Representation>,
{
    /// A safe entry point for allocating lwe ciphertexts.
    fn allocate_lwe(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<Output, LweAllocationError<Self::EngineError>>;

    /// An unsafe entry point for allocating lwe ciphertexts.
    ///
    /// # Safey
    ///
    /// See the documentation of the implementation for the engine you intend to use for details on
    /// the safety of this function.
    unsafe fn allocate_lwe_unchecked(&mut self, lwe_size: LweSize) -> Output;
}

engine_error! {
    "The error used in the `ConversionEngine` trait.",
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

    unsafe fn convert_unchecked(&mut self, output: &mut Output, input: &Input);
}

engine_error! {
    "The error used in the `LweEncryptionEngine` trait.",
    LweEncryptionError @
    LweDimensionMismatch => "Lwe dimensions of the key is incompatible with the output ciphertext."
}

/// A trait for engines which encrypt lwe ciphertexts.
pub trait LweEncryptionEngine<Key, Input, Output, Flavor, Representation>: AbstractEngine
where
    Key: LweSecretKeyEntity<Representation = Representation, KeyFlavor = Flavor>,
    Input: PlaintextEntity<Representation = Representation>,
    Output: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
{
    fn encrypt_lwe(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweEncryptionError<Self::EngineError>>;

    unsafe fn encrypt_lwe_unchecked(&mut self, key: &Key, output: &mut Output, input: &Input);
}

engine_error! {
    "The error used in the `LweAdditionEngine` trait.",
    LweAdditionError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform out-of-place lwe addition.
pub trait LweAdditionEngine<Input1, Input2, Output, Representation, Flavor>:
    AbstractEngine
where
    Input1: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
    Input2: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
    Output: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
{
    fn add_lwe(
        &mut self,
        output: &mut Output,
        input_1: &Input1,
        input_2: &Input2,
    ) -> Result<(), LweAdditionError<Self::EngineError>>;

    unsafe fn add_lwe_unchecked(&mut self, output: &mut Output, input_1: &Input1, input_2: &Input2);
}

engine_error! {
    "The error used in the `LweInplaceAdditionEngine` trait.",
    LweInplaceAdditionError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform inplace lwe addition.
pub trait LweInplaceAdditionEngine<Input, Output, Representation, Flavor>: AbstractEngine
where
    Input: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
    Output: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
{
    fn inplace_add_lwe(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>>;

    unsafe fn inplace_add_lwe_unchecked(&mut self, output: &mut Output, input: &Input);
}

engine_error! {
    "The error used in the `LweNegationEngine` trait.",
    LweNegationError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform out-of-place lwe negation.
pub trait LweNegationEngine<Input, Output, Representation, Flavor>: AbstractEngine
where
    Input: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
    Output: LweCiphertextEntity<Representation = Representation, KeyFlavor = Flavor>,
{
    fn negate_lwe(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweNegationError<Self::EngineError>>;

    unsafe fn add_lwe_unchecked(&mut self, output: &mut Output, input: &Input);
}

engine_error! {
    "The error used in the `LweInplaceNegationEngine` trait.",
    LweInplaceNegationError @
    LweDimensionMismatch => "Input and output ciphertexts have incompatible lwe dimension."
}

/// A trait for engines which perform inplace lwe negation.
pub trait LweInplaceNegationEngine<Input>: AbstractEngine
where
    Input: LweCiphertextEntity,
{
    fn inplace_neg_lwe(
        &mut self,
        input: &mut Input,
    ) -> Result<(), LweInplaceNegationError<Self::EngineError>>;

    unsafe fn inplace_neg_lwe_unchecked(&mut self, input: &mut Input);
}

engine_error! {
    "The error used in the `LweScalarAdditionEngine` trait.",
    LweScalarAdditionError @
}

/// A trait for engines which perform out-of-place lwe addition.
pub trait LweScalarAdditionEngine<Input1, Input2, Output, Representation>: AbstractEngine
where
    Input1: LweCiphertextEntity<Representation = Representation>,
    Input2: PlaintextEntity<Representation = Representation>,
    Output: LweCiphertextEntity<Representation = Representation>,
{
    fn scalar_add_lwe(
        &mut self,
        output: &mut Output,
        input_1: &Input1,
        input_2: &Input2,
    ) -> Result<(), LweScalarAdditionError<Self::EngineError>>;

    unsafe fn scalar_add_lwe_unchecked(
        &mut self,
        output: &mut Output,
        input_1: &Input1,
        input_2: &Input2,
    );
}

engine_error! {
    "The error used in the `LweInplaceScalarAdditionEngine` trait.",
    LweInplaceScalarAdditionError @
}

/// A trait for engines which perform inplace lwe addition.
pub trait LweInplaceScalarAdditionEngine<Input, Output, Representation>: AbstractEngine
where
    Input: PlaintextEntity<Representation = Representation>,
    Output: LweCiphertextEntity<Representation = Representation>,
{
    fn inplace_scalar_add_lwe(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>>;

    unsafe fn inplace_scalar_add_lwe_unchecked(&mut self, output: &mut Output, input: &Input);
}

// This makes it impossible for types outside concrete to implement operations.
pub(crate) mod sealed {
    pub trait AbstractEngineSeal {}
}
