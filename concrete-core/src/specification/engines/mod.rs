//! Engines are types which can be used to perform operations on fhe entities. Those engines may
//! contain the necessary side-resources needed to execute the operations they declare. Every
//! operation is defined by an operation trait. Those operation traits are meant to expose two entry
//! points:
//!
//! + A safe entry point, returning a result, with an operation-dedicated error. When using this
//! entry point, concrete will ensure that the necessary invariants are verified at the beginning of
//! the operation. This can result in a small extra cost. Finally, this entry point is not expected
//! to panic.
//! + An unsafe entry point, returning the raw result if any. When using this entry point, the user
//! must take care of guaranteeing that the invariants expected by the operation are verified.
//! Breaking one of those invariants will result in UB, from an FHE point of view. Also, this entry
//! point may panic, depending on the broken invariant.
//!
//! We expect the different backends to each include each, a single engine. This we have a single
//! entry point for every operations made possible by a backend. This does not mean that a single
//! instance of this object will leave during the program execution. When working in a multithreaded
//! environment, we will probably end up with one engine in each thread.
use crate::specification::entities::{
    AbstractEntity, LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};

/// A trait shared by all engines.
///
/// Basically an engine is expected to have a specific error type attached to him, which could
/// be used when implementing the operations. This error is supposed to be reduced to only engine
/// related errors, and not ones related to the operations. For this reason, an engine can only have
/// a single error type attached to it by the `Engine` trait. If a variant of this error can only be
/// triggered for a single operation implemented by the engine, then it should probably be moved
/// upstream, in the operation-dedicated error.
pub trait AbstractEngine: sealed::EngineSeal {
    type EngineError: Error;
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
        impl<EngineError: Error> Error for $name<EngineError>{}
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
    Output: LweCiphertextEntity<Watermark= Representation>,
{
    fn allocate_lwe(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<Output, LweAllocationError<Self::EngineError>>;

    unsafe fn allocate_lwe_unchecked(&mut self) -> Output;
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
    Input: AbstractEntity<Kind = Kind, Watermark= InputRepresentation>,
    Output: AbstractEntity<Kind = Kind, Watermark= OutputRepresentation>,
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
pub trait LweEncryptionEngine<Key, Input, Output, Representation>: AbstractEngine
where
    Key: LweSecretKeyEntity<Watermark= Representation>,
    Input: PlaintextEntity<Watermark= Representation>,
    Output: LweCiphertextEntity<Watermark= Representation>,
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
pub trait LweAdditionEngine<Input1, Input2, Output, Representation>: AbstractEngine
where
    Input1: LweCiphertextEntity<Watermark= Representation>,
    Input2: LweCiphertextEntity<Watermark= Representation>,
    Output: LweCiphertextEntity<Watermark= Representation>,
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
pub trait LweInplaceAdditionEngine<Input, Output, Representation>: AbstractEngine
where
    Input: LweCiphertextEntity<Watermark= Representation>,
    Output: LweCiphertextEntity<Watermark= Representation>,
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
pub trait LweNegationEngine<Input, Output, Representation>: AbstractEngine
where
    Input: LweCiphertextEntity<Watermark= Representation>,
    Output: LweCiphertextEntity<Watermark= Representation>,
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
    Input1: LweCiphertextEntity<Watermark= Representation>,
    Input2: PlaintextEntity<Watermark= Representation>,
    Output: LweCiphertextEntity<Watermark= Representation>,
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
    Input: PlaintextEntity<Watermark= Representation>,
    Output: LweCiphertextEntity<Watermark= Representation>,
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
    pub(crate) trait EngineSeal {}
}
