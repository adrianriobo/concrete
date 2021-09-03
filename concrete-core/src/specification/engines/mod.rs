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

// This makes it impossible for types outside concrete to implement operations.
pub(crate) mod sealed {
    pub trait AbstractEngineSeal {}
}

/// This trait is the top-level abstraction for engines.
///
/// An `AbstractEngine` is nothing more than a type with an associated error type. This error type
/// encodes the failure cases _specific_ to the engine.
pub trait AbstractEngine: sealed::AbstractEngineSeal + Sized {
    // # Why putting the error type in an abstract super trait ?
    //
    // This error is supposed to be reduced to only engine related errors, and not ones related to
    // the operations. For this reason, it is better for an engine to only have one error shared
    // among all the operations. If a variant of this error can only be triggered for a single
    // operation implemented by the engine, then it should probably be moved upstream, in the
    // operation-dedicated error.

    /// The error associated to the engine.
    type EngineError: std::error::Error;

    /// A constructor for the engine.
    fn new() -> Result<Self, Self::EngineError>;
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
pub(crate) use engine_error;

mod conversion;
pub use conversion::*;

mod lwe_allocation;
pub use lwe_allocation::*;

mod glwe_allocation;
pub use glwe_allocation::*;

mod lwe_secret_key_generation;
pub use lwe_secret_key_generation::*;

mod glwe_secret_key_generation;
pub use glwe_secret_key_generation::*;

mod glwe_encryption;
pub use glwe_encryption::*;

mod glwe_vector_encryption;
pub use glwe_vector_encryption::*;

mod lwe_encryption;
pub use lwe_encryption::*;

mod lwe_vector_encryption;
pub use lwe_vector_encryption::*;

mod lwe_add;
pub use lwe_add::*;

mod lwe_add_assign;
pub use lwe_add_assign::*;

mod lwe_negation;
pub use lwe_negation::*;

mod lwe_negation_inplace;
pub use lwe_negation_inplace::*;

mod lwe_plaintext_addition;
pub use lwe_plaintext_addition::*;

mod lwe_plaintext_addition_inplace;
pub use lwe_plaintext_addition_inplace::*;

mod lwe_cleartext_multiplication;
pub use lwe_cleartext_multiplication::*;

mod lwe_cleartext_multiplication_inplace;
pub use lwe_cleartext_multiplication_inplace::*;

mod lwe_multisum;
pub use lwe_multisum::*;

mod lwe_keyswitch_key_generation;
pub use lwe_keyswitch_key_generation::*;
