//! This module contains the specification for fhe entities.
//!
//! A type representing a given fhe entity used in the concrete scheme _must_ implement one of the
//! traits contained in this module.
use concrete_commons::parameters::{
    CleartextCount, DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextCount,
    GlweCiphertextCount, GlweDimension, GswCiphertextCount, LweCiphertextCount, LweDimension,
    PlaintextCount, PolynomialSize,
};

/// A module containing various marker traits used for entities.
pub mod markers;
use markers::*;

/// This trait is the top-level abstraction for entities of the concrete scheme.
///
/// An `AbstractEntity` is nothing more but a type with two associated types:
///
/// + One `EntityKindMarker` type which encodes in the type system, the kind of the fhe entity the
/// implementor represents (is it a plaintext, an lwe ciphertext, ...).
/// + One `EntityRepresentationMarker` type which encodes in the type system, the _representation_
/// embodied by the implementor (is it in the cpu or the gpu memory, is it in the standard or
/// fourier domain, is it in 32 or 64 bits, ...).
///
/// In essence, this trait allows to ensure at compile-time that you operate on compatible entities.
pub trait AbstractEntity {
    // # Why associated types and not generic parameters ?
    //
    // With generic parameter you can have one type implement a variety of abstract entity. With
    // associated types, a type can only implement one abstract entity. Hence, using generic
    // parameter, would encourage broadly generic types representing various entities (say an array)
    // while using associated types encourages narrowly defined types representing a single entity.
    // We think it is preferable for the user if the backends expose narrowly defined types, as it
    // makes the api cleaner and the signatures leaner. The downside is probably a bit more
    // boilerplate though.
    //
    // Also, this prevents a single type to implement different downstream traits (a type being both
    // a ggsw ciphertext vector and an lwe bootstrap key). Again, I think this is for the best, as
    // it will help us design better backend-level apis.

    /// The _kind_ of the entity.
    type Kind: EntityKindMarker;
    /// The _representation_ this entity embodies.
    type Representation: EntityRepresentationMarker;
}

/// This trait must be implemented by types embodying a plaintext.
pub trait PlaintextEntity: AbstractEntity<Kind = PlaintextKind> {}

/// This trait must be implemented by types embodying a plaintext vector.
pub trait PlaintextVectorEntity: AbstractEntity<Kind = PlaintextVectorKind> {
    /// Returns the number of plaintext contained in the vector.
    fn plaintext_count(&self) -> PlaintextCount;
}

/// This trait must be implemented by types embodying a cleartext.
pub trait CleartextEntity: AbstractEntity<Kind = CleartextKind> {}

/// This trait must be implemented by types embodying a cleartext vector.
pub trait CleartextVectorEntity: AbstractEntity<Kind = CleartextVectorKind> {
    /// Returns the number of cleartext contained in the vector.
    fn cleartext_count(&self) -> CleartextCount;
}

/// This trait must be implemented by types embodying an lwe ciphertext.
pub trait LweCiphertextEntity: AbstractEntity<Kind = LweCiphertextKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the lwe dimension of the ciphertext.
    fn lwe_dimension(&self) -> LweDimension;
}

/// This trait must be implemented by types embodying an lwe ciphertext vector.
pub trait LweCiphertextVectorEntity: AbstractEntity<Kind = LweCiphertextVectorKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the lwe dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of ciphertexts contained in the vector.
    fn lwe_ciphertext_count(&self) -> LweCiphertextCount;
}

/// This trait must be implemented by types embodying a glwe ciphertext.
pub trait GlweCiphertextEntity: AbstractEntity<Kind = GlweCiphertextKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the glwe dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;
}

/// This trait must be implemented by types embodying a glwe ciphertext vector.
pub trait GlweCiphertextVectorEntity: AbstractEntity<Kind = GlweCiphertextVectorKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the glwe dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of ciphertexts in the vector.
    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount;
}

/// This trait must be implemented by types embodying a gsw ciphertext.
pub trait GswCiphertextEntity: AbstractEntity<Kind = GswCiphertextKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the lwe dimension of the ciphertext.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of decomposition levels of the ciphertext.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertext.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}

/// This trait must be implemented by types embodying a gsw ciphertext vector.
pub trait GswCiphertextVectorEntity: AbstractEntity<Kind = GswCiphertextVectorKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the lwe dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of decomposition levels of the ciphertexts.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertexts.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the number of ciphertexts in the vector.
    fn gsw_ciphertext_count(&self) -> GswCiphertextCount;
}

/// This trait must be implemented by types embodying a ggsw ciphertext.
pub trait GgswCiphertextEntity: AbstractEntity<Kind = GgswCiphertextKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the glwe dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the ciphertext.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertext.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}

/// This trait must be implemented by types embodying a ggsw ciphertext vector.
pub trait GgswCiphertextVectorEntity: AbstractEntity<Kind = GgswCiphertextVectorKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the glwe dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the ciphertexts.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertexts.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the number of ciphertexts in the vector.
    fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount;
}

/// This trait must be implemented by types embodying an lwe secret key.
pub trait LweSecretKeyEntity: AbstractEntity<Kind = LweSecretKeyKind> {
    /// The flavor of this key
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the lwe dimension of the key.
    fn lwe_dimension(&self) -> LweDimension;
}

/// This trait must be implemented by types embodying a glwe secret key.
pub trait GlweSecretKeyEntity: AbstractEntity<Kind = GlweSecretKeyKind> {
    /// The flavor of this key
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the glwe dimension of the key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the key.
    fn polynomial_size(&self) -> PolynomialSize;
}

/// This trait must be implemented by types embodying an lwe keyswitch key.
/// d
pub trait LweKeyswitchKeyEntity: AbstractEntity<Kind = LweKeyswitchKeyKind> {
    /// The flavor of key the ciphertext was encrypted with.
    type KeyFlavor: KeyFlavorMarker;

    /// Returns the input lwe dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output lew dimension of the key.
    fn output_lwe_dimension(&self) -> LweDimension;

    /// Returns the number of decomposition levels of the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}

/// This trait must be implemented by types embodying an lwe bootstrap key.
pub trait LweBootstrapKeyEntity: AbstractEntity<Kind = LweBootstrapKeyKind> {
    /// The flavor of key the input ciphertext is encrypted with.
    type InputKeyFlavor: KeyFlavorMarker;

    /// The flavor of the key the output ciphertext is encrypted with.
    type OutputKeyFlavor: KeyFlavorMarker;

    /// Returns the glwe dimension of the key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the key.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the input lwe dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output lwe dimension of the key.
    fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_dimension().0 * self.polynomial_size().0)
    }

    /// Returns the number of decomposition levels of the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;
}
