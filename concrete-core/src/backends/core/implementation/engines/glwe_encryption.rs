use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweCiphertextVector32, GlweCiphertextVector64,
    GlweSecretKey32, GlweSecretKey64, PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    GlweEncryptionEngine, GlweEncryptionError, GlweVectorEncryptionEngine,
    GlweVectorEncryptionError,
};
use crate::specification::entities::{
    GlweCiphertextEntity, GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

macro_rules! implem {
    ($SecretKey:ident, $Plaintext:ident, $Ciphertext:ident) => {
        impl GlweEncryptionEngine<$SecretKey, $Plaintext, $Ciphertext> for CoreEngine {
            fn encrypt_glwe(
                &mut self,
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
                noise: Variance,
            ) -> Result<(), GlweEncryptionError<Self::EngineError>> {
                if key.polynomial_size() != output.polynomial_size() {
                    return Err(GlweEncryptionError::PolynomialSizeMismatch);
                }
                if key.glwe_dimension() != output.glwe_dimension() {
                    return Err(GlweEncryptionError::GlweDimensionMismatch);
                }
                unsafe { self.encrypt_glwe_unchecked(key, output, input, noise) };
                Ok(())
            }

            unsafe fn encrypt_glwe_unchecked(
                &mut self,
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
                noise: Variance,
            ) {
                key.0.encrypt_glwe(
                    &mut output.0,
                    &input.0,
                    noise,
                    &mut self.encryption_generator,
                );
            }
        }
    };
}

implem!(GlweSecretKey32, PlaintextVector32, GlweCiphertext32);
implem!(GlweSecretKey64, PlaintextVector64, GlweCiphertext64);

macro_rules! implem_vector {
    ($SecretKey:ident, $Plaintext:ident, $Ciphertext:ident) => {
        impl GlweVectorEncryptionEngine<$SecretKey, $Plaintext, $Ciphertext> for CoreEngine {
            fn encrypt_glwe_vector(
                &mut self,
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
                noise: Variance,
            ) -> Result<(), GlweVectorEncryptionError<Self::EngineError>> {
                if key.glwe_dimension() != output.glwe_dimension() {
                    return Err(GlweVectorEncryptionError::GlweDimensionMismatch);
                }
                if key.polynomial_size() != output.polynomial_size() {
                    return Err(GlweVectorEncryptionError::PolynomialSizeMismatch);
                }
                if (output.glwe_ciphertext_count().0 % input.plaintext_count().0) == 0 {
                    return Err(GlweVectorEncryptionError::CountMismatch);
                }
                unsafe { self.encrypt_glwe_vector_unchecked(key, output, input, noise) };
                Ok(())
            }

            unsafe fn encrypt_glwe_vector_unchecked(
                &mut self,
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
                noise: Variance,
            ) {
                key.0.encrypt_glwe_list(
                    &mut output.0,
                    &input.0,
                    noise,
                    &mut self.encryption_generator,
                )
            }
        }
    };
}

implem_vector!(GlweSecretKey32, PlaintextVector32, GlweCiphertextVector32);
implem_vector!(GlweSecretKey64, PlaintextVector64, GlweCiphertextVector64);
