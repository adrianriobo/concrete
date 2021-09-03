use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphextext32, GlweCiphextext64,
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

impl GlweEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphextext32> for CoreEngine {
    fn encrypt_glwe(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphextext32,
        input: &PlaintextVector32,
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
        key: &GlweSecretKey32,
        output: &mut GlweCiphextext32,
        input: &PlaintextVector32,
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

impl GlweEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphextext64> for CoreEngine {
    fn encrypt_glwe(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphextext64,
        input: &PlaintextVector64,
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
        key: &GlweSecretKey64,
        output: &mut GlweCiphextext64,
        input: &PlaintextVector64,
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

impl GlweVectorEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphertextVector32>
    for CoreEngine
{
    fn encrypt_glwe_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
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
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
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

impl GlweVectorEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphertextVector64>
    for CoreEngine
{
    fn encrypt_glwe_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
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
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
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
