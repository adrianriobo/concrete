use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32,
    LweSecretKey64, Plaintext32, Plaintext64, PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    LweEncryptionEngine, LweEncryptionError, LweVectorEncryptionEngine, LweVectorEncryptionError,
};
use crate::specification::entities::{
    LweCiphertextEntity, LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

impl LweEncryptionEngine<LweSecretKey32, Plaintext32, LweCiphertext32> for CoreEngine {
    fn encrypt_lwe(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
        noise: Variance,
    ) -> Result<(), LweEncryptionError<Self::EngineError>> {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(LweEncryptionError::LweDimensionMismatch);
        }
        unsafe { self.encrypt_lwe_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn encrypt_lwe_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl LweEncryptionEngine<LweSecretKey64, Plaintext64, LweCiphertext64> for CoreEngine {
    fn encrypt_lwe(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<(), LweEncryptionError<Self::EngineError>> {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(LweEncryptionError::LweDimensionMismatch);
        }
        unsafe { self.encrypt_lwe_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn encrypt_lwe_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl LweVectorEncryptionEngine<LweSecretKey32, PlaintextVector32, LweCiphertextVector32>
    for CoreEngine
{
    fn encrypt_lwe_vector(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), LweVectorEncryptionError<Self::EngineError>> {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(LweVectorEncryptionError::LweDimensionMismatch);
        }
        if input.plaintext_count().0 != output.lwe_ciphertext_count().0 {
            return Err(LweVectorEncryptionError::CountMismatch);
        }
        unsafe { self.encrypt_lwe_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn encrypt_lwe_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl LweVectorEncryptionEngine<LweSecretKey64, PlaintextVector64, LweCiphertextVector64>
    for CoreEngine
{
    fn encrypt_lwe_vector(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), LweVectorEncryptionError<Self::EngineError>> {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(LweVectorEncryptionError::LweDimensionMismatch);
        }
        if input.plaintext_count().0 != output.lwe_ciphertext_count().0 {
            return Err(LweVectorEncryptionError::CountMismatch);
        }
        unsafe { self.encrypt_lwe_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn encrypt_lwe_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
