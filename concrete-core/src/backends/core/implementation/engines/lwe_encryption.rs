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

macro_rules! implem {
    ($SecretKey:ident, $Plaintext:ident, $Ciphertext:ident) => {
        impl LweEncryptionEngine<$SecretKey, $Plaintext, $Ciphertext> for CoreEngine {
            fn encrypt_lwe(
                &mut self,
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
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
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
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
    };
}
implem!(LweSecretKey32, Plaintext32, LweCiphertext32);
implem!(LweSecretKey64, Plaintext64, LweCiphertext64);

macro_rules! implem_vector {
    ($SecretKey:ident, $Plaintext:ident, $Ciphertext:ident) => {
        impl LweVectorEncryptionEngine<$SecretKey, $Plaintext, $Ciphertext> for CoreEngine {
            fn encrypt_lwe_vector(
                &mut self,
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
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
                key: &$SecretKey,
                output: &mut $Ciphertext,
                input: &$Plaintext,
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
    };
}
implem_vector!(LweSecretKey32, PlaintextVector32, LweCiphertextVector32);
implem_vector!(LweSecretKey64, PlaintextVector64, LweCiphertextVector64);
