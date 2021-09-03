use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    CleartextVector32, CleartextVector64, LweCiphertext32, LweCiphertext64, LweCiphertextVector32,
    LweCiphertextVector64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{LweMultisumEngine, LweMultisumError};
use crate::specification::entities::{
    CleartextVectorEntity, LweCiphertextEntity, LweCiphertextVectorEntity,
};

impl LweMultisumEngine<LweCiphertext32, LweCiphertextVector32, CleartextVector32, Plaintext32>
    for CoreEngine
{
    fn lwe_multisum(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) -> Result<(), LweMultisumError<Self::EngineError>> {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(LweMultisumError::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(LweMultisumError::VectorCountMismatch);
        }
        unsafe { self.lwe_multisum_unchecked(output, inputs, weights, bias) };
        Ok(())
    }

    unsafe fn lwe_multisum_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}

impl LweMultisumEngine<LweCiphertext64, LweCiphertextVector64, CleartextVector64, Plaintext64>
    for CoreEngine
{
    fn lwe_multisum(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) -> Result<(), LweMultisumError<Self::EngineError>> {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(LweMultisumError::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(LweMultisumError::VectorCountMismatch);
        }
        unsafe { self.lwe_multisum_unchecked(output, inputs, weights, bias) };
        Ok(())
    }

    unsafe fn lwe_multisum_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}
