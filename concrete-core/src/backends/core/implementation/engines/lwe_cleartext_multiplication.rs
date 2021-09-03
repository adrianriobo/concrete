use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCleartextMultiplicationEngine, LweCleartextMultiplicationError,
    LweCleartextMultiplicationInplaceEngine, LweCleartextMultitlicationInplaceError,
};

impl LweCleartextMultiplicationInplaceEngine<LweCiphertext32, Cleartext32> for CoreEngine {
    fn lwe_cleartext_mul_inplace(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) -> Result<(), LweCleartextMultitlicationInplaceError<Self::EngineError>> {
        unsafe { self.lwe_cleartext_mul_inplace_unchecked(output, input) };
        Ok(())
    }

    unsafe fn lwe_cleartext_mul_inplace_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}

impl LweCleartextMultiplicationInplaceEngine<LweCiphertext64, Cleartext64> for CoreEngine {
    fn lwe_cleartext_mul_inplace(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) -> Result<(), LweCleartextMultitlicationInplaceError<Self::EngineError>> {
        unsafe { self.lwe_cleartext_mul_inplace_unchecked(output, input) };
        Ok(())
    }

    unsafe fn lwe_cleartext_mul_inplace_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}

impl LweCleartextMultiplicationEngine<LweCiphertext32, Cleartext32> for CoreEngine {
    fn lwe_cleartext_mul(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Cleartext32,
    ) -> Result<(), LweCleartextMultiplicationError<Self::EngineError>> {
        unsafe { self.lwe_cleartext_mul_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn lwe_cleartext_mul_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Cleartext32,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}

impl LweCleartextMultiplicationEngine<LweCiphertext64, Cleartext64> for CoreEngine {
    fn lwe_cleartext_mul(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Cleartext64,
    ) -> Result<(), LweCleartextMultiplicationError<Self::EngineError>> {
        unsafe { self.lwe_cleartext_mul_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn lwe_cleartext_mul_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Cleartext64,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}
