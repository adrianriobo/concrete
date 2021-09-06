use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCleartextMultiplicationEngine, LweCleartextMultiplicationError,
    LweCleartextMultiplicationInplaceEngine, LweCleartextMultitlicationInplaceError,
};

macro_rules! implem {
    ($Ciphertext:ident, $Cleartext:ident) => {
        impl LweCleartextMultiplicationEngine<$Ciphertext, $Cleartext> for CoreEngine {
            fn lwe_cleartext_mul(
                &mut self,
                output: &mut $Ciphertext,
                input_1: &$Ciphertext,
                input_2: &$Cleartext,
            ) -> Result<(), LweCleartextMultiplicationError<Self::EngineError>> {
                unsafe { self.lwe_cleartext_mul_unchecked(output, input_1, input_2) };
                Ok(())
            }

            unsafe fn lwe_cleartext_mul_unchecked(
                &mut self,
                output: &mut $Ciphertext,
                input_1: &$Ciphertext,
                input_2: &$Cleartext,
            ) {
                output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
            }
        }
    };
}
implem!(LweCiphertext32, Cleartext32);
implem!(LweCiphertext64, Cleartext64);

macro_rules! implem_inplace {
    ($Ciphertext:ident, $Cleartext:ident) => {
        impl LweCleartextMultiplicationInplaceEngine<$Ciphertext, $Cleartext> for CoreEngine {
            fn lwe_cleartext_mul_inplace(
                &mut self,
                output: &mut $Ciphertext,
                input: &$Cleartext,
            ) -> Result<(), LweCleartextMultitlicationInplaceError<Self::EngineError>> {
                unsafe { self.lwe_cleartext_mul_inplace_unchecked(output, input) };
                Ok(())
            }

            unsafe fn lwe_cleartext_mul_inplace_unchecked(
                &mut self,
                output: &mut $Ciphertext,
                input: &$Cleartext,
            ) {
                output.0.update_with_scalar_mul(input.0);
            }
        }
    };
}
implem_inplace!(LweCiphertext32, Cleartext32);
implem_inplace!(LweCiphertext64, Cleartext64);
