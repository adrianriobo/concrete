use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    FourierLweBootstrapKey32, FourierLweBootstrapKey64, GlweCiphertext32, GlweCiphertext64,
    LweCiphertext32, LweCiphertext64,
};
use crate::backends::core::private::crypto::bootstrap::Bootstrap;
use crate::specification::engines::{LweBootstrapEngine, LweBootstrapError};
use crate::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

macro_rules! implem {
    ($Ciphertext:ident, $Accumulator:ident, $Bsk:ident) => {
        impl LweBootstrapEngine<$Bsk, $Ciphertext, $Accumulator> for CoreEngine {
            fn lwe_bootstrap(
                &mut self,
                output: &mut $Ciphertext,
                input: &$Ciphertext,
                acc: &$Accumulator,
                bsk: &$Bsk,
            ) -> Result<(), LweBootstrapError<Self::EngineError>> {
                if input.lwe_dimension() != bsk.input_lwe_dimension() {
                    return Err(LweBootstrapError::InputDimensionMismatch);
                }
                if acc.polynomial_size() != bsk.polynomial_size() {
                    return Err(LweBootstrapError::PolynomialSizeMismatch);
                }
                if acc.glwe_dimension() != bsk.glwe_dimension() {
                    return Err(LweBootstrapError::AccumulatorDimensionMismatch);
                }
                if output.lwe_dimension() != bsk.output_lwe_dimension() {
                    return Err(LweBootstrapError::OutputDimensionMismatch);
                }
                unsafe { self.lwe_bootstrap_unchecked(output, input, acc, bsk) };
                Ok(())
            }

            unsafe fn lwe_bootstrap_unchecked(
                &mut self,
                output: &mut $Ciphertext,
                input: &$Ciphertext,
                acc: &$Accumulator,
                bsk: &$Bsk,
            ) {
                bsk.0.bootstrap(&mut output.0, &input.0, &acc.0);
            }
        }
    };
}
implem!(LweCiphertext32, GlweCiphertext32, FourierLweBootstrapKey32);
implem!(LweCiphertext64, GlweCiphertext64, FourierLweBootstrapKey64);
