use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    FourierLweBootstrapKey32, FourierLweBootstrapKey64, LweBootstrapKey32, LweBootstrapKey64,
};
use crate::specification::engines::{
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError,
};
use crate::specification::entities::LweBootstrapKeyEntity;

macro_rules! implem {
    ($Output:ident, $Input: ident) => {
        impl LweBootstrapKeyConversionEngine<$Input, $Output> for CoreEngine {
            fn convert_lwe_bootstrap_key(
                &mut self,
                output: &mut $Output,
                input: &$Input,
            ) -> Result<(), LweBootstrapKeyConversionError<Self::EngineError>> {
                if output.decomposition_level_count() != input.decomposition_level_count() {
                    return Err(LweBootstrapKeyConversionError::DifferingDecompositionLevelCount);
                }
                if output.decomposition_base_log() != input.decomposition_base_log() {
                    return Err(LweBootstrapKeyConversionError::DifferingDecompositionBaseLog);
                }
                if output.polynomial_size() != input.polynomial_size() {
                    return Err(LweBootstrapKeyConversionError::DifferingPolynomialSize);
                }
                if output.lwe_dimension() != input.lwe_dimension() {
                    return Err(LweBootstrapKeyConversionError::DifferingLweDimension);
                }
                if output.glwe_dimension() != input.glwe_dimension() {
                    return Err(LweBootstrapKeyConversionError::DifferingGlweDimension);
                }
                unsafe { self.convert_lwe_bootstrap_key_unchecked(output, input) };
                Ok(())
            }

            unsafe fn convert_lwe_bootstrap_key_unchecked(
                &mut self,
                output: &mut $Output,
                input: &$Input,
            ) {
                output.0.fill_with_forward_fourier(&input.0);
            }
        }
    };
}
implem!(FourierLweBootstrapKey32, LweBootstrapKey32);
implem!(FourierLweBootstrapKey64, LweBootstrapKey64);
