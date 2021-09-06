use crate::specification::engines::{LweBootstrapEngine, LweBootstrapError};
use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{GlweCiphertext32, LweCiphertext32, FourierLweBootstrapKey32};
use crate::backends::core::private::crypto::bootstrap::Bootstrap;
use crate::specification::entities::{LweCiphertextEntity, LweBootstrapKeyEntity};

impl LweBootstrapEngine<FourierLweBootstrapKey32, LweCiphertext32, GlweCiphertext32> for CoreEngine{
    fn lwe_bootstrap(&mut self, output: &mut LweCiphertext32, input: &LweCiphertext32, acc: &GlweCiphertext32, bsk: &FourierLweBootstrapKey32) -> Result<(), LweBootstrapError<Self::EngineError>> {
        if input.lwe_dimension() != bsk.lwe_dimension()
        unsafe{self.lwe_bootstrap_unchecked(output, input, acc, bsk)};
        Ok(())
    }

    unsafe fn lwe_bootstrap_unchecked(&mut self, output: &mut LweCiphertext32, input: &LweCiphertext32, acc: &GlweCiphertext32, bsk: &FourierLweBootstrapKey32) {
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0);
    }
}
