use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphextext32, GlweCiphextext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{GlweSampleExtractionEngine, GlweSampleExtractionError};
use concrete_commons::parameters::MonomialDegree;

impl GlweSampleExtractionEngine<GlweCiphextext32, LweCiphertext32> for CoreEngine {
    fn glwe_sample_extract(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphextext32,
        nth: MonomialDegree,
    ) -> Result<(), GlweSampleExtractionError<Self::EngineError>> {
        if output.0.lwe_size().to_lwe_dimension().0
            != input.0.polynomial_size().0 * input.0.size().to_glwe_dimension().0
        {
            return Err(GlweSampleExtractionError::SizeMismatch);
        }
        unsafe { self.glwe_sample_extract_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn glwe_sample_extract_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphextext32,
        nth: MonomialDegree,
    ) {
        output.0.fill_with_glwe_sample_extraction(&input.0, nth);
    }
}

impl GlweSampleExtractionEngine<GlweCiphextext64, LweCiphertext64> for CoreEngine {
    fn glwe_sample_extract(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphextext64,
        nth: MonomialDegree,
    ) -> Result<(), GlweSampleExtractionError<Self::EngineError>> {
        if output.0.lwe_size().to_lwe_dimension().0
            != input.0.polynomial_size().0 * input.0.size().to_glwe_dimension().0
        {
            return Err(GlweSampleExtractionError::SizeMismatch);
        }
        unsafe { self.glwe_sample_extract_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn glwe_sample_extract_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphextext64,
        nth: MonomialDegree,
    ) {
        output.0.fill_with_glwe_sample_extraction(&input.0, nth);
    }
}
