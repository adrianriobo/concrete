use crate::backends::core::implementation::entities::markers::{
    CpuFourier32, CpuFourier64, CpuStandard32, CpuStandard64,
};
use crate::backends::core::private::crypto::bootstrap::{
    FourierBootstrapKey as ImplFourierBootstrapKey,
    StandardBootstrapKey as ImplStandardBootstrapKey,
};
use crate::backends::core::private::math::fft::Complex64;
use crate::specification::entities::markers::{BinaryKeyFlavor, LweBootstrapKeyKind};
use crate::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_fftw::array::AlignedVec;

pub struct LweBootstrapKey32(pub(crate) ImplStandardBootstrapKey<Vec<u32>>);
impl AbstractEntity for LweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
    type Representation = CpuStandard32;
}
impl LweBootstrapKeyEntity for LweBootstrapKey32 {
    type InputKeyFlavor = BinaryKeyFlavor;
    type OutputKeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

pub struct LweBootstrapKey64(pub(crate) ImplStandardBootstrapKey<Vec<u64>>);
impl AbstractEntity for LweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
    type Representation = CpuStandard64;
}
impl LweBootstrapKeyEntity for LweBootstrapKey64 {
    type InputKeyFlavor = BinaryKeyFlavor;
    type OutputKeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

pub struct FourierLweBootstrapKey32(pub(crate) ImplFourierBootstrapKey<AlignedVec<Complex64>, u32>);
impl AbstractEntity for FourierLweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
    type Representation = CpuFourier32;
}
impl LweBootstrapKeyEntity for FourierLweBootstrapKey32 {
    type InputKeyFlavor = BinaryKeyFlavor;
    type OutputKeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

pub struct FourierLweBootstrapKey64(pub(crate) ImplFourierBootstrapKey<AlignedVec<Complex64>, u64>);
impl AbstractEntity for FourierLweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
    type Representation = CpuFourier64;
}
impl LweBootstrapKeyEntity for FourierLweBootstrapKey64 {
    type InputKeyFlavor = BinaryKeyFlavor;
    type OutputKeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}