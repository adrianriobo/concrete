use crate::backends::core::private::crypto::ggsw::GgswCiphertext as ImplGgswCiphertext;
use crate::specification::entities::{AbstractEntity, GgswCiphertextEntity};
use crate::specification::entities::markers::{GgswCiphertextKind, BinaryKeyFlavor};
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use concrete_commons::parameters::{GlweDimension, PolynomialSize, DecompositionLevelCount, DecompositionBaseLog};

pub struct GgswCiphertext32(ImplGgswCiphertext<Vec<u32>>);
impl AbstractEntity for GgswCiphertext32{
    type Kind = GgswCiphertextKind;
    type Representation = CpuStandard32;
}
impl GgswCiphertextEntity for GgswCiphertext32{
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

pub struct GgswCiphertext64(ImplGgswCiphertext<Vec<u64>>);
impl AbstractEntity for GgswCiphertext64{
    type Kind = GgswCiphertextKind;
    type Representation = CpuStandard64;
}
impl GgswCiphertextEntity for GgswCiphertext64{
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}
