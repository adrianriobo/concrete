use super::super::super::private::crypto::glwe::{
    GlweCiphertext as ImplGlweCiphertext, GlweList as ImplGlweList,
};
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::{
    BinaryKeyFlavor, GlweCiphertextKind, GlweCiphertextVectorKind,
};
use crate::specification::entities::{
    AbstractEntity, GlweCiphertextEntity, GlweCiphertextVectorEntity,
};
use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};

pub struct GlweCiphextext32(pub(crate) ImplGlweCiphertext<Vec<u32>>);
impl AbstractEntity for GlweCiphextext32 {
    type Kind = GlweCiphertextKind;
    type Representation = CpuStandard32;
}
impl GlweCiphertextEntity for GlweCiphextext32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

pub struct GlweCiphextext64(pub(crate) ImplGlweCiphertext<Vec<u64>>);
impl AbstractEntity for GlweCiphextext64 {
    type Kind = GlweCiphertextKind;
    type Representation = CpuStandard64;
}
impl GlweCiphertextEntity for GlweCiphextext64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

pub struct GlweCiphertextVector32(pub(crate) ImplGlweList<Vec<u32>>);
impl AbstractEntity for GlweCiphertextVector32 {
    type Kind = GlweCiphertextVectorKind;
    type Representation = CpuStandard32;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}

pub struct GlweCiphertextVector64(pub(crate) ImplGlweList<Vec<u64>>);
impl AbstractEntity for GlweCiphertextVector64 {
    type Kind = GlweCiphertextVectorKind;
    type Representation = CpuStandard64;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}
