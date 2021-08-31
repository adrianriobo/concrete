use crate::specification::entities::{AbstractEntity, LweCiphertextEntity, LweCiphertextVectorEntity};
use crate::specification::entities::markers::{LweCiphertextKind, LweCiphertextVectorKind, BinaryKeyFlavor};
use concrete_commons::parameters::{LweDimension, LweCiphertextCount};
use super::super::super::private::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use super::super::super::private::crypto::lwe::LweList as ImplLweList;

/// An lwe ciphertext in the cpu memory, in the standard domain, using 32-bits precision integers.
pub struct LweCiphertext32(ImplLweCiphertext<Vec<u32>>);
impl AbstractEntity for LweCiphertext32 {
    type Kind = LweCiphertextKind;
    type Representation = markers::ImplStandard32;
}
impl LweCiphertextEntity for LweCiphertext32{
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

/// An lwe ciphertext in the cpu memory, in the standard domain, using 64-bits precision integers.
pub struct LweCiphertext64(ImplLweCiphertext<Vec<u64>>);
impl AbstractEntity for LweCiphertext64{
    type Kind = LweCiphertextKind;
    type Representation = markers::ImplStandard64;
}
impl LweCiphertextEntity for LweCiphertext64{
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

/// A vector of lwe ciphertexts in the cpu memory, in the standard domain, using 32-bits precision
/// integers.
pub struct LweCiphertextVector32(ImplLweList<Vec<u32>>);
impl AbstractEntity for LweCiphertextVector32 {
    type Kind = LweCiphertextVectorKind;
    type Representation = markers::ImplStandard32;
}
impl LweCiphertextVectorEntity for LweCiphertextVector32{
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A vector of lwe ciphertexts in the cpu memory, in the standard domain, using 64-bits precision
/// integers.
pub struct LweCiphertextVector64(ImplLweList<Vec<u64>>);
impl AbstractEntity for LweCiphertextVector64 {
    type Kind = LweCiphertextVectorKind;
    type Representation = markers::ImplStandard64;
}
impl LweCiphertextVectorEntity for LweCiphertextVector64{
    type KeyFlavor = BinaryKeyFlavor

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}
