/// This trait is a marker for types encoding an fhe entity in the type system.
///
/// Data kind implementors are unsized types which are used to encode the kind of fhe object
/// we are dealing with, in the type system. They are not meant for any computation, but just for
/// compile-time verification, dispatch, and genericity.
pub trait EntityKind: sealed::EntityKindSeal {}
macro_rules! fhe_entity_kind {
        (@ $name: ident)=>{
            pub struct $name{}
            impl sealed::EntityKindSeal for $name{}
            impl EntityKind for $name{}
        };
        ($($name: ident),+) =>{
            $(
                fhe_entity_kind!(@ $name);
            )+
        }
}
fhe_entity_kind! {
        PlaintextKind,
        PlaintextVectorKind,
        CleartextKind,
        CleartextVectorKind,
        LweCiphertextKind,
        LweCiphertextVectorKind,
        GlweCiphertextKind,
        GlweCiphertextVectorKind,
        GgswCiphertextKind,
        GgswCiphertextVectorKind,
        GswCiphertextKind,
        GswCiphertextVectorKind,
        LweSecretKeyKind,
        GlweSecretKeyKind,
        LweKeyswitchKeyKind,
        LweBootstrapKeyKind
}

/// This trait is implemented by watermark types.
///
/// Watermark implementors are unsized types which are used to encode the specific representation of
/// an fhe object we are dealing with. For us, a representation can mean a variety of things:
/// + Hardware attachment: Is it on cpu gpu fpga ?
/// + Domain of expression: Is it in Fourier domain ? In standard Domain ? In ntt form ?
/// + State of change: In fourier was it regularized ?
/// + Precision: How many bytes does this representation use ?
pub trait EntityWatermark: sealed::EntityRepresentationSealed {}

pub trait KeyKind: sealed::KeyKindSeal {}
macro_rules! key_kind {
        (@ $name: ident)=>{
            pub struct $name{}
            impl sealed::KeyKindSeal for $name{}
            impl KeyKind for $name{}
        };
        ($($name: ident),+) =>{
            $(
                key_kind!(@ $name);
            )+
        }
    }
key_kind! {
    BinaryKeyKind,
    TernaryKeyKind,
    GaussianKeyKind
}

pub(crate) mod sealed {
    pub(crate) trait EntityRepresentationSealed {}
    pub(crate) trait EntityKindSeal {}
    pub(crate) trait KeyKindSeal {}
}
