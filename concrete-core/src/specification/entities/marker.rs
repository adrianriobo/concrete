/// This trait is implemented by types encoding the kind of an fhe entity in the type system.
///
/// By _kind_ here, we mean the different objects we manipulate at an abstract level (like
/// plaintext, cleartext, lwe ciphertext, ...).
pub trait EntityKindMarker: seal::EntityKindMarkerSealed {}
macro_rules! entity_kind_marker {
        (@ $name: ident => $doc: literal)=>{
            #[doc=$doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $name{}
            impl seal::EntityKindMarkerSealed for $name{}
            impl EntityKindMarker for $name{}
        };
        ($($name: ident => $doc: literal),+) =>{
            $(
                entity_kind_marker!(@ $name => $doc);
            )+
        }
}
entity_kind_marker! {
        PlaintextKind
            => "A type encoding the plaintext kind in the type system.",
        PlaintextVectorKind
            => "A type encoding the plaintext vector kind in the type system",
        CleartextKind
            => "A type encoding the cleartext kind in the type system.",
        CleartextVectorKind
            => "A type encoding the cleartext vector kind in the type system.",
        LweCiphertextKind
            => "A type encoding the lwe ciphertext kind in the type system.",
        LweCiphertextVectorKind
            => "A type encoding the lwe ciphertext vector kind in the type system.",
        GlweCiphertextKind
            => "A type encoding the glwe ciphertext kind in the type system.",
        GlweCiphertextVectorKind
            => "A type encoding the glwe ciphertext vector kind in the type system.",
        GgswCiphertextKind
            => "A type encoding the ggsw ciphertext kind in the type system.",
        GgswCiphertextVectorKind
            => "A type encoding the ggsw ciphertext vector kind in the type system.",
        GswCiphertextKind
            => "A type encoding the gsw ciphertext kind in the type system.",
        GswCiphertextVectorKind
            => "A type encoding the gsw ciphertext vector kind in the type system.",
        LweSecretKeyKind
            => "A type encoding the lwe secret key kind in the type system.",
        GlweSecretKeyKind
            => "A type encoding the glwe secret key kind in the type system.",
        LweKeyswitchKeyKind
            => "A type encoding the lwe keyswitch key kind in the type system.",
        LweBootstrapKeyKind
            => "A type encoding the lwe bootstrap key kind in the type system."
}

/// This trait is implemented by types encoding the representation on an fhe entity in the type
/// system.
///
/// By _representation_ here, we mean the format of a given entity, during the execution of the
/// program. A type implementing this trait should contain every informations needed to completely
/// define the format, such as:
///
/// + The location of the object: Is it in the cpu or the gpu memory ?
/// + The domain the object is represented in: Is it in the fourier, the ntt, or the standard
/// domain?
/// + The precision used to represent the object: Is it 16, 32, 64, 128 bits ?
pub trait EntityRepresentationMarker: seal::EntityRepresentationMarkerSealed {}

/// This trait is implemented by types encoding a flavor of secret key in the type system.
///
/// By _flavor_ here, we mean the different types of secret key that can exist such as binary,
/// ternary, uniform or gaussian key.
pub trait KeyFlavorMarker: seal::KeyFlavorMarkerSealed {}
macro_rules! key_flavor_marker {
        (@ $name: ident => $doc: literal)=>{
            #[doc=$doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $name{}
            impl seal::KeyFlavorMarkerSealed for $name{}
            impl KeyFlavorMarker for $name{}
        };
        ($($name: ident => $doc: literal),+) =>{
            $(
                key_flavor_marker!(@ $name => $doc);
            )+
        }
    }
key_flavor_marker! {
    BinaryKeyFlavor => "A type encoding the binary key flavor in the type system.",
    TernaryKeyFlavor => "A type encoding the ternary key flavor in the type system.",
    GaussianKeyFlavor => "A type encoding the gaussian key flavor in the type system."
}

pub(crate) mod seal {
    pub trait EntityRepresentationMarkerSealed {}
    pub trait EntityKindMarkerSealed {}
    pub trait KeyFlavorMarkerSealed {}
}
