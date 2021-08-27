//! The `concrete-core` backends provides give access to two different families of objects:
//!
//! + _Entities_ which are fhe datatypes you can manipulate with the library.
//! + _Engines_ which are objects you can use to operate on entities.
//!
//! This module contains different traits which give a layout of how the different backends
//! implement the concrete core scheme.

/// A module containing traits for entities.
pub mod entities;

/// A module containing traits for engines.
pub mod engines;
