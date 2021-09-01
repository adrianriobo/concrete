//! A module containing a specification of the concrete fhe scheme.
//!
//! The `concrete-core` backends provides give access to two different families of objects:
//!
//! + __Entities__ which are fhe objects you can manipulate with the library.
//! + __Engines__ which are types you can use to operate on entities.
//!
//! This module contains different traits which, united, provide a layout of how the different
//! backends implement the concrete scheme.

pub mod engines;
pub mod entities;
