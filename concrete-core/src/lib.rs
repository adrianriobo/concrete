//! Welcome to the `concrete-core` documentation!
//!
//! # Fully Homomorphic Encryption
//!
//! This library contains low-level primitives which can be used to implement *fully
//! homomorphically encrypted* programs. In a nutshell, fully homomorphic
//! encryption allows you to perform any computation you would normally perform over clear data;
//! but this time over encrypted data. With fhe, you can perform computations without putting
//! your trust on third-party providers. To learn more about the fhe schemes used in this library,
//! you can have a look at the following papers:
//!
//! + [CONCRETE: Concrete Operates oN Ciphertexts Rapidly by Extending TfhE](https://whitepaper.zama.ai/concrete/WAHC2020Demo.pdf)
//! + [Programmable Bootstrapping Enables Efficient Homomorphic Inference of Deep Neural Networks](https://whitepaper.zama.ai/)
//!
//! # Architecture
//!
//! `concrete-core` is a pretty modular library. The `specification` module contains a specification
//! (in the form of traits) of the concrete fhe scheme. It describes the fhe datatypes and
//! operators, which are exposed by the library. The `backends` module contains various backends
//! implementing all or a part of this scheme. These different backends can be activated by feature
//! flags, and can make use of different hardware or system libraries to make operations faster.

/// A module containing a specification of the concrete fhe scheme.
pub mod specification;

/// A module containing various backends implementing the concrete fhe scheme.
pub mod backends;
