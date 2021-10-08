//! XRPL Hooks API
//!
//! This crate allows you to write XRPL hooks in Rust.
//!
//! Before you begin, it is highly recommended that you read
//! the [official docs](https://xrpl-hooks.readme.io/) carefully.
//!
//! # Examples
//!
//! For a quick start and to view examples,
//! use the [hook template](https://github.com/otov4its/xrpl-hook-template/)

#![no_std]
#![deny(
    warnings,
    clippy::all,
    missing_copy_implementations,
    missing_docs,
    rustdoc::missing_crate_level_docs,
    rustdoc::missing_doc_code_examples,
    non_ascii_idents,
    unreachable_pub
)]
#![doc(test(attr(deny(warnings))))]
#![doc(html_root_url = "https://docs.rs/xrpl-hooks/0.3.0")]

mod macros;

/// # Low-level unsafe C bindings
///
/// Use very carefully if at all necessary.
pub mod _c;

/// XRPL Hooks API
pub mod api;

/// A few utilities
pub mod helpers;

// Prelude
pub use {api::*, helpers::*};

#[cfg(not(test))]
use core::panic::PanicInfo;
/// You should use rollback() instead of native panic!() macro
#[cfg(not(test))]
#[inline(always)]
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
