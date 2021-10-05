//! XRPL Hooks API
//!
//! # Examples
//!
//! See <https://github.com/otov4its/xrpl-hook-template/>

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
#![doc(html_root_url = "https://docs.rs/xrpl-hooks/0.1.0")]

/// # Low-level unsafe C bindings
///
/// Use very carefully if at all necessary.
pub mod _c;

/// XRPL Hooks API
pub mod api;

/// A few utilities
pub mod helpers;

/// Usefull macros to comply XRPL Hooks
pub mod macros;

// Prelude
pub use {api::*, helpers::*, macros::*};

#[cfg(not(test))]
use core::panic::PanicInfo;
/// You should use rollback() instead of native panic!() macro
#[cfg(not(test))]
#[inline(always)]
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
