/// Assumes uninitialized as initialized
///
/// Rust doesn't allow to use uninitialized values, but we need them to avoid
/// memset, memcpy extra functions call in wasm binary.
/// Use this macro every time you need a buffer.
///
/// # Example
///
/// ``` txt
/// let mut buf: [u8; 20] = uninit_buf!();
/// ```
#[macro_export]
macro_rules! uninit_buf {
    () => {
        unsafe { ::core::mem::MaybeUninit::uninit().assume_init() }
    };
}
