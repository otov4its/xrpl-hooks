use crate::api::rollback;

/// Simple version of Result type 
/// to comply XRPL Hooks Webassembly restrictions
#[must_use]
pub enum Result<T> {
    Ok(T),
    Err(i64)
}

pub use self::Result::*;

#[must_use]
impl<T> Result<T> {
    #[inline(always)]
    pub fn expect(self, msg: &[u8]) -> T {
        match self {
            Err(e) => rollback(msg, e),
            Ok(val) => val
        }
    }

    #[inline(always)]
    pub fn unwrap(self) -> T {
        match self {
            Err(e) => rollback(b"error", e),
            Ok(val) => val
        }
    }

    #[inline(always)]
    pub unsafe fn unwrap_unchecked(self) -> T {
        match self {
            Ok(val) => val,
            // SAFETY: the safety contract must be upheld by the caller.
            Err(_) => core::hint::unreachable_unchecked(),
        }
    }

    #[must_use]
    #[inline(always)]
    pub const fn is_ok(&self) -> bool {
        matches!(*self, Ok(_))
    }

    #[must_use]
    #[inline(always)]
    pub const fn is_err(&self) -> bool {
        !self.is_ok()
    }
}
