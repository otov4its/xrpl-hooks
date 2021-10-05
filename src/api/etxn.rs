use super::*;

/// Get the burden of a hypothetically emitted transaction
#[inline(always)]
pub fn etxn_burden() -> i64 {
    unsafe { _c::etxn_burden() }
}

/// Produce an sfEmitDetails suitable for a soon-to-be emitted transaction
#[inline(always)]
pub fn etxn_details(emitdet: &mut [u8]) -> Result<u64> {
    buf_write(emitdet, _c::etxn_details)
}

/// Estimate the required fee for a txn to be emitted successfully
#[inline(always)]
pub fn etxn_fee_base(tx_byte_count: u32) -> Result<u64> {
    api_1arg_call(tx_byte_count, _c::etxn_fee_base)
}

/// Estimate the required fee for a txn to be emitted successfully
#[inline(always)]
pub fn etxn_reserve(count: u32) -> Result<u64> {
    api_1arg_call(count, _c::etxn_reserve)
}

/// Get the generation of a hypothetically emitted transaction
#[inline(always)]
pub fn etxn_generation() -> i64 {
    unsafe { _c::etxn_generation() }
}

/// Emit a new transaction from the hook
#[inline(always)]
pub fn emit(hash: &mut [u8], tx_buf: &[u8]) -> Result<u64> {
    buf_write_read(hash, tx_buf, _c::emit)
}
