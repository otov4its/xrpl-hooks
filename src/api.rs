use crate::_c;
use crate::error::Result::{self, Err, Ok};
use crate::helpers::{
    FieldId,
    DataRepr,
};

#[inline(always)]
pub fn _g(id: u32, maxiter: u32) {
    unsafe {
        _c::_g(id, maxiter);
    }
}

#[inline(always)]
pub fn accept(msg: &[u8], error_code: i64) -> ! {
    unsafe {
        _c::accept(msg.as_ptr() as u32, msg.len() as u32, error_code);
        core::hint::unreachable_unchecked()
    }
}

#[inline(always)]
pub fn rollback(msg: &[u8], error_code: i64) -> ! {
    unsafe {
        _c::rollback(msg.as_ptr() as u32, msg.len() as u32, error_code);
        core::hint::unreachable_unchecked()
    }
}

#[inline(always)]
pub fn util_raddr(raddr_out: &mut [u8], accid: &[u8]) -> Result<u64> {
    buf_write_read(raddr_out, accid, _c::util_raddr)
}

#[inline(always)]
pub fn util_accid(accid_out: &mut [u8], raddr_in: &[u8]) -> Result<u64> {
    buf_write_read(accid_out, raddr_in, _c::util_accid)
}

#[inline(always)]
pub fn util_verify(payload: &[u8], signature: &[u8], publickey: &[u8]) -> bool {
    let res = buf_3_read(payload, signature, publickey, _c::util_verify);

    match res {
        Ok(0) => false,
        Ok(1) => true,
        _ => false
    }
}

#[inline(always)]
pub fn util_sha512h(hash_out: &mut [u8], data_in: &[u8]) -> Result<u64> {
    buf_write_read(hash_out, data_in, _c::util_sha512h)
}

//TODO: make multiple pub helpers functions
#[inline(always)]
fn _util_keylet() -> ! {
    unimplemented!("use _c::util_keylet")
}

#[inline(always)]
pub fn sto_subfield(sto: &[u8], field_id: FieldId) -> Result<&[u8]> {
    let res = unsafe {
        _c::sto_subfield(sto.as_ptr() as u32, sto.len() as u32, field_id as _)
    };

    let location = match res {
        res if res >= 0 => res,
        res => return Err(res)
    };

    Ok(
        &sto[range_from_location(location)]
    )
}

#[inline(always)]
pub fn sto_subarray(sto: &[u8], array_id: u32) -> Result<&[u8]> {
    let res = unsafe {
        _c::sto_subarray(sto.as_ptr() as u32, sto.len() as u32, array_id)
    };

    let location = match res {
        res if res >= 0 => res,
        res => return Err(res)
    };

    Ok(
        &sto[range_from_location(location)]
    )
}

#[inline(always)]
pub fn sto_emplace(sto_out: &mut [u8], sto_src: &[u8], field: &[u8], field_id: FieldId) -> Result<u64> {
    let res = unsafe {
        _c::sto_emplace(
            sto_out.as_mut_ptr() as u32,
            sto_out.len() as u32,
            sto_src.as_ptr() as u32,
            sto_src.len() as u32,
            field.as_ptr() as u32,
            field.len() as u32,
            field_id as _
        )
    };

    result(res)
}

#[inline(always)]
pub fn sto_erase(sto_out: &mut [u8], sto_src: &[u8], field_id: FieldId) -> Result<u64> {
    let res = unsafe {
        _c::sto_erase(
            sto_out.as_mut_ptr() as u32,
            sto_out.len() as u32,
            sto_src.as_ptr() as u32,
            sto_src.len() as u32,
            field_id as _
        )
    };

    result(res)
}

#[inline(always)]
pub fn sto_validate(sto: &[u8]) -> bool {
    let res = buf_read(sto, _c::sto_validate);

    match res {
        Ok(0) => false,
        Ok(1) => true,
        _ => false
    }
}

#[inline(always)]
pub fn etxn_burden() -> i64 {
    unsafe { _c::etxn_burden() }
}

#[inline(always)]
pub fn etxn_details(emitdet: &mut [u8]) -> Result<u64> {
    buf_write(emitdet, _c::etxn_details)
}

#[inline(always)]
pub fn etxn_fee_base(tx_byte_count: u32) -> Result<u64> {
    let res = unsafe { _c::etxn_fee_base(tx_byte_count) };

    result(res)
}

#[inline(always)]
pub fn etxn_reserve(count: u32) -> Result<u64> {
    let res = unsafe { _c::etxn_reserve(count) };

    result(res)
}

#[inline(always)]
pub fn etxn_generation() -> i64 {
    unsafe { _c::etxn_generation() }
}

#[inline(always)]
pub fn emit(hash: &mut [u8], tx_buf: &[u8]) -> Result<u64> {
    buf_write_read(hash, tx_buf, _c::emit)
}

//TODO: float api

#[inline(always)]
pub fn hook_account(accid: &mut [u8]) -> Result<u64> {
    buf_write(accid, _c::hook_account)
}

#[inline(always)]
pub fn hook_hash(hash: &mut [u8]) -> Result<u64> {
    buf_write(hash, _c::hook_hash)
}

#[inline(always)]
pub fn fee_base() -> i64 {
    unsafe { _c::fee_base() }
}

#[inline(always)]
pub fn ledger_seq() -> i64 {
    unsafe { _c::ledger_seq() }
}

#[inline(always)]
pub fn ledger_last_hash(hash: &mut [u8]) -> Result<u64> {
    buf_write(hash, _c::ledger_last_hash)
}

#[inline(always)]
pub fn nonce(n: &mut [u8]) -> Result<u64> {
    buf_write(n, _c::nonce)
}

//TODO: slot api

#[inline(always)]
pub fn state(data: &mut [u8], key: &[u8]) -> Result<u64> {
    buf_write_read(data, key, _c::state)
}

#[inline(always)]
pub fn state_set(data: &[u8], key: &[u8]) -> Result<u64> {
    buf_2read(data, key, _c::state_set)
}

#[inline(always)]
pub fn state_foreign(data: &mut [u8], key: &[u8], accid: &[u8]) -> Result<u64> {
    let res = unsafe {
        _c::state_foreign(
            data.as_mut_ptr() as u32,
            data.len() as u32,
            key.as_ptr() as u32,
            key.len() as u32,
            accid.as_ptr() as u32,
            accid.len() as u32
        )
    };

    result(res)
}

#[inline(always)]
pub fn trace(msg: &[u8], data: &[u8], data_repr: DataRepr) -> Result<u64> {
    let res = unsafe {
        _c::trace(msg.as_ptr() as u32, msg.len() as u32, data.as_ptr() as u32, data.len() as u32, data_repr as _)
    };

    result(res)
}

#[inline(always)]
pub fn trace_num(msg: &[u8], number: i64) -> Result<u64> {
    let res = unsafe {
        _c::trace_num(msg.as_ptr() as u32, msg.len() as u32, number)
    };

    result(res)
}

#[inline(always)]
pub fn trace_slot(msg: &[u8], slot: u32) -> Result<u64> {
    let res = unsafe {
        _c::trace_slot(msg.as_ptr() as u32, msg.len() as u32, slot)
    };

    result(res)
}

#[inline(always)]
pub fn trace_float(msg: &[u8], float: i64) -> Result<u64> {
    let res = unsafe {
        _c::trace_float(msg.as_ptr() as u32, msg.len() as u32, float)
    };

    result(res)
}

#[inline(always)]
pub fn otxn_burden() -> i64 {
    unsafe { _c::otxn_burden() }
}

#[inline(always)]
pub fn otxn_field(accid: &mut [u8], field_id: FieldId) -> Result<u64> {
    buf_write_1arg(accid, field_id as _, _c::otxn_field)
}

#[inline(always)]
pub fn otxn_field_txt(acctxt: &mut [u8], field_id: FieldId) -> Result<u64> {
    buf_write_1arg(acctxt, field_id as _, _c::otxn_field_txt)
}

#[inline(always)]
pub fn otxn_generation() -> i64 {
    unsafe { _c::otxn_generation() }
}

#[inline(always)]
pub fn otxn_id(hash: &mut [u8]) -> Result<u64> {
    buf_write(hash, _c::otxn_id)
}

#[inline(always)]
pub fn otxn_type() -> i64 {
    unsafe { _c::otxn_type() }
}

#[inline(always)]
pub fn otxn_slot(slot_no: u32) -> Result<u64> {
    let res = unsafe { _c::otxn_slot(slot_no) };

    result(res)
}

type Api2ArgsU32 = unsafe extern "C" fn(u32, u32) -> i64;
type Api3ArgsU32 = unsafe extern "C" fn(u32, u32, u32) -> i64;
type Api4ArgsU32 = unsafe extern "C" fn(u32, u32, u32, u32) -> i64;
type Api6ArgsU32 = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32) -> i64;

type BufWriter = Api2ArgsU32;
type BufReader = Api2ArgsU32;
type Buf2Reader = Api4ArgsU32;
type BufWriterReader = Api4ArgsU32;
type Buf3Reader = Api6ArgsU32;
type BufWriter1Arg = Api3ArgsU32;

#[inline(always)]
fn buf_write(buf_write: &mut [u8], fun: BufWriter) -> Result<u64> {
    let res = unsafe { fun(buf_write.as_mut_ptr() as u32, buf_write.len() as u32) };

    result(res)
}

#[inline(always)]
fn buf_write_1arg(buf_write: &mut [u8], arg: u32, fun: BufWriter1Arg) -> Result<u64> {
    let res = unsafe { fun(buf_write.as_mut_ptr() as u32, buf_write.len() as u32, arg) };

    result(res)
}

#[inline(always)]
fn buf_read(buf: &[u8], fun: BufReader) -> Result<u64> {
    let res = unsafe { fun(buf.as_ptr() as u32, buf.len() as u32) };

    result(res)
}

#[inline(always)]
fn buf_2read(buf_1: &[u8], buf_2: &[u8], fun: Buf2Reader) -> Result<u64> {
    let res = unsafe { fun(buf_1.as_ptr() as u32, buf_1.len() as u32, buf_2.as_ptr() as u32, buf_2.len() as u32) };

    result(res)
}

#[inline(always)]
fn buf_write_read(buf_write: &mut [u8], buf_read: &[u8], fun: BufWriterReader) -> Result<u64> {
    let res = unsafe { 
        fun(
            buf_write.as_mut_ptr() as u32,
            buf_write.len() as u32,
            buf_read.as_ptr() as u32,
            buf_read.len() as u32
        )
    };

    result(res)
}

#[inline(always)]
fn buf_3_read(buf_read_1: &[u8], buf_read_2: &[u8], buf_read_3: &[u8], fun: Buf3Reader) -> Result<u64> {
    let res = unsafe { 
        fun(
            buf_read_1.as_ptr() as u32,
            buf_read_1.len() as u32,
            buf_read_2.as_ptr() as u32,
            buf_read_2.len() as u32,
            buf_read_3.as_ptr() as u32,
            buf_read_3.len() as u32,
        )
    };

    result(res)
}

#[inline(always)]
fn result(res: i64) -> Result<u64> {
    match res {
        res if res >= 0 => Ok(res as _),
        _ => Err(res)
    }
}

#[inline(always)]
fn range_from_location(location: i64) -> core::ops::Range<usize> {
    let offset: i32 = (location >> 32) as _;
    let lenght: i32 = (location & 0xFFFFFFFF) as _;

    core::ops::Range {start: offset as _, end: (offset + lenght) as _}
}
