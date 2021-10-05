use crate::error::Result::{self, Err, Ok};
use crate::helpers::{DataRepr, FieldId};
use crate::{KeyletType, _c};

/// Guard function
///
/// Each time a loop appears in your code a call to this must be 
/// the first branch instruction after the beginning of the loop.
/// In order to achieve this in Rust use the while loop in this
/// manner:
/// ``` txt
/// let mut i = 0;
/// while {
///     _g(UNIQUE_GUARD_ID, MAXITER);
///     i < MAXITER
/// } {
///     ...
///     i += 1;
/// }
/// ```
#[inline(always)]
pub fn _g(id: u32, maxiter: u32) {
    unsafe {
        _c::_g(id, maxiter);
    }
}

/// Accept the originating transaction and commit any changes the hook made
#[inline(always)]
pub fn accept(msg: &[u8], error_code: i64) -> ! {
    unsafe {
        _c::accept(msg.as_ptr() as u32, msg.len() as u32, error_code);
        core::hint::unreachable_unchecked()
    }
}

/// Reject the originating transaction and discard any changes the hook made
#[inline(always)]
pub fn rollback(msg: &[u8], error_code: i64) -> ! {
    unsafe {
        _c::rollback(msg.as_ptr() as u32, msg.len() as u32, error_code);
        core::hint::unreachable_unchecked()
    }
}

/// Convert a 20 byte Account ID to an r-address
#[inline(always)]
pub fn util_raddr(raddr_out: &mut [u8], accid: &[u8]) -> Result<u64> {
    buf_write_read(raddr_out, accid, _c::util_raddr)
}

/// Convert an r-address into a 20 byte Account ID
#[inline(always)]
pub fn util_accid(accid_out: &mut [u8], raddr_in: &[u8]) -> Result<u64> {
    buf_write_read(accid_out, raddr_in, _c::util_accid)
}

/// Verify a cryptographic signature
#[inline(always)]
pub fn util_verify(payload: &[u8], signature: &[u8], publickey: &[u8]) -> bool {
    let res = buf_3_read(payload, signature, publickey, _c::util_verify);

    match res {
        Ok(0) => false,
        Ok(1) => true,
        _ => false,
    }
}

/// Compute an sha512-half over some data
#[inline(always)]
pub fn util_sha512h(hash_out: &mut [u8], data_in: &[u8]) -> Result<u64> {
    buf_write_read(hash_out, data_in, _c::util_sha512h)
}

/// Compute a serialized keylet of a given type
#[inline(always)]
pub fn util_keylet(keylet: &mut [u8], keylet_type: KeyletType) -> Result<u64> {
    let write_ptr = keylet.as_mut_ptr() as _;
    let write_len = keylet.len() as _;

    match keylet_type {
        KeyletType::Hook(accid) => buf_read_and_zeroes(keylet, accid, _c::KEYLET_HOOK),

        KeyletType::HookState(accid, statekey) => {
            buf_2_read_and_zeroes(keylet, accid, statekey, _c::KEYLET_HOOK_STATE)
        }

        KeyletType::Account(accid) => buf_read_and_zeroes(keylet, accid, _c::KEYLET_ACCOUNT),

        KeyletType::Amendments => all_zeroes(keylet, _c::KEYLET_AMENDMENTS),

        KeyletType::Child(key) => buf_read_and_zeroes(keylet, key, _c::KEYLET_CHILD),

        KeyletType::Skip(opt) => match opt {
            None => all_zeroes(keylet, _c::KEYLET_SKIP),

            Some((ledger_index, num)) => {
                let res = unsafe {
                    _c::util_keylet(
                        write_ptr,
                        write_len,
                        _c::KEYLET_SKIP,
                        ledger_index,
                        num,
                        0,
                        0,
                        0,
                        0,
                    )
                };

                result_u64(res)
            }
        },

        KeyletType::Fees => all_zeroes(keylet, _c::KEYLET_FEES),

        KeyletType::NegativeUnl => all_zeroes(keylet, _c::KEYLET_NEGATIVE_UNL),

        KeyletType::Line(accid_high, accid_low, currency_code) => {
            let res = unsafe {
                _c::util_keylet(
                    write_ptr,
                    write_len,
                    _c::KEYLET_LINE,
                    accid_high.as_ptr() as _,
                    accid_high.len() as _,
                    accid_low.as_ptr() as _,
                    accid_low.len() as _,
                    currency_code.as_ptr() as _,
                    currency_code.len() as _,
                )
            };

            result_u64(res)
        }

        KeyletType::Offer(accid, num) => buf_read_and_1_arg(keylet, accid, num, _c::KEYLET_OFFER),

        KeyletType::Quality(serialized_keylet, bits_high, bits_low) => buf_read_and_2_args(
            keylet,
            serialized_keylet,
            bits_high,
            bits_low,
            _c::KEYLET_QUALITY,
        ),

        KeyletType::EmittedDir => all_zeroes(keylet, _c::KEYLET_EMITTED_DIR),

        KeyletType::Signers(accid) => buf_read_and_zeroes(keylet, accid, _c::KEYLET_SIGNERS),

        KeyletType::Check(accid, num) => buf_read_and_1_arg(keylet, accid, num, _c::KEYLET_CHECK),

        KeyletType::DepositPreauth(accid_1, accid_2) => {
            buf_2_read_and_zeroes(keylet, accid_1, accid_2, _c::KEYLET_DEPOSIT_PREAUTH)
        }

        KeyletType::Unchecked(key) => buf_read_and_zeroes(keylet, key, _c::KEYLET_UNCHECKED),

        KeyletType::OwnerDir(accid) => buf_read_and_zeroes(keylet, accid, _c::KEYLET_OWNER_DIR),

        KeyletType::Page(key, bits_high, bits_low) => {
            buf_read_and_2_args(keylet, key, bits_high, bits_low, _c::KEYLET_PAGE)
        }

        KeyletType::Escrow(accid, num) => buf_read_and_1_arg(keylet, accid, num, _c::KEYLET_ESCROW),

        KeyletType::Paychan(accid_1, accid_2, num) => {
            let res = unsafe {
                _c::util_keylet(
                    write_ptr,
                    write_len,
                    _c::KEYLET_PAYCHAN,
                    accid_1.as_ptr() as _,
                    accid_1.len() as _,
                    accid_2.as_ptr() as _,
                    accid_2.len() as _,
                    num,
                    0,
                )
            };

            result_u64(res)
        }

        KeyletType::Emitted(key) => buf_read_and_zeroes(keylet, key, _c::KEYLET_EMITTED),
    }
}

/// Index into a xrpld serialized object and return the location and length of a subfield
#[inline(always)]
pub fn sto_subfield(sto: &[u8], field_id: FieldId) -> Result<&[u8]> {
    let res = unsafe { _c::sto_subfield(sto.as_ptr() as u32, sto.len() as u32, field_id as _) };

    let location = match res {
        res if res >= 0 => res,
        res => return Err(res),
    };

    Ok(&sto[range_from_location(location)])
}

/// Index into a xrpld serialized array and return the location and length of an index
#[inline(always)]
pub fn sto_subarray(sto: &[u8], array_id: u32) -> Result<&[u8]> {
    let res = unsafe { _c::sto_subarray(sto.as_ptr() as u32, sto.len() as u32, array_id) };

    let location = match res {
        res if res >= 0 => res,
        res => return Err(res),
    };

    Ok(&sto[range_from_location(location)])
}

/// Emplace a field into an existing STObject at its canonical placement
#[inline(always)]
pub fn sto_emplace(
    sto_out: &mut [u8],
    sto_src: &[u8],
    field: &[u8],
    field_id: FieldId,
) -> Result<u64> {
    let res = unsafe {
        _c::sto_emplace(
            sto_out.as_mut_ptr() as u32,
            sto_out.len() as u32,
            sto_src.as_ptr() as u32,
            sto_src.len() as u32,
            field.as_ptr() as u32,
            field.len() as u32,
            field_id as _,
        )
    };

    result_u64(res)
}

/// Remove a field from an STObject
#[inline(always)]
pub fn sto_erase(sto_out: &mut [u8], sto_src: &[u8], field_id: FieldId) -> Result<u64> {
    let res = unsafe {
        _c::sto_erase(
            sto_out.as_mut_ptr() as u32,
            sto_out.len() as u32,
            sto_src.as_ptr() as u32,
            sto_src.len() as u32,
            field_id as _,
        )
    };

    result_u64(res)
}

/// Validate an STObject
#[inline(always)]
pub fn sto_validate(sto: &[u8]) -> bool {
    let res = buf_read(sto, _c::sto_validate);

    match res {
        Ok(0) => false,
        Ok(1) => true,
        _ => false,
    }
}

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

/// XFL floating point numbers
#[derive(Clone, Copy)]
pub struct XFL(i64 /* enclosing number */);

/// Create a float from an exponent and mantissa
#[inline(always)]
pub fn float_set(exponent: i32, mantissa: i64) -> Result<XFL> {
    let res = unsafe { _c::float_set(exponent, mantissa) };

    result_xfl(res)
}

/// Multiply two XFL numbers together
#[inline(always)]
pub fn float_multiply(float1: XFL, float2: XFL) -> Result<XFL> {
    let res = unsafe { _c::float_multiply(float1.0, float2.0) };

    result_xfl(res)
}

/// Multiply an XFL floating point by a non-XFL numerator and denominator
#[inline(always)]
pub fn float_mulratio(
    float1: XFL,
    round_up: bool,
    numerator: u32,
    denominator: u32,
) -> Result<XFL> {
    let res = unsafe { _c::float_mulratio(float1.0, round_up as _, numerator, denominator) };

    result_xfl(res)
}

/// Negate an XFL floating point number
#[inline(always)]
pub fn float_negate(float: XFL) -> Result<XFL> {
    let res = unsafe { _c::float_negate(float.0) };

    result_xfl(res)
}

/// XFL compare mode
#[derive(Clone, Copy)]
pub enum XFLCompareMode {
    Less,
    Equal,
    Greater,
    NotEqual,
    LessOrEqual,
    GreaterOrEqual,
}

/// Perform a comparison on two XFL floating point numbers
#[inline(always)]
pub fn float_compare(float1: XFL, float2: XFL, mode: XFLCompareMode) -> Result<bool> {
    let mode = match mode {
        XFLCompareMode::Less => _c::COMPARE_LESS,
        XFLCompareMode::Equal => _c::COMPARE_EQUAL,
        XFLCompareMode::Greater => _c::COMPARE_GREATER,
        XFLCompareMode::NotEqual => _c::COMPARE_LESS | _c::COMPARE_GREATER,
        XFLCompareMode::LessOrEqual => _c::COMPARE_LESS | _c::COMPARE_EQUAL,
        XFLCompareMode::GreaterOrEqual => _c::COMPARE_GREATER | _c::COMPARE_EQUAL,
    };

    let res = unsafe { _c::float_compare(float1.0, float2.0, mode) };

    match res {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(res),
    }
}

/// Add two XFL numbers together
#[inline(always)]
pub fn float_sum(float1: XFL, float2: XFL) -> Result<XFL> {
    let res = unsafe { _c::float_sum(float1.0, float2.0) };

    result_xfl(res)
}

/// Output an XFL as a serialized object
#[inline(always)]
pub fn float_sto(
    amount: &mut [u8],
    currency_code: &[u8],
    issuer_accid: &[u8],
    float: XFL,
    field_code: FieldId
) -> Result<u64> {
    let res = unsafe {
        _c::float_sto(
            amount.as_mut_ptr() as _,
            amount.len() as _,
            currency_code.as_ptr() as _,
            currency_code.len() as _,
            issuer_accid.as_ptr() as _,
            issuer_accid.len() as _,
            float.0,
            field_code as _
        )
    };

    result_u64(res)
}

/// Read a serialized amount into an XFL
#[inline(always)]
pub fn float_sto_set(sto_xfl: &[u8]) -> Result<XFL> {
    let res = unsafe { _c::float_sto_set(sto_xfl.as_ptr() as _, sto_xfl.len() as _) };

    result_xfl(res)
}

/// Divide one by an XFL floating point number
#[inline(always)]
pub fn float_invert(float: XFL) -> Result<XFL> {
    let res = unsafe { _c::float_invert(float.0) };

    result_xfl(res)
}

/// Divide an XFL by another XFL floating point number
#[inline(always)]
pub fn float_divide(float1: XFL, float2: XFL) -> Result<XFL> {
    let res = unsafe { _c::float_divide(float1.0, float2.0) };

    result_xfl(res)
}

/// Return the number 1 represented in an XFL enclosing number
#[inline(always)]
pub fn float_one() -> XFL {
    XFL(unsafe { _c::float_one() })
}

/// Get the exponent of an XFL enclosing number
#[inline(always)]
pub fn float_exponent(float: XFL) -> i64 {
    unsafe { _c::float_exponent(float.0) }
}

/// Get the mantissa of an XFL enclosing number
#[inline(always)]
pub fn float_mantissa(float: XFL) -> i64 {
    unsafe { _c::float_mantissa(float.0) }
}

/// Get the sign of an XFL enclosing number
#[inline(always)]
pub fn float_sign(float: XFL) -> Result<bool> {
    match unsafe { _c::float_sign(float.0) } {
        0 => Ok(false),
        1 => Ok(true),
        res => Err(res)
    }
}

/// Set the exponent of an XFL enclosing number
#[inline(always)]
pub fn float_exponent_set(float: XFL, exponent: i32) -> Result<XFL> {
    let res = unsafe { _c::float_exponent_set(float.0, exponent) };

    result_xfl(res)
}

/// Set the mantissa of an XFL enclosing number
#[inline(always)]
pub fn float_mantissa_set(float: XFL, mantissa: i64) -> Result<XFL> {
    let res = unsafe { _c::float_mantissa_set(float.0, mantissa) };

    result_xfl(res)
}

/// Set the sign of an XFL enclosing number
#[inline(always)]
pub fn float_sign_set(float: XFL, sign: bool) -> XFL {
    XFL(unsafe { _c::float_sign_set(float.0, sign as _) })
}

/// Convert an XFL floating point into an integer (floor)
#[inline(always)]
pub fn float_int(float: XFL, decimal_places: u32, absolute: bool) -> Result<u64> {
    let res = unsafe { _c::float_int(float.0, decimal_places, absolute as _) };

    result_u64(res)
}

/// Retreive the 20 byte Account ID the Hook is executing on
#[inline(always)]
pub fn hook_account(accid: &mut [u8]) -> Result<u64> {
    buf_write(accid, _c::hook_account)
}

/// Retreive the 32 byte namespace biased SHA512H of the currently executing Hook
#[inline(always)]
pub fn hook_hash(hash: &mut [u8]) -> Result<u64> {
    buf_write(hash, _c::hook_hash)
}

/// Fetch the fee base of the current ledger
#[inline(always)]
pub fn fee_base() -> i64 {
    unsafe { _c::fee_base() }
}

/// Fetch the current ledger sequence number
#[inline(always)]
pub fn ledger_seq() -> i64 {
    unsafe { _c::ledger_seq() }
}

/// Retreive the 32 byte namespace biased SHA512H of the last closed ledger
#[inline(always)]
pub fn ledger_last_hash(hash: &mut [u8]) -> Result<u64> {
    buf_write(hash, _c::ledger_last_hash)
}

/// Generate a 32 byte nonce for use in an emitted transaction
#[inline(always)]
pub fn nonce(n: &mut [u8]) -> Result<u64> {
    buf_write(n, _c::nonce)
}

/// Serialize and output a slotted object
#[inline(always)]
pub fn slot(slotted_obj: &mut [u8], slot_no: u32) -> Result<u64> {
    buf_write_1arg(slotted_obj, slot_no, _c::slot)
}

/// Free up a currently occupied slot
#[inline(always)]
pub fn slot_clear(slot_no: u32) -> Result<u64> {
    api_1arg_call(slot_no, _c::slot_clear)
}

/// Count the elements of an array object in a slot
#[inline(always)]
pub fn slot_count(slot_no: u32) -> Result<u64> {
    api_1arg_call(slot_no, _c::slot_count)
}

/// Slot ID
#[inline(always)]
pub fn slot_id(slot_no: u32) -> Result<u64> {
    api_1arg_call(slot_no, _c::slot_id)
}

/// Locate an object based on its keylet and place it into a slot
#[inline(always)]
pub fn slot_set(keylet: &[u8], slot_no: i32) -> Result<u64> {
    let res = unsafe { _c::slot_set(keylet.as_ptr() as u32, keylet.len() as u32, slot_no) };

    result_u64(res)
}

/// Compute the serialized size of an object in a slot
#[inline(always)]
pub fn slot_size(slot_no: u32) -> Result<u64> {
    api_1arg_call(slot_no, _c::slot_size)
}

/// Index into a slotted array and assign a sub-object to another slot
#[inline(always)]
pub fn slot_subarray(parent_slot: u32, array_id: u32, new_slot: u32) -> Result<u64> {
    api_3arg_call(parent_slot, array_id, new_slot, _c::slot_subarray)
}

/// Index into a slotted object and assign a sub-object to another slot
#[inline(always)]
pub fn slot_subfield(parent_slot: u32, field_id: FieldId, new_slot: u32) -> Result<u64> {
    api_3arg_call(parent_slot, field_id as _, new_slot, _c::slot_subfield)
}

//todo: tricky args and return - think about
/// Retrieve the field code of an object in a slot and, optionally, some other information
#[inline(always)]
pub fn slot_type(slot_no: u32, flags: u32) -> Result<u64> {
    let res = unsafe { _c::slot_type(slot_no, flags) };

    result_u64(res)
}

/// Parse the STI_AMOUNT in the specified slot and return it as an XFL enclosed number
#[inline(always)]
pub fn slot_float(slot_no: u32) -> Result<XFL> {
    let res = unsafe { _c::slot_float(slot_no) };

    result_xfl(res)
}

/// Retrieve the data pointed to by a Hook State key and write it to an output buffer
#[inline(always)]
pub fn state(data: &mut [u8], key: &[u8]) -> Result<u64> {
    buf_write_read(data, key, _c::state)
}

/// Set the Hook State for a given key and value
#[inline(always)]
pub fn state_set(data: &[u8], key: &[u8]) -> Result<u64> {
    buf_2read(data, key, _c::state_set)
}

/// Retrieve the data pointed to, on another account, by a Hook State key and write it to an output buffer
#[inline(always)]
pub fn state_foreign(data: &mut [u8], key: &[u8], accid: &[u8]) -> Result<u64> {
    let res = unsafe {
        _c::state_foreign(
            data.as_mut_ptr() as u32,
            data.len() as u32,
            key.as_ptr() as u32,
            key.len() as u32,
            accid.as_ptr() as u32,
            accid.len() as u32,
        )
    };

    result_u64(res)
}

/// Write the contents of a buffer to the XRPLD trace log
#[inline(always)]
pub fn trace(msg: &[u8], data: &[u8], data_repr: DataRepr) -> Result<u64> {
    let res = unsafe {
        _c::trace(
            msg.as_ptr() as u32,
            msg.len() as u32,
            data.as_ptr() as u32,
            data.len() as u32,
            data_repr as _,
        )
    };

    result_u64(res)
}

/// Write the contents of a slot to the XRPLD trace log
#[inline(always)]
pub fn trace_slot(msg: &[u8], slot: u32) -> Result<u64> {
    let res = unsafe { _c::trace_slot(msg.as_ptr() as u32, msg.len() as u32, slot) };

    result_u64(res)
}

/// Write an integer to the XRPLD trace log
#[inline(always)]
pub fn trace_num(msg: &[u8], number: i64) -> Result<u64> {
    let res = unsafe { _c::trace_num(msg.as_ptr() as u32, msg.len() as u32, number) };

    result_u64(res)
}

/// Write a XFL float to the XRPLD trace log
#[inline(always)]
pub fn trace_float(msg: &[u8], float: XFL) -> Result<u64> {
    let res = unsafe { _c::trace_float(msg.as_ptr() as u32, msg.len() as u32, float.0) };

    result_u64(res)
}

/// Get the burden of the originating transaction
#[inline(always)]
pub fn otxn_burden() -> i64 {
    unsafe { _c::otxn_burden() }
}

/// Serialize and output a field from the originating transaction
#[inline(always)]
pub fn otxn_field(accid: &mut [u8], field_id: FieldId) -> Result<u64> {
    buf_write_1arg(accid, field_id as _, _c::otxn_field)
}

/// Output a field from the originating transaction as a human readable string
#[inline(always)]
pub fn otxn_field_txt(acctxt: &mut [u8], field_id: FieldId) -> Result<u64> {
    buf_write_1arg(acctxt, field_id as _, _c::otxn_field_txt)
}

/// Get the generation of the originating transaction
#[inline(always)]
pub fn otxn_generation() -> i64 {
    unsafe { _c::otxn_generation() }
}

/// Output the canonical hash of the originating transaction
#[inline(always)]
pub fn otxn_id(hash: &mut [u8]) -> Result<u64> {
    buf_write(hash, _c::otxn_id)
}

/// Get the Transaction Type of the originating transaction
#[inline(always)]
pub fn otxn_type() -> i64 {
    unsafe { _c::otxn_type() }
}

/// Load the originating transaction into a slot
#[inline(always)]
pub fn otxn_slot(slot_no: u32) -> Result<u64> {
    api_1arg_call(slot_no, _c::otxn_slot)
}

type Api1ArgsU32 = unsafe extern "C" fn(u32) -> i64;
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
fn api_1arg_call(arg: u32, fun: Api1ArgsU32) -> Result<u64> {
    let res = unsafe { fun(arg) };

    result_u64(res)
}

#[inline(always)]
fn api_3arg_call(arg_1: u32, arg_2: u32, arg_3: u32, fun: Api3ArgsU32) -> Result<u64> {
    let res = unsafe { fun(arg_1, arg_2, arg_3) };

    result_u64(res)
}

#[inline(always)]
fn buf_write(buf_write: &mut [u8], fun: BufWriter) -> Result<u64> {
    let res = unsafe { fun(buf_write.as_mut_ptr() as u32, buf_write.len() as u32) };

    result_u64(res)
}

#[inline(always)]
fn buf_write_1arg(buf_write: &mut [u8], arg: u32, fun: BufWriter1Arg) -> Result<u64> {
    let res = unsafe { fun(buf_write.as_mut_ptr() as u32, buf_write.len() as u32, arg) };

    result_u64(res)
}

#[inline(always)]
fn buf_read(buf: &[u8], fun: BufReader) -> Result<u64> {
    let res = unsafe { fun(buf.as_ptr() as u32, buf.len() as u32) };

    result_u64(res)
}

#[inline(always)]
fn buf_2read(buf_1: &[u8], buf_2: &[u8], fun: Buf2Reader) -> Result<u64> {
    let res = unsafe {
        fun(
            buf_1.as_ptr() as u32,
            buf_1.len() as u32,
            buf_2.as_ptr() as u32,
            buf_2.len() as u32,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn buf_write_read(buf_write: &mut [u8], buf_read: &[u8], fun: BufWriterReader) -> Result<u64> {
    let res = unsafe {
        fun(
            buf_write.as_mut_ptr() as u32,
            buf_write.len() as u32,
            buf_read.as_ptr() as u32,
            buf_read.len() as u32,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn buf_3_read(
    buf_read_1: &[u8],
    buf_read_2: &[u8],
    buf_read_3: &[u8],
    fun: Buf3Reader,
) -> Result<u64> {
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

    result_u64(res)
}

#[inline(always)]
fn result_u64(res: i64) -> Result<u64> {
    match res {
        res if res >= 0 => Ok(res as _),
        _ => Err(res),
    }
}

#[inline(always)]
fn range_from_location(location: i64) -> core::ops::Range<usize> {
    let offset: i32 = (location >> 32) as _;
    let lenght: i32 = (location & 0xFFFFFFFF) as _;

    core::ops::Range {
        start: offset as _,
        end: (offset + lenght) as _,
    }
}

#[inline(always)]
fn all_zeroes(buf_write: &mut [u8], keylet_type_c: u32) -> Result<u64> {
    let res = unsafe {
        _c::util_keylet(
            buf_write.as_mut_ptr() as _,
            buf_write.len() as _,
            keylet_type_c,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn buf_read_and_zeroes(buf_write: &mut [u8], buf_read: &[u8], keylet_type_c: u32) -> Result<u64> {
    let res = unsafe {
        _c::util_keylet(
            buf_write.as_mut_ptr() as _,
            buf_write.len() as _,
            keylet_type_c,
            buf_read.as_ptr() as _,
            buf_read.len() as _,
            0,
            0,
            0,
            0,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn buf_read_and_1_arg(
    buf_write: &mut [u8],
    buf_read: &[u8],
    arg: u32,
    keylet_type_c: u32,
) -> Result<u64> {
    let res = unsafe {
        _c::util_keylet(
            buf_write.as_mut_ptr() as _,
            buf_write.len() as _,
            keylet_type_c,
            buf_read.as_ptr() as _,
            buf_read.len() as _,
            arg,
            0,
            0,
            0,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn buf_read_and_2_args(
    buf_write: &mut [u8],
    buf_read: &[u8],
    arg_1: u32,
    arg_2: u32,
    keylet_type_c: u32,
) -> Result<u64> {
    let res = unsafe {
        _c::util_keylet(
            buf_write.as_mut_ptr() as _,
            buf_write.len() as _,
            keylet_type_c,
            buf_read.as_ptr() as _,
            buf_read.len() as _,
            arg_1,
            arg_2,
            0,
            0,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn buf_2_read_and_zeroes(
    buf_write: &mut [u8],
    buf_1_read: &[u8],
    buf_2_read: &[u8],
    keylet_type_c: u32,
) -> Result<u64> {
    let res = unsafe {
        _c::util_keylet(
            buf_write.as_mut_ptr() as _,
            buf_write.len() as _,
            keylet_type_c,
            buf_1_read.as_ptr() as _,
            buf_1_read.len() as _,
            buf_2_read.as_ptr() as _,
            buf_2_read.len() as _,
            0,
            0,
        )
    };

    result_u64(res)
}

#[inline(always)]
fn result_xfl(res: i64) -> Result<XFL> {
    match res {
        res if res >= 0 => Ok(XFL(res)),
        _ => Err(res),
    }
}
