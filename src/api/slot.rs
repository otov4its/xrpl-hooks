use super::*;

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
