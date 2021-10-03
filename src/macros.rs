#[macro_export]
macro_rules! uninit_buf {
    () => {
        unsafe { ::core::mem::MaybeUninit::uninit().assume_init() }
    };
}
