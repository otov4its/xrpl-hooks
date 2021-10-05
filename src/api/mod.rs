#![allow(missing_docs)] //todo more detailed docs

use crate::_c;

mod control;
mod util;
mod sto;
mod etxn;
mod float;
mod ledger;
mod slot;
mod state;
mod trace;
mod otxn;

pub use control::*;
pub use util::*;
pub use sto::*;
pub use etxn::*;
pub use float::*;
pub use ledger::*;
pub use slot::*;
pub use state::*;
pub use trace::*;
pub use otxn::*;


pub const TF_CANONICAL: u32 = _c::tfCANONICAL;

pub const ACC_ID_LEN: usize = 20;
pub const CURRENCY_CODE_SIZE: usize = 20;
pub const LEDGER_HASH_LEN: usize = 32;
pub const KEYLET_LEN: usize = 34;
pub const STATE_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const AMOUNT_LEN: usize = 48;
pub const PREPARE_PAYMENT_SIMPLE_SIZE: usize = _c::PREPARE_PAYMENT_SIMPLE_SIZE as _;
pub const EMIT_DETAILS_SIZE: usize = 105;

pub type Buffer<const T: usize> = [u8; T];

pub type AccountId = Buffer<ACC_ID_LEN>;
pub type Hash = Buffer<HASH_LEN>;
pub type Keylet = Buffer<KEYLET_LEN>;
pub type StateKey = Buffer<STATE_KEY_LEN>;
pub type Nonce = Buffer<NONCE_LEN>;
pub type Amount = Buffer<AMOUNT_LEN>;
pub type TxnPaymentSimple = Buffer<PREPARE_PAYMENT_SIMPLE_SIZE>;
pub type EmitDetails = Buffer<EMIT_DETAILS_SIZE>;
pub type CurrencyCode = Buffer<CURRENCY_CODE_SIZE>;

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum TxnType {
    Payment = _c::ttPAYMENT as isize,
    EscrowCreate = 1,
    EscrowFinish = 2,
    AccountSet = 3,
    EscrowCancel = 4,
    RegularKeySet = 5,
    OfferCreate = 7,
    OfferCancel = 8,
    TicketCreate = 10,
    TicketCancel = 11,
    SignerListSet = 12,
    PaychanCreate = 13,
    PaychanFund = 14,
    PaychanClaim = 15,
    CheckCreate = 16,
    CheckCash = 17,
    CheckCancel = 18,
    DepositPreauth = 19,
    TrustSet = 20,
    AccountDelete = 21,
    HookSet = 22,
    Amendment = 100,
    Fee = 101,
    UnlModify = 102,
}

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum AccountType {
    Account = _c::atACCOUNT as isize,
    Owner = _c::atOWNER as isize,
    Destination = _c::atDESTINATION as isize,
    Issuer = _c::atISSUER as isize,
    Authorize = _c::atAUTHORIZE as isize,
    Unauthorize = _c::atUNAUTHORIZE as isize,
    Target = _c::atTARGET as isize,
    RegularKey = _c::atREGULARKEY as isize,
    PseudoCallback = _c::atPSEUDOCALLBACK as isize,
}

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum AmountType {
    Amount = _c::amAMOUNT as isize,
    Balance = _c::amBALANCE as isize,
    LimitAmount = _c::amLIMITAMOUNT as isize,
    TakerPays = _c::amTAKERPAYS as isize,
    TakerGets = _c::amTAKERGETS as isize,
    LowLimit = _c::amLOWLIMIT as isize,
    HighLimit = _c::amHIGHLIMIT as isize,
    Fee = _c::amFEE as isize,
    SendMax = _c::amSENDMAX as isize,
    DeliverMin = _c::amDELIVERMIN as isize,
    MinimumOffer = _c::amMINIMUMOFFER as isize,
    RippleEscrow = _c::amRIPPLEESCROW as isize,
    DeliveredAmount = _c::amDELIVEREDAMOUNT as isize,
}

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum KeyletType<'a> {
    Hook(&'a [u8]),
    HookState(&'a [u8], &'a [u8]),
    Account(&'a [u8]),
    Amendments,
    Child(&'a [u8]),
    Skip(Option<(u32, u32)>),
    Fees,
    NegativeUnl,
    Line(&'a [u8], &'a [u8], &'a [u8]),
    Offer(&'a [u8], u32),
    Quality(&'a [u8], u32, u32),
    EmittedDir,
    Signers(&'a [u8]),
    Check(&'a [u8], u32),
    DepositPreauth(&'a [u8], &'a [u8]),
    Unchecked(&'a [u8]),
    OwnerDir(&'a [u8]),
    Page(&'a [u8], u32, u32),
    Escrow(&'a [u8], u32),
    Paychan(&'a [u8], &'a [u8], u32),
    Emitted(&'a [u8]),
}

//todo: think about enums #[repr(u32)] to safe mem::transmutes
//      return codes into enums

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum FieldId {
    Invalid = _c::sfInvalid as isize,
    Generic = _c::sfGeneric as isize,
    LedgerEntry = _c::sfLedgerEntry as isize,
    Transaction = _c::sfTransaction as isize,
    Validation = _c::sfValidation as isize,
    Metadata = _c::sfMetadata as isize,
    Hash = _c::sfHash as isize,
    Index = _c::sfIndex as isize,
    CloseResolution = _c::sfCloseResolution as isize,
    Method = _c::sfMethod as isize,
    TransactionResult = _c::sfTransactionResult as isize,
    TickSize = _c::sfTickSize as isize,
    UNLModifyDisabling = _c::sfUNLModifyDisabling as isize,
    LedgerEntryType = _c::sfLedgerEntryType as isize,
    TransactionType = _c::sfTransactionType as isize,
    SignerWeight = _c::sfSignerWeight as isize,
    Version = _c::sfVersion as isize,
    Flags = _c::sfFlags as isize,
    SourceTag = _c::sfSourceTag as isize,
    Sequence = _c::sfSequence as isize,
    PreviousTxnLgrSeq = _c::sfPreviousTxnLgrSeq as isize,
    LedgerSequence = _c::sfLedgerSequence as isize,
    CloseTime = _c::sfCloseTime as isize,
    ParentCloseTime = _c::sfParentCloseTime as isize,
    SigningTime = _c::sfSigningTime as isize,
    Expiration = _c::sfExpiration as isize,
    TransferRate = _c::sfTransferRate as isize,
    WalletSize = _c::sfWalletSize as isize,
    OwnerCount = _c::sfOwnerCount as isize,
    DestinationTag = _c::sfDestinationTag as isize,
    HighQualityIn = _c::sfHighQualityIn as isize,
    HighQualityOut = _c::sfHighQualityOut as isize,
    LowQualityIn = _c::sfLowQualityIn as isize,
    LowQualityOut = _c::sfLowQualityOut as isize,
    QualityIn = _c::sfQualityIn as isize,
    QualityOut = _c::sfQualityOut as isize,
    StampEscrow = _c::sfStampEscrow as isize,
    BondAmount = _c::sfBondAmount as isize,
    LoadFee = _c::sfLoadFee as isize,
    OfferSequence = _c::sfOfferSequence as isize,
    FirstLedgerSequence = _c::sfFirstLedgerSequence as isize,
    LastLedgerSequence = _c::sfLastLedgerSequence as isize,
    TransactionIndex = _c::sfTransactionIndex as isize,
    OperationLimit = _c::sfOperationLimit as isize,
    ReferenceFeeUnits = _c::sfReferenceFeeUnits as isize,
    ReserveBase = _c::sfReserveBase as isize,
    ReserveIncrement = _c::sfReserveIncrement as isize,
    SetFlag = _c::sfSetFlag as isize,
    ClearFlag = _c::sfClearFlag as isize,
    SignerQuorum = _c::sfSignerQuorum as isize,
    CancelAfter = _c::sfCancelAfter as isize,
    FinishAfter = _c::sfFinishAfter as isize,
    SignerListID = _c::sfSignerListID as isize,
    SettleDelay = _c::sfSettleDelay as isize,
    HookStateCount = _c::sfHookStateCount as isize,
    HookReserveCount = _c::sfHookReserveCount as isize,
    HookDataMaxSize = _c::sfHookDataMaxSize as isize,
    EmitGeneration = _c::sfEmitGeneration as isize,
    IndexNext = _c::sfIndexNext as isize,
    IndexPrevious = _c::sfIndexPrevious as isize,
    BookNode = _c::sfBookNode as isize,
    OwnerNode = _c::sfOwnerNode as isize,
    BaseFee = _c::sfBaseFee as isize,
    ExchangeRate = _c::sfExchangeRate as isize,
    LowNode = _c::sfLowNode as isize,
    HighNode = _c::sfHighNode as isize,
    DestinationNode = _c::sfDestinationNode as isize,
    Cookie = _c::sfCookie as isize,
    ServerVersion = _c::sfServerVersion as isize,
    EmitBurden = _c::sfEmitBurden as isize,
    HookOn = _c::sfHookOn as isize,
    EmailHash = _c::sfEmailHash as isize,
    TakerPaysCurrency = _c::sfTakerPaysCurrency as isize,
    TakerPaysIssuer = _c::sfTakerPaysIssuer as isize,
    TakerGetsCurrency = _c::sfTakerGetsCurrency as isize,
    TakerGetsIssuer = _c::sfTakerGetsIssuer as isize,
    LedgerHash = _c::sfLedgerHash as isize,
    ParentHash = _c::sfParentHash as isize,
    TransactionHash = _c::sfTransactionHash as isize,
    AccountHash = _c::sfAccountHash as isize,
    PreviousTxnID = _c::sfPreviousTxnID as isize,
    LedgerIndex = _c::sfLedgerIndex as isize,
    WalletLocator = _c::sfWalletLocator as isize,
    RootIndex = _c::sfRootIndex as isize,
    AccountTxnID = _c::sfAccountTxnID as isize,
    EmitParentTxnID = _c::sfEmitParentTxnID as isize,
    EmitNonce = _c::sfEmitNonce as isize,
    BookDirectory = _c::sfBookDirectory as isize,
    InvoiceID = _c::sfInvoiceID as isize,
    Nickname = _c::sfNickname as isize,
    Amendment = _c::sfAmendment as isize,
    TicketID = _c::sfTicketID as isize,
    Digest = _c::sfDigest as isize,
    PayChannel = _c::sfPayChannel as isize,
    ConsensusHash = _c::sfConsensusHash as isize,
    CheckID = _c::sfCheckID as isize,
    ValidatedHash = _c::sfValidatedHash as isize,
    Amount = _c::sfAmount as isize,
    Balance = _c::sfBalance as isize,
    LimitAmount = _c::sfLimitAmount as isize,
    TakerPays = _c::sfTakerPays as isize,
    TakerGets = _c::sfTakerGets as isize,
    LowLimit = _c::sfLowLimit as isize,
    HighLimit = _c::sfHighLimit as isize,
    Fee = _c::sfFee as isize,
    SendMax = _c::sfSendMax as isize,
    DeliverMin = _c::sfDeliverMin as isize,
    MinimumOffer = _c::sfMinimumOffer as isize,
    RippleEscrow = _c::sfRippleEscrow as isize,
    DeliveredAmount = _c::sfDeliveredAmount as isize,
    PublicKey = _c::sfPublicKey as isize,
    MessageKey = _c::sfMessageKey as isize,
    SigningPubKey = _c::sfSigningPubKey as isize,
    TxnSignature = _c::sfTxnSignature as isize,
    Signature = _c::sfSignature as isize,
    Domain = _c::sfDomain as isize,
    FundCode = _c::sfFundCode as isize,
    RemoveCode = _c::sfRemoveCode as isize,
    ExpireCode = _c::sfExpireCode as isize,
    CreateCode = _c::sfCreateCode as isize,
    MemoType = _c::sfMemoType as isize,
    MemoData = _c::sfMemoData as isize,
    MemoFormat = _c::sfMemoFormat as isize,
    Fulfillment = _c::sfFulfillment as isize,
    Condition = _c::sfCondition as isize,
    MasterSignature = _c::sfMasterSignature as isize,
    UNLModifyValidator = _c::sfUNLModifyValidator as isize,
    NegativeUNLToDisable = _c::sfNegativeUNLToDisable as isize,
    NegativeUNLToReEnable = _c::sfNegativeUNLToReEnable as isize,
    HookData = _c::sfHookData as isize,
    Account = _c::sfAccount as isize,
    Owner = _c::sfOwner as isize,
    Destination = _c::sfDestination as isize,
    Issuer = _c::sfIssuer as isize,
    Authorize = _c::sfAuthorize as isize,
    Unauthorize = _c::sfUnauthorize as isize,
    Target = _c::sfTarget as isize,
    RegularKey = _c::sfRegularKey as isize,
    Paths = _c::sfPaths as isize,
    Indexes = _c::sfIndexes as isize,
    Hashes = _c::sfHashes as isize,
    Amendments = _c::sfAmendments as isize,
    TransactionMetaData = _c::sfTransactionMetaData as isize,
    CreatedNode = _c::sfCreatedNode as isize,
    DeletedNode = _c::sfDeletedNode as isize,
    ModifiedNode = _c::sfModifiedNode as isize,
    PreviousFields = _c::sfPreviousFields as isize,
    FinalFields = _c::sfFinalFields as isize,
    NewFields = _c::sfNewFields as isize,
    TemplateEntry = _c::sfTemplateEntry as isize,
    Memo = _c::sfMemo as isize,
    SignerEntry = _c::sfSignerEntry as isize,
    EmitDetails = _c::sfEmitDetails as isize,
    Signer = _c::sfSigner as isize,
    Majority = _c::sfMajority as isize,
    NegativeUNLEntry = _c::sfNegativeUNLEntry as isize,
    SigningAccounts = _c::sfSigningAccounts as isize,
    Signers = _c::sfSigners as isize,
    SignerEntries = _c::sfSignerEntries as isize,
    Template = _c::sfTemplate as isize,
    Necessary = _c::sfNecessary as isize,
    Sufficient = _c::sfSufficient as isize,
    AffectedNodes = _c::sfAffectedNodes as isize,
    Memos = _c::sfMemos as isize,
    Majorities = _c::sfMajorities as isize,
    NegativeUNL = _c::sfNegativeUNL as isize,
}

/// Data representation
#[derive(Clone, Copy)]
pub enum DataRepr {
    /// As UTF-8
    AsUTF8 = 0,
    /// As hexadecimal
    AsHex = 1,
}


/// `Result` is a type that represents either success ([`Ok`]) or failure ([`Err`]).
//
/// This is simple version of Result type
/// to comply XRPL Hooks Webassembly restrictions
#[must_use]
pub enum Result<T> {
    /// Contains the success value
    Ok(T),
    /// Contains the error value
    Err(i64),
}

pub use self::Result::*;

#[must_use]
impl<T> Result<T> {
    /// Returns the contained [`Ok`] value, consuming the `self` value.
    ///
    /// # Rollbacks
    ///
    /// Rollbacks if the value is an [`Err`], with a rollback message and error code.
    #[inline(always)]
    pub fn expect(self, msg: &[u8]) -> T {
        match self {
            Err(e) => rollback(msg, e),
            Ok(val) => val,
        }
    }

    /// Returns the contained [`Ok`] value, consuming the `self` value.
    ///
    /// Because this function may rollback, its use is generally discouraged.
    /// Instead, prefer to use pattern matching and handle the [`Err`]
    /// case explicitly.
    ///
    /// # Rollbacks
    ///
    /// Rollbacks if the value is an [`Err`], with a "error" and error code provided by the
    /// [`Err`]'s value.
    #[inline(always)]
    pub fn unwrap(self) -> T {
        match self {
            Err(e) => rollback(b"error", e),
            Ok(val) => val,
        }
    }

    /// Returns the contained [`Ok`] value, consuming the `self` value,
    /// without checking that the value is not an [`Err`].
    ///
    /// # Safety
    ///
    /// Calling this method on an [`Err`] is *[undefined behavior]*.
    ///
    /// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    #[inline(always)]
    pub unsafe fn unwrap_unchecked(self) -> T {
        match self {
            Ok(val) => val,
            // SAFETY: the safety contract must be upheld by the caller.
            Err(_) => core::hint::unreachable_unchecked(),
        }
    }

    /// Returns `true` if the result is [`Ok`].
    #[must_use]
    #[inline(always)]
    pub const fn is_ok(&self) -> bool {
        matches!(*self, Ok(_))
    }

    /// Returns `true` if the result is [`Err`].
    #[must_use]
    #[inline(always)]
    pub const fn is_err(&self) -> bool {
        !self.is_ok()
    }
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
