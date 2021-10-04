use core::ops::Range;

use crate::api::*;

use crate::*;

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
    Emitted(&'a [u8])
}

//todo: think about enums #[repr(u32)] to safe mem::transmutes 
//      return codes into enums 

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

#[derive(Clone, Copy)]
pub enum DataRepr {
    AsUTF8 = 0,
    AsHex = 1,
}

#[inline(always)]
pub fn is_buffer_equal<const GUARD_ID: u32>(buf_1: &[u8], buf_2: &[u8]) -> bool {
    let buf1_len = buf_1.len();

    if buf1_len != buf_2.len() {
        return false;
    };

    // guarded loop
    let mut i = 0;
    while {
        _g(GUARD_ID, buf1_len as u32);
        i < buf1_len
    } {
        if buf_1[i] != buf_2[i] {
            return false;
        }
        i += 1;
    }

    true
}

#[inline(always)]
pub fn buffer_zeroize<const GUARD_ID: u32>(buf: &mut [u8]) {
    let buf_len = buf.len();
    // guarded loop
    let mut i = 0;
    while {
        _g(GUARD_ID, buf_len as _);
        i < buf_len
    } {
        buf[0] = 0;
        i += 1;
    }
}

#[inline(always)]
pub fn is_txn_outgoing<const GUARD_ID: u32>(
    hook_acc_id: &mut AccountId,
    otnx_acc_id: &mut AccountId,
) -> Result<bool> {
    match hook_account(hook_acc_id) {
        Err(e) => return Err(e),
        Ok(_) => {}
    }

    match otxn_field(otnx_acc_id, FieldId::Account) {
        Err(e) => return Err(e),
        Ok(_) => {}
    }

    Ok(is_buffer_equal::<GUARD_ID>(
        &hook_acc_id[..],
        &otnx_acc_id[..],
    ))
}

#[inline(always)]
pub fn is_txn_ingoing<const GUARD_ID: u32>(
    hook_acc_id: &mut AccountId,
    otnx_acc_id: &mut AccountId,
) -> Result<bool> {
    match is_txn_outgoing::<GUARD_ID>(hook_acc_id, otnx_acc_id) {
        Err(e) => Err(e),
        Ok(res) => Ok(!res),
    }
}

#[inline(always)]
pub const fn amount_to_drops(amount_buf: &Amount) -> Result<u64> {
    if (amount_buf[0] >> 7) == 1 {
        return Err(-2);
    }

    Ok((((amount_buf[0] as u64) & 0xb00111111) << 56)
        + ((amount_buf[1] as u64) << 48)
        + ((amount_buf[2] as u64) << 40)
        + ((amount_buf[3] as u64) << 32)
        + ((amount_buf[4] as u64) << 24)
        + ((amount_buf[5] as u64) << 16)
        + ((amount_buf[6] as u64) << 8)
        + (amount_buf[7] as u64))
}

#[inline(always)]
pub fn prepare_payment_simple(
    buf_out: &mut TxnPaymentSimple,
    drops_amount: u64,
    drops_fee: u64,
    to_address: &AccountId,
    dest_tag: u32,
    src_tag: u32,
) -> Result<()> {
    const TT_RANGE: Range<usize> = Range { start: 0, end: 3 };
    const FLAGS_RANGE: Range<usize> = Range { start: 3, end: 8 };
    const TAG_SRC_RANGE: Range<usize> = Range { start: 8, end: 13 };
    const SEQUENCE_RANGE: Range<usize> = Range { start: 13, end: 18 };
    const TAG_DST_RANGE: Range<usize> = Range { start: 18, end: 23 };
    const FLS_RANGE: Range<usize> = Range { start: 23, end: 29 };
    const LLS_RANGE: Range<usize> = Range { start: 29, end: 35 };
    const DROPS_RANGE: Range<usize> = Range { start: 35, end: 44 };
    const DROPS_FEE_RANGE: Range<usize> = Range { start: 44, end: 53 };
    const SIGNING_PUBKEY_RANGE: Range<usize> = Range { start: 53, end: 88 };
    const ACCOUNT_SRC_RANGE: Range<usize> = Range {
        start: 88,
        end: 110,
    };
    const ACCOUNT_DST_RANGE: Range<usize> = Range {
        start: 110,
        end: 132,
    };
    const ETXN_DETAILS_RANGE: Range<usize> = Range {
        start: 132,
        end: 237,
    };

    let mut acc: AccountId = uninit_buf!();
    match hook_account(&mut acc) {
        Err(e) => return Err(e),
        Ok(_) => {}
    }

    let cls = ledger_seq() as u32;

    encode_tt(&mut buf_out[TT_RANGE], TxnType::Payment);
    encode_flags(&mut buf_out[FLAGS_RANGE], TF_CANONICAL);
    encode_tag_src(&mut buf_out[TAG_SRC_RANGE], src_tag);
    encode_sequence(&mut buf_out[SEQUENCE_RANGE], 0);
    encode_tag_dst(&mut buf_out[TAG_DST_RANGE], dest_tag);
    encode_fls(&mut buf_out[FLS_RANGE], cls + 1);
    encode_lls(&mut buf_out[LLS_RANGE], cls + 5);
    encode_drops_amount(&mut buf_out[DROPS_RANGE], drops_amount);
    encode_drops_fee(&mut buf_out[DROPS_FEE_RANGE], drops_fee);
    encode_signing_pubkey_null(&mut buf_out[SIGNING_PUBKEY_RANGE]);
    encode_account_src(&mut buf_out[ACCOUNT_SRC_RANGE], &acc);
    encode_account_dst(&mut buf_out[ACCOUNT_DST_RANGE], to_address);
    match etxn_details(&mut buf_out[ETXN_DETAILS_RANGE]) {
        Err(e) => return Err(e),
        Ok(_) => {}
    }

    Ok(())
}

#[inline(always)]
fn encode_tt(buf_out: &mut [u8], tt: TxnType) {
    buf_out[0] = 0x12;
    buf_out[1] = ((tt as u16 >> 8) & 0xFF) as u8;
    buf_out[2] = ((tt as u16 >> 0) & 0xFF) as u8;
}

#[inline(always)]
fn encode_flags(buf_out: &mut [u8], flags: u32) {
    encode_u32_common(buf_out, flags, 0x2)
}

#[inline(always)]
fn encode_tag_src(buf_out: &mut [u8], tag: u32) {
    encode_u32_common(buf_out, tag, 0x3)
}

#[inline(always)]
fn encode_sequence(buf_out: &mut [u8], sequence: u32) {
    encode_u32_common(buf_out, sequence, 0x4)
}

#[inline(always)]
fn encode_tag_dst(buf_out: &mut [u8], tag: u32) {
    encode_u32_common(buf_out, tag, 0xE)
}

#[inline(always)]
fn encode_fls(buf_out: &mut [u8], fls: u32) {
    encode_u32_uncommon(buf_out, fls, 0x1A)
}

#[inline(always)]
fn encode_lls(buf_out: &mut [u8], lls: u32) {
    encode_u32_uncommon(buf_out, lls, 0x1B)
}

#[inline(always)]
fn encode_drops_amount(buf_out: &mut [u8], drops: u64) {
    encode_drops(buf_out, drops, AmountType::Amount)
}

#[inline(always)]
fn encode_drops_fee(buf_out: &mut [u8], drops: u64) {
    encode_drops(buf_out, drops, AmountType::Fee)
}

#[inline(always)]
fn encode_account_src(buf_out: &mut [u8], account_id: &Buffer<ACC_ID_LEN>) {
    encode_account(buf_out, account_id, AccountType::Account)
}

#[inline(always)]
fn encode_account_dst(buf_out: &mut [u8], account_id: &Buffer<ACC_ID_LEN>) {
    encode_account(buf_out, account_id, AccountType::Destination)
}

#[inline(always)]
fn encode_u32_common(buf_out: &mut [u8], i: u32, field: u8) {
    buf_out[0] = 0x20 + (field & 0x0F);
    buf_out[1] = ((i >> 24) & 0xFF) as u8;
    buf_out[2] = ((i >> 16) & 0xFF) as u8;
    buf_out[3] = ((i >> 8) & 0xFF) as u8;
    buf_out[4] = ((i >> 0) & 0xFF) as u8;
}

#[inline(always)]
fn encode_u32_uncommon(buf_out: &mut [u8], i: u32, field: u8) {
    buf_out[0] = 0x20;
    buf_out[1] = field;
    buf_out[2] = ((i >> 24) & 0xFF) as u8;
    buf_out[3] = ((i >> 16) & 0xFF) as u8;
    buf_out[4] = ((i >> 8) & 0xFF) as u8;
    buf_out[5] = ((i >> 0) & 0xFF) as u8;
}

#[inline(always)]
fn encode_drops(buf_out: &mut [u8], drops: u64, amount_type: AmountType) {
    buf_out[0] = 0x60 + (amount_type as u8 & 0x0F);
    buf_out[1] = (0b01000000 + ((drops >> 56) & 0b00111111)) as u8;
    buf_out[2] = ((drops >> 48) & 0xFF) as u8;
    buf_out[3] = ((drops >> 40) & 0xFF) as u8;
    buf_out[4] = ((drops >> 32) & 0xFF) as u8;
    buf_out[5] = ((drops >> 24) & 0xFF) as u8;
    buf_out[6] = ((drops >> 16) & 0xFF) as u8;
    buf_out[7] = ((drops >> 8) & 0xFF) as u8;
    buf_out[8] = ((drops >> 0) & 0xFF) as u8;
}

#[inline(always)]
fn encode_signing_pubkey_null(buf_out: &mut [u8]) {
    buf_out[0] = 0x73;
    buf_out[1] = 0x21;
    buf_out[2..35].clone_from_slice(&[0; 33]);
}

#[inline(always)]
fn encode_account(buf_out: &mut [u8], account_id: &AccountId, account_type: AccountType) {
    buf_out[0] = 0x80 + account_type as u8;
    buf_out[1] = 0x14;
    buf_out[2..22].clone_from_slice(&account_id[..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_c;

    const ACCOUNT_ID: AccountId = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];

    #[test]
    fn enc_account() {
        let mut encoded: [u8; _c::ENCODE_ACCOUNT_SIZE as usize] = uninit_buf!();

        encode_account(&mut encoded, &ACCOUNT_ID, AccountType::Account);

        assert_eq!(
            encoded,
            [0x81, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );
    }

    #[test]
    fn enc_signing_pubkey_null() {
        let mut key: [u8; _c::ENCODE_SIGNING_PUBKEY_NULL_SIZE as usize] = [255; 35];

        encode_signing_pubkey_null(&mut key);

        assert_eq!(
            key,
            [
                0x73, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        )
    }
}
