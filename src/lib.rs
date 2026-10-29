//! C ABI wrapper around Mollusk. Public surface is `include/mollusk.h`.
//!
//! ## ABI conventions
//!
//! - All handles are returned as opaque `*mut T`. They must be freed with the
//!   matching `*_free` function. Passing null to a `*_free` fn is allowed and
//!   is a no-op.
//! - Pubkeys are passed as 32-byte buffers (no length param).
//! - Status returns: `0` = ok, non-zero = error. On error the thread-local
//!   error string is set and can be read with [`mollusk_last_error_copy`].
//!   Specific non-zero codes are implementation details, not a stable contract.
//! - Rust panics are caught at every FFI boundary and converted to a non-zero
//!   status (or null) plus a descriptive error message. They are never unwound
//!   across the C ABI.
//!
//! ## Other notes
//!
//! - Handles aren't thread-safe.
//! - Callers are responsible for ensuring safety given the bounds of the API.
//!   If there's any ambiguity here, check the safety comment in this file for more info.

#![deny(clippy::all)]
#![warn(unsafe_op_in_unsafe_fn)]

use {
    bincode::serialize,
    mollusk_svm::{
        program::{
            create_keyed_account_for_builtin_program, create_program_account_loader_v1,
            create_program_account_loader_v2, create_program_account_loader_v3, loader_keys,
        },
        result::types::{
            InstructionResult, ProgramResult, TransactionProgramResult, TransactionResult,
        },
        Mollusk, MolluskContext,
    },
    solana_account::Account,
    solana_instruction::{AccountMeta, Instruction},
    solana_instruction_error::InstructionError,
    solana_keypair::Keypair,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_svm_log_collector::LogCollector,
    solana_transaction_error::TransactionError,
    std::{
        cell::RefCell,
        collections::HashMap,
        panic::{catch_unwind, AssertUnwindSafe},
        ptr, slice,
        str::from_utf8,
    },
};

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

fn clear_error() {
    LAST_ERROR.with(|e| e.borrow_mut().clear());
}

/// Mollusk reports misuse (a missing account, a bad program) by panicking.
/// [`guard`] turns those into error returns, so the default hook's stderr
/// output is just noise; keep it only when RUST_BACKTRACE asks for detail.
fn quiet_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RUST_BACKTRACE").is_none() {
            std::panic::set_hook(Box::new(|_| {}));
        }
    });
}

/// Guard every extern fn body with this to prevent unwinding across the FFI
/// boundary. Returns `on_panic` if the closure panics, after setting the
/// thread-local error string.
fn guard<T>(on_panic: T, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "panic across FFI".to_string()
            };
            set_error(format!("panic: {msg}"));
            on_panic
        }
    }
}

/// Safely build a slice from an FFI `(ptr, len)` pair that may carry a null
/// pointer when `len == 0`.
///
/// # Safety
///
/// If `len > 0`, `ptr` must be aligned for `T`, point to `len` initialized
/// elements, and those elements must not be mutated for the returned lifetime.
unsafe fn slice_from_c<'a, T>(ptr: *const T, len: usize, label: &str) -> Option<&'a [T]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        set_error(format!("null {label} pointer"));
        None
    } else {
        // SAFETY: ptr is non-null and caller guarantees the rest of the
        // from_raw_parts contract (see this function's `# Safety`).
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

/// Copies bytes into `buf` subject to probe-then-copy semantics: always
/// returns the full byte length, copying `min(bytes.len(), buf_len)` when
/// `buf` is non-null and `buf_len > 0`.
///
/// # Safety
///
/// If `buf_len > 0` and `buf` is non-null, `buf` must be valid for writes of
/// at least `buf_len` bytes.
unsafe fn copy_probe(bytes: &[u8], buf: *mut u8, buf_len: usize) -> usize {
    if buf_len > 0 && !buf.is_null() && !bytes.is_empty() {
        let copy_len = bytes.len().min(buf_len);
        // SAFETY: caller guarantees `buf` is writable for `buf_len` bytes;
        // we copy at most `buf_len` of `bytes`.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len) };
    }
    bytes.len()
}

/// # Safety
///
/// `p` must be either null or a pointer to at least 32 readable bytes.
unsafe fn pubkey_from_ptr(p: *const u8) -> Option<Pubkey> {
    if p.is_null() {
        set_error("null pubkey pointer");
        return None;
    }
    // SAFETY: non-null and 32 readable bytes per caller's contract.
    let bytes = unsafe { slice::from_raw_parts(p, 32) };
    Some(Pubkey::try_from(bytes).expect("32-byte slice always fits Pubkey"))
}

/// # Safety
///
/// `out` must be null or valid for 32 writable bytes.
unsafe fn write_pubkey(key: &Pubkey, out: *mut u8) {
    if !out.is_null() {
        // SAFETY: non-null, 32 writable bytes per caller's contract.
        unsafe { ptr::copy_nonoverlapping(key.as_ref().as_ptr(), out, 32) };
    }
}

/// Copies the last error string into `buf` (up to `buf_len` bytes, no NUL).
/// Returns the *full* length of the error. `buf` may be null if `buf_len` is 0.
///
/// # Safety
///
/// If `buf_len > 0` and `buf` is non-null, `buf` must be valid for writes of
/// `buf_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_last_error_copy(buf: *mut u8, buf_len: usize) -> usize {
    guard(0, || {
        LAST_ERROR.with(|e| {
            let err = e.borrow();
            // SAFETY: forwarded precondition on (buf, buf_len).
            unsafe { copy_probe(err.as_bytes(), buf, buf_len) }
        })
    })
}

/// Static NUL-terminated mollusk-cxx version. Do not free.
#[no_mangle]
pub extern "C" fn mollusk_version() -> *const u8 {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr()
}

/// One account reference in a [`MolluskInstruction`].
#[repr(C)]
pub struct MolluskAccountMeta {
    pub pubkey: *const u8,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// An instruction described with plain C data. Pointers are borrowed for
/// the duration of the call only.
#[repr(C)]
pub struct MolluskInstruction {
    pub program_id: *const u8,
    pub accounts: *const MolluskAccountMeta,
    pub accounts_len: usize,
    pub data: *const u8,
    pub data_len: usize,
}

/// An account and its address, as plain C data. Pointers are borrowed for
/// the duration of the call only.
#[repr(C)]
pub struct MolluskKeyedAccount {
    pub pubkey: *const u8,
    pub lamports: u64,
    pub data: *const u8,
    pub data_len: usize,
    pub owner: *const u8,
    pub executable: bool,
    pub rent_epoch: u64,
}

/// # Safety
///
/// `raw` must satisfy the [`MolluskInstruction`] contract.
unsafe fn instruction_from_c(raw: &MolluskInstruction) -> Option<Instruction> {
    // SAFETY: forwarded caller contract.
    let program_id = unsafe { pubkey_from_ptr(raw.program_id) }?;
    // SAFETY: forwarded caller contract.
    let metas = unsafe { slice_from_c(raw.accounts, raw.accounts_len, "accounts") }?;
    // SAFETY: forwarded caller contract.
    let data = unsafe { slice_from_c(raw.data, raw.data_len, "data") }?;
    let mut accounts = Vec::with_capacity(metas.len());
    for m in metas {
        // SAFETY: forwarded caller contract.
        let key = unsafe { pubkey_from_ptr(m.pubkey) }?;
        accounts.push(if m.is_writable {
            AccountMeta::new(key, m.is_signer)
        } else {
            AccountMeta::new_readonly(key, m.is_signer)
        });
    }
    Some(Instruction {
        program_id,
        accounts,
        data: data.to_vec(),
    })
}

/// # Safety
///
/// `(ixs, len)` must be a valid array of [`MolluskInstruction`].
unsafe fn instructions_from_c(ixs: *const MolluskInstruction, len: usize) -> Option<Vec<Instruction>> {
    // SAFETY: forwarded caller contract.
    let raw = unsafe { slice_from_c(ixs, len, "instructions") }?;
    if raw.is_empty() {
        set_error("at least one instruction is required");
        return None;
    }
    // SAFETY: forwarded caller contract.
    raw.iter().map(|r| unsafe { instruction_from_c(r) }).collect()
}

/// # Safety
///
/// `raw` must satisfy the [`MolluskKeyedAccount`] contract.
unsafe fn keyed_account_from_c(raw: &MolluskKeyedAccount) -> Option<(Pubkey, Account)> {
    // SAFETY: forwarded caller contract.
    let key = unsafe { pubkey_from_ptr(raw.pubkey) }?;
    // SAFETY: forwarded caller contract.
    let owner = unsafe { pubkey_from_ptr(raw.owner) }?;
    // SAFETY: forwarded caller contract.
    let data = unsafe { slice_from_c(raw.data, raw.data_len, "account data") }?;
    Some((
        key,
        Account {
            lamports: raw.lamports,
            data: data.to_vec(),
            owner,
            executable: raw.executable,
            rent_epoch: raw.rent_epoch,
        },
    ))
}

/// # Safety
///
/// `(accounts, len)` must be a valid array of [`MolluskKeyedAccount`].
unsafe fn keyed_accounts_from_c(
    accounts: *const MolluskKeyedAccount,
    len: usize,
) -> Option<Vec<(Pubkey, Account)>> {
    // SAFETY: forwarded caller contract.
    let raw = unsafe { slice_from_c(accounts, len, "accounts") }?;
    // SAFETY: forwarded caller contract.
    raw.iter().map(|r| unsafe { keyed_account_from_c(r) }).collect()
}

/// Same layout as `Mollusk`, so a context's inner harness can be handed out
/// as a borrowed `MolluskHandle`.
#[repr(transparent)]
pub struct MolluskHandle {
    inner: Mollusk,
}

/// # Safety
///
/// `h` must be either null or a valid pointer to a `MolluskHandle`.
unsafe fn handle_ref<'a>(h: *const MolluskHandle) -> Option<&'a MolluskHandle> {
    if h.is_null() {
        set_error("null handle");
        None
    } else {
        // SAFETY: non-null and a valid pointee per caller's contract.
        Some(unsafe { &*h })
    }
}

/// # Safety
///
/// `h` must be either null or a valid pointer to a `MolluskHandle` with no
/// other live references.
unsafe fn handle_mut<'a>(h: *mut MolluskHandle) -> Option<&'a mut MolluskHandle> {
    if h.is_null() {
        set_error("null handle");
        None
    } else {
        // SAFETY: non-null and a valid, exclusively-owned pointee per caller.
        Some(unsafe { &mut *h })
    }
}

/// Create a Mollusk with the default builtins (System, BPF loaders) and no
/// programs. Returns null on panic.
#[no_mangle]
pub extern "C" fn mollusk_new() -> *mut MolluskHandle {
    quiet_panics();
    guard(ptr::null_mut(), || {
        clear_error();
        let inner = Mollusk::default();
        // Mollusk installs a global logger echoing every program log at
        // DEBUG; results carry the logs, so keep stderr to errors unless
        // RUST_LOG asks for more.
        solana_logger::setup_with_default("error");
        Box::into_raw(Box::new(MolluskHandle { inner }))
    })
}

/// Free a handle. Null is a no-op. Never pass the borrowed handle returned by
/// [`mollusk_context_mollusk`].
///
/// # Safety
///
/// `handle` must be null or a pointer from [`mollusk_new`], not yet freed or
/// passed to [`mollusk_context_new`].
#[no_mangle]
pub unsafe extern "C" fn mollusk_free(handle: *mut MolluskHandle) {
    if handle.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: non-null; the pointer came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    });
}

/// Add a program from ELF bytes. `loader_id` may be null for the upgradeable
/// loader (Mollusk's default).
///
/// # Safety
///
/// `program_id` must point to 32 bytes; `loader_id` to 32 bytes or be null;
/// `(elf, elf_len)` must be readable.
#[no_mangle]
pub unsafe extern "C" fn mollusk_add_program(
    handle: *mut MolluskHandle,
    program_id: *const u8,
    loader_id: *const u8,
    elf: *const u8,
    elf_len: usize,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return 1;
        };
        // SAFETY: forwarded caller contract.
        let Some(id) = (unsafe { pubkey_from_ptr(program_id) }) else {
            return 2;
        };
        let loader = if loader_id.is_null() {
            loader_keys::LOADER_V3
        } else {
            // SAFETY: non-null, 32 bytes per caller's contract.
            unsafe { pubkey_from_ptr(loader_id) }.expect("checked non-null")
        };
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { slice_from_c(elf, elf_len, "elf") }) else {
            return 3;
        };
        if bytes.is_empty() {
            set_error("empty elf");
            return 3;
        }
        h.inner.add_program_with_loader_and_elf(&id, &loader, bytes);
        0
    })
}

/// Add a program from a `.so` file on disk under the upgradeable loader.
/// `path` is UTF-8 and not NUL-terminated.
///
/// # Safety
///
/// `program_id` must point to 32 bytes; `(path, path_len)` must be readable.
#[no_mangle]
pub unsafe extern "C" fn mollusk_add_program_from_file(
    handle: *mut MolluskHandle,
    program_id: *const u8,
    path: *const u8,
    path_len: usize,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return 1;
        };
        // SAFETY: forwarded caller contract.
        let Some(id) = (unsafe { pubkey_from_ptr(program_id) }) else {
            return 2;
        };
        // SAFETY: forwarded caller contract.
        let Some(raw) = (unsafe { slice_from_c(path, path_len, "path") }) else {
            return 3;
        };
        let Ok(path) = from_utf8(raw) else {
            set_error("path is not UTF-8");
            return 3;
        };
        let elf = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                set_error(format!("{path}: {e}"));
                return 4;
            }
        };
        h.inner
            .add_program_with_loader_and_elf(&id, &loader_keys::LOADER_V3, &elf);
        0
    })
}

/// Add SPL Token, Token-2022 and Associated Token Account, as bundled with
/// mollusk-svm-programs-token.
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_add_token_programs(handle: *mut MolluskHandle) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return 1;
        };
        mollusk_svm_programs_token::token::add_program(&mut h.inner);
        mollusk_svm_programs_token::token2022::add_program(&mut h.inner);
        mollusk_svm_programs_token::associated_token::add_program(&mut h.inner);
        0
    })
}

/// The account for a program or builtin this Mollusk knows, as Mollusk
/// itself stubs it in (for the stateless calls, which need every account
/// other than the top-level program passed in). Null if it isn't one.
///
/// # Safety
///
/// See module-level safety model. `program_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_program_account(
    handle: *const MolluskHandle,
    program_id: *const u8,
) -> *mut MolluskAccount {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_ref(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let Some(id) = (unsafe { pubkey_from_ptr(program_id) }) else {
            return ptr::null_mut();
        };
        let Some(entry) = h.inner.program_cache.load_program(&id) else {
            set_error(format!("{id} is not a program in this Mollusk"));
            return ptr::null_mut();
        };
        // mirrors ProgramCache::maybe_create_program_account
        let account = match Pubkey::from(entry.account_owner) {
            o if o == loader_keys::NATIVE_LOADER => {
                create_keyed_account_for_builtin_program(&id, "I'm a stub!").1
            }
            o if o == loader_keys::LOADER_V1 => create_program_account_loader_v1(&[]),
            o if o == loader_keys::LOADER_V2 => create_program_account_loader_v2(&[]),
            _ => create_program_account_loader_v3(&id),
        };
        account_box(account)
    })
}

/// Move the sysvars (Clock, SlotHashes, ...) to `slot`.
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_warp_to_slot(handle: *mut MolluskHandle, slot: u64) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return 1;
        };
        h.inner.warp_to_slot(slot);
        0
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_set_compute_unit_limit(
    handle: *mut MolluskHandle,
    limit: u64,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return 1;
        };
        h.inner.compute_budget.compute_unit_limit = limit;
        0
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_get_compute_unit_limit(handle: *const MolluskHandle) -> u64 {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { handle_ref(handle) }.map_or(0, |h| h.inner.compute_budget.compute_unit_limit)
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_minimum_balance_for_rent_exemption(
    handle: *const MolluskHandle,
    data_len: usize,
) -> u64 {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { handle_ref(handle) }.map_or(0, |h| h.inner.sysvars.rent.minimum_balance(data_len))
    })
}

#[repr(C)]
pub struct MolluskClock {
    pub slot: u64,
    pub epoch_start_timestamp: i64,
    pub epoch: u64,
    pub leader_schedule_epoch: u64,
    pub unix_timestamp: i64,
}

/// # Safety
///
/// See module-level safety model. `out` must be null or valid for writes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_get_clock(
    handle: *const MolluskHandle,
    out: *mut MolluskClock,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_ref(handle) }) else {
            return 1;
        };
        if out.is_null() {
            set_error("null clock out pointer");
            return 2;
        }
        let c = &h.inner.sysvars.clock;
        let value = MolluskClock {
            slot: c.slot,
            epoch_start_timestamp: c.epoch_start_timestamp,
            epoch: c.epoch,
            leader_schedule_epoch: c.leader_schedule_epoch,
            unix_timestamp: c.unix_timestamp,
        };
        // SAFETY: non-null and valid for writes per caller's contract.
        unsafe { ptr::write_unaligned(out, value) };
        0
    })
}

/// Replace the Clock sysvar. Other sysvars are left alone (use
/// [`mollusk_warp_to_slot`] to move them together).
///
/// # Safety
///
/// See module-level safety model. `clock` must be null or valid for reads.
#[no_mangle]
pub unsafe extern "C" fn mollusk_set_clock(
    handle: *mut MolluskHandle,
    clock: *const MolluskClock,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return 1;
        };
        if clock.is_null() {
            set_error("null clock pointer");
            return 2;
        }
        // SAFETY: non-null and valid for reads per caller's contract.
        let src = unsafe { ptr::read_unaligned(clock) };
        h.inner.sysvars.clock = solana_clock::Clock {
            slot: src.slot,
            epoch_start_timestamp: src.epoch_start_timestamp,
            epoch: src.epoch,
            leader_schedule_epoch: src.leader_schedule_epoch,
            unix_timestamp: src.unix_timestamp,
        };
        0
    })
}

pub const MOLLUSK_ERR_NONE: i32 = 0;
pub const MOLLUSK_ERR_INSTRUCTION: i32 = 1;
pub const MOLLUSK_ERR_TRANSACTION: i32 = 2;

/// Same layout as `LiteSvmTxError` in litesvm-cxx.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MolluskError {
    pub kind: i32,
    pub code: u32,
    pub instruction_index: u8,
    pub program_error: u64,
}

const NO_ERROR: MolluskError = MolluskError {
    kind: MOLLUSK_ERR_NONE,
    code: 0,
    instruction_index: 0,
    program_error: 0,
};

/// bincode encodes an enum as a u32 LE variant index, then its fields.
fn variant_index<T: serde::Serialize>(v: &T) -> u32 {
    serialize(v)
        .ok()
        .and_then(|b| b.get(..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())))
        .unwrap_or(0)
}

fn instruction_error(index: usize, err: &InstructionError) -> MolluskError {
    MolluskError {
        kind: MOLLUSK_ERR_INSTRUCTION,
        code: variant_index(err),
        instruction_index: u8::try_from(index).unwrap_or(u8::MAX),
        program_error: ProgramError::try_from(err.clone())
            .map(u64::from)
            .unwrap_or(0),
    }
}

/// The outcome of one `process_*` call, normalized across Mollusk's
/// `InstructionResult` and `TransactionResult`.
pub struct MolluskResult {
    ok: bool,
    compute_units: u64,
    execution_time: u64,
    error: MolluskError,
    error_text: String,
    return_data: Vec<u8>,
    accounts: Vec<(Pubkey, Account)>,
    logs: Vec<String>,
}

impl MolluskResult {
    fn from_instruction(r: InstructionResult, logs: Vec<String>) -> Self {
        // raw_result is the execution error; program_result can also carry
        // the post-execution rent check, which raw_result doesn't see.
        let err = match (&r.raw_result, &r.program_result) {
            (_, ProgramResult::Success) => None,
            (Err(e), _) => Some(e.clone()),
            (Ok(()), ProgramResult::UnknownError(e)) => Some(e.clone()),
            (Ok(()), ProgramResult::Failure(_)) => Some(InstructionError::AccountNotRentExempt),
        };
        Self {
            ok: err.is_none(),
            compute_units: r.compute_units_consumed,
            execution_time: r.execution_time,
            error: err.as_ref().map_or(NO_ERROR, |e| instruction_error(0, e)),
            error_text: err.map(|e| format!("{e:?}")).unwrap_or_default(),
            return_data: r.return_data,
            accounts: r.resulting_accounts,
            logs,
        }
    }

    fn from_transaction(r: TransactionResult, logs: Vec<String>) -> Self {
        let tx_error = |e: &TransactionError| MolluskError {
            kind: MOLLUSK_ERR_TRANSACTION,
            code: variant_index(e),
            ..NO_ERROR
        };
        let (error, error_text) = match &r.raw_result {
            _ if r.program_result.is_ok() => (NO_ERROR, String::new()),
            Err(TransactionError::InstructionError(i, e)) => {
                (instruction_error(usize::from(*i), e), format!("{e:?}"))
            }
            Err(e) => (tx_error(e), format!("{e:?}")),
            // raw_result passed; the post-execution rent check did not
            Ok(()) => match &r.program_result {
                TransactionProgramResult::TransactionError(e) => (tx_error(e), format!("{e:?}")),
                TransactionProgramResult::UnknownError(i, e) => {
                    (instruction_error(*i, e), format!("{e:?}"))
                }
                TransactionProgramResult::Failure(i, e) => (
                    MolluskError {
                        kind: MOLLUSK_ERR_INSTRUCTION,
                        instruction_index: u8::try_from(*i).unwrap_or(u8::MAX),
                        program_error: u64::from(e.clone()),
                        ..NO_ERROR
                    },
                    format!("{e:?}"),
                ),
                TransactionProgramResult::Success => (NO_ERROR, String::new()),
            },
        };
        Self {
            ok: error.kind == MOLLUSK_ERR_NONE,
            compute_units: r.compute_units_consumed,
            execution_time: r.execution_time,
            error,
            error_text,
            return_data: r.return_data,
            accounts: r.resulting_accounts,
            logs,
        }
    }
}

/// Run `f` with a fresh log collector installed, returning its logs too.
fn with_logs<T>(m: &mut Mollusk, f: impl FnOnce(&Mollusk) -> T) -> (T, Vec<String>) {
    let logger = LogCollector::new_ref();
    m.logger = Some(logger.clone());
    let out = f(m);
    m.logger = None;
    let logs = logger.borrow().get_recorded_content().to_vec();
    (out, logs)
}

fn boxed(r: MolluskResult) -> *mut MolluskResult {
    Box::into_raw(Box::new(r))
}

/// # Safety
///
/// `h` must be either null or a valid pointer to a `MolluskResult`.
unsafe fn result_ref<'a>(h: *const MolluskResult) -> Option<&'a MolluskResult> {
    if h.is_null() {
        set_error("null result handle");
        None
    } else {
        // SAFETY: non-null and a valid pointee per caller's contract.
        Some(unsafe { &*h })
    }
}

/// Free a result. Null is a no-op.
///
/// # Safety
///
/// `handle` must be null or a pointer from a `process_*` fn, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_free(handle: *mut MolluskResult) {
    if handle.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: non-null; the pointer came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    });
}

/// 1 if it succeeded, 0 if not, -1 on a bad handle.
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_is_ok(handle: *const MolluskResult) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }.map_or(-1, |r| r.ok as i32)
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_compute_units(handle: *const MolluskResult) -> u64 {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }.map_or(0, |r| r.compute_units)
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_execution_time(handle: *const MolluskResult) -> u64 {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }.map_or(0, |r| r.execution_time)
    })
}

/// Fills `out` (kind = MOLLUSK_ERR_NONE on success). Returns 0, non-zero on
/// bad arguments.
///
/// # Safety
///
/// See module-level safety model. `out` must be null or valid for writes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_error_info(
    handle: *const MolluskResult,
    out: *mut MolluskError,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(r) = (unsafe { result_ref(handle) }) else {
            return 1;
        };
        if out.is_null() {
            set_error("null error-info out pointer");
            return 2;
        }
        // SAFETY: non-null and valid for writes per caller's contract.
        unsafe { ptr::write_unaligned(out, r.error) };
        0
    })
}

/// Debug text of the error (empty on success), probe-then-copy.
///
/// # Safety
///
/// See module-level safety model and [`copy_probe`].
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_error_copy(
    handle: *const MolluskResult,
    buf: *mut u8,
    buf_len: usize,
) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }
            // SAFETY: forwarded caller contract.
            .map_or(0, |r| unsafe { copy_probe(r.error_text.as_bytes(), buf, buf_len) })
    })
}

/// Return data of the last instruction, probe-then-copy.
///
/// # Safety
///
/// See module-level safety model and [`copy_probe`].
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_return_data_copy(
    handle: *const MolluskResult,
    buf: *mut u8,
    buf_len: usize,
) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }
            // SAFETY: forwarded caller contract.
            .map_or(0, |r| unsafe { copy_probe(&r.return_data, buf, buf_len) })
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_logs_count(handle: *const MolluskResult) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }.map_or(0, |r| r.logs.len())
    })
}

/// Log line `index`, probe-then-copy (0 when out of range).
///
/// # Safety
///
/// See module-level safety model and [`copy_probe`].
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_log_copy(
    handle: *const MolluskResult,
    index: usize,
    buf: *mut u8,
    buf_len: usize,
) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(r) = (unsafe { result_ref(handle) }) else {
            return 0;
        };
        // SAFETY: forwarded caller contract.
        r.logs
            .get(index)
            .map_or(0, |l| unsafe { copy_probe(l.as_bytes(), buf, buf_len) })
    })
}

/// Number of resulting accounts (every account the instruction(s) touched).
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_accounts_count(handle: *const MolluskResult) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { result_ref(handle) }.map_or(0, |r| r.accounts.len())
    })
}

/// Resulting account `index` as a new account handle; writes its address to
/// `pubkey_out` (may be null). Null when out of range.
///
/// # Safety
///
/// See module-level safety model. `pubkey_out` must be null or 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_account_at(
    handle: *const MolluskResult,
    index: usize,
    pubkey_out: *mut u8,
) -> *mut MolluskAccount {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(r) = (unsafe { result_ref(handle) }) else {
            return ptr::null_mut();
        };
        let Some((key, acct)) = r.accounts.get(index) else {
            set_error("account index out of range");
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        unsafe { write_pubkey(key, pubkey_out) };
        account_box(acct.clone())
    })
}

/// The resulting account at `pubkey`, or null if the result has none.
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_result_get_account(
    handle: *const MolluskResult,
    pubkey: *const u8,
) -> *mut MolluskAccount {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(r) = (unsafe { result_ref(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let Some(key) = (unsafe { pubkey_from_ptr(pubkey) }) else {
            return ptr::null_mut();
        };
        r.accounts
            .iter()
            .find(|(k, _)| *k == key)
            .map_or(ptr::null_mut(), |(_, a)| account_box(a.clone()))
    })
}

/// Process one instruction against `accounts`. The result holds the resulting
/// accounts; nothing is stored. Null on bad arguments.
///
/// # Safety
///
/// See module-level safety model and the C struct contracts.
#[no_mangle]
pub unsafe extern "C" fn mollusk_process_instruction(
    handle: *mut MolluskHandle,
    ix: *const MolluskInstruction,
    accounts: *const MolluskKeyedAccount,
    accounts_len: usize,
) -> *mut MolluskResult {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let (Some(ixs), Some(accts)) = (unsafe {
            (
                instructions_from_c(ix, 1),
                keyed_accounts_from_c(accounts, accounts_len),
            )
        }) else {
            return ptr::null_mut();
        };
        let (r, logs) = with_logs(&mut h.inner, |m| m.process_instruction(&ixs[0], &accts));
        boxed(MolluskResult::from_instruction(r, logs))
    })
}

/// Process instructions one after another, each in its own transaction
/// context, feeding each one's resulting accounts to the next. Stops at the
/// first failure. Mollusk doesn't report which element failed, so
/// `instruction_index` is always 0 here.
///
/// # Safety
///
/// See module-level safety model and the C struct contracts.
#[no_mangle]
pub unsafe extern "C" fn mollusk_process_instruction_chain(
    handle: *mut MolluskHandle,
    ixs: *const MolluskInstruction,
    ixs_len: usize,
    accounts: *const MolluskKeyedAccount,
    accounts_len: usize,
) -> *mut MolluskResult {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let (Some(ixs), Some(accts)) = (unsafe {
            (
                instructions_from_c(ixs, ixs_len),
                keyed_accounts_from_c(accounts, accounts_len),
            )
        }) else {
            return ptr::null_mut();
        };
        let (r, logs) = with_logs(&mut h.inner, |m| m.process_instruction_chain(&ixs, &accts));
        boxed(MolluskResult::from_instruction(r, logs))
    })
}

/// Process instructions in one shared transaction context, atomically.
/// `payer` (may be null) is the message's fee payer; no fee is charged.
///
/// # Safety
///
/// See module-level safety model and the C struct contracts.
#[no_mangle]
pub unsafe extern "C" fn mollusk_process_transaction_instructions(
    handle: *mut MolluskHandle,
    ixs: *const MolluskInstruction,
    ixs_len: usize,
    accounts: *const MolluskKeyedAccount,
    accounts_len: usize,
    payer: *const u8,
) -> *mut MolluskResult {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(h) = (unsafe { handle_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let (Some(ixs), Some(accts)) = (unsafe {
            (
                instructions_from_c(ixs, ixs_len),
                keyed_accounts_from_c(accounts, accounts_len),
            )
        }) else {
            return ptr::null_mut();
        };
        let payer = if payer.is_null() {
            None
        } else {
            // SAFETY: non-null, 32 bytes per caller's contract.
            unsafe { pubkey_from_ptr(payer) }
        };
        let (r, logs) = with_logs(&mut h.inner, |m| {
            m.process_transaction_instructions(&ixs, &accts, payer.as_ref())
        });
        boxed(MolluskResult::from_transaction(r, logs))
    })
}

pub struct MolluskContextHandle {
    inner: MolluskContext<HashMap<Pubkey, Account>>,
}

/// # Safety
///
/// `h` must be either null or a valid pointer to a `MolluskContextHandle`.
unsafe fn context_mut<'a>(h: *mut MolluskContextHandle) -> Option<&'a mut MolluskContextHandle> {
    if h.is_null() {
        set_error("null context handle");
        None
    } else {
        // SAFETY: non-null and a valid, exclusively-owned pointee per caller.
        Some(unsafe { &mut *h })
    }
}

/// Wrap a Mollusk in a context with an empty account store. Takes ownership
/// of `handle` (it is freed, even on failure); configure the harness
/// afterwards through [`mollusk_context_mollusk`].
///
/// # Safety
///
/// `handle` must be a pointer from [`mollusk_new`], not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_new(handle: *mut MolluskHandle) -> *mut MolluskContextHandle {
    if handle.is_null() {
        set_error("null handle");
        return ptr::null_mut();
    }
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: non-null; the pointer came from `Box::into_raw`.
        let m = unsafe { Box::from_raw(handle) }.inner;
        Box::into_raw(Box::new(MolluskContextHandle {
            inner: m.with_context(HashMap::new()),
        }))
    })
}

/// Free a context and the Mollusk it owns. Null is a no-op.
///
/// # Safety
///
/// `handle` must be null or a pointer from [`mollusk_context_new`], not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_free(handle: *mut MolluskContextHandle) {
    if handle.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: non-null; the pointer came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    });
}

/// The context's Mollusk, borrowed: valid until the context is freed, usable
/// with every `mollusk_*` fn except [`mollusk_free`] and [`mollusk_context_new`].
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_mollusk(
    handle: *mut MolluskContextHandle,
) -> *mut MolluskHandle {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { context_mut(handle) }.map_or(ptr::null_mut(), |c| {
            // `MolluskHandle` is `repr(transparent)` over `Mollusk`.
            &mut c.inner.mollusk as *mut Mollusk as *mut MolluskHandle
        })
    })
}

/// Process one instruction, loading its accounts from the store and writing
/// them back if it succeeds.
///
/// # Safety
///
/// See module-level safety model and the C struct contracts.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_process_instruction(
    handle: *mut MolluskContextHandle,
    ix: *const MolluskInstruction,
) -> *mut MolluskResult {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(c) = (unsafe { context_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let Some(ixs) = (unsafe { instructions_from_c(ix, 1) }) else {
            return ptr::null_mut();
        };
        let (r, logs) = context_with_logs(&mut c.inner, |ctx| ctx.process_instruction(&ixs[0]));
        boxed(MolluskResult::from_instruction(r, logs))
    })
}

/// [`mollusk_process_instruction_chain`] against the store; accounts are
/// written back only if every instruction succeeds.
///
/// # Safety
///
/// See module-level safety model and the C struct contracts.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_process_instruction_chain(
    handle: *mut MolluskContextHandle,
    ixs: *const MolluskInstruction,
    ixs_len: usize,
) -> *mut MolluskResult {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(c) = (unsafe { context_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let Some(ixs) = (unsafe { instructions_from_c(ixs, ixs_len) }) else {
            return ptr::null_mut();
        };
        let (r, logs) = context_with_logs(&mut c.inner, |ctx| ctx.process_instruction_chain(&ixs));
        boxed(MolluskResult::from_instruction(r, logs))
    })
}

/// [`mollusk_process_transaction_instructions`] against the store.
///
/// # Safety
///
/// See module-level safety model and the C struct contracts.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_process_transaction_instructions(
    handle: *mut MolluskContextHandle,
    ixs: *const MolluskInstruction,
    ixs_len: usize,
    payer: *const u8,
) -> *mut MolluskResult {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(c) = (unsafe { context_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let Some(ixs) = (unsafe { instructions_from_c(ixs, ixs_len) }) else {
            return ptr::null_mut();
        };
        let payer = if payer.is_null() {
            None
        } else {
            // SAFETY: non-null, 32 bytes per caller's contract.
            unsafe { pubkey_from_ptr(payer) }
        };
        let (r, logs) = context_with_logs(&mut c.inner, |ctx| {
            ctx.process_transaction_instructions(&ixs, payer.as_ref())
        });
        boxed(MolluskResult::from_transaction(r, logs))
    })
}

fn context_with_logs<T>(
    ctx: &mut MolluskContext<HashMap<Pubkey, Account>>,
    f: impl FnOnce(&MolluskContext<HashMap<Pubkey, Account>>) -> T,
) -> (T, Vec<String>) {
    let logger = LogCollector::new_ref();
    ctx.mollusk.logger = Some(logger.clone());
    let out = f(ctx);
    ctx.mollusk.logger = None;
    let logs = logger.borrow().get_recorded_content().to_vec();
    (out, logs)
}

/// The stored account at `pubkey`, or null if the store has none.
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_get_account(
    handle: *mut MolluskContextHandle,
    pubkey: *const u8,
) -> *mut MolluskAccount {
    guard(ptr::null_mut(), || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(c) = (unsafe { context_mut(handle) }) else {
            return ptr::null_mut();
        };
        // SAFETY: forwarded caller contract.
        let Some(key) = (unsafe { pubkey_from_ptr(pubkey) }) else {
            return ptr::null_mut();
        };
        let store = c.inner.account_store.borrow();
        store
            .get(&key)
            .map_or(ptr::null_mut(), |a| account_box(a.clone()))
    })
}

/// Create or overwrite a stored account.
///
/// # Safety
///
/// See module-level safety model and [`MolluskKeyedAccount`].
#[no_mangle]
pub unsafe extern "C" fn mollusk_context_set_account(
    handle: *mut MolluskContextHandle,
    account: *const MolluskKeyedAccount,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(c) = (unsafe { context_mut(handle) }) else {
            return 1;
        };
        if account.is_null() {
            set_error("null account pointer");
            return 2;
        }
        // SAFETY: non-null; forwarded caller contract.
        let Some((key, acct)) = (unsafe { keyed_account_from_c(&*account) }) else {
            return 3;
        };
        c.inner.account_store.borrow_mut().insert(key, acct);
        0
    })
}

pub struct MolluskAccount {
    inner: Account,
}

fn account_box(a: Account) -> *mut MolluskAccount {
    Box::into_raw(Box::new(MolluskAccount { inner: a }))
}

/// # Safety
///
/// `h` must be either null or a valid pointer to a `MolluskAccount`.
unsafe fn account_ref<'a>(h: *const MolluskAccount) -> Option<&'a MolluskAccount> {
    if h.is_null() {
        set_error("null account handle");
        None
    } else {
        // SAFETY: non-null, valid pointee per caller's contract.
        Some(unsafe { &*h })
    }
}

/// Free an account handle. Null is a no-op.
///
/// # Safety
///
/// `handle` must be null or a pointer from a fn returning `MolluskAccount *`,
/// not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_free(handle: *mut MolluskAccount) {
    if handle.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: non-null and the pointer came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    });
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_lamports(handle: *const MolluskAccount) -> u64 {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { account_ref(handle) }.map_or(0, |a| a.inner.lamports)
    })
}

/// 1 if executable, 0 if not, -1 on a bad handle.
///
/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_executable(handle: *const MolluskAccount) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { account_ref(handle) }.map_or(-1, |a| a.inner.executable as i32)
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_rent_epoch(handle: *const MolluskAccount) -> u64 {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { account_ref(handle) }.map_or(0, |a| a.inner.rent_epoch)
    })
}

/// Writes the owner to `out32`.
///
/// # Safety
///
/// See module-level safety model. `out32` must be 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_owner(handle: *const MolluskAccount, out32: *mut u8) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(a) = (unsafe { account_ref(handle) }) else {
            return 1;
        };
        if out32.is_null() {
            set_error("null out pointer");
            return 2;
        }
        // SAFETY: non-null, 32 writable bytes.
        unsafe { write_pubkey(&a.inner.owner, out32) };
        0
    })
}

/// # Safety
///
/// See module-level safety model.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_data_len(handle: *const MolluskAccount) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { account_ref(handle) }.map_or(0, |a| a.inner.data.len())
    })
}

/// Account data, probe-then-copy.
///
/// # Safety
///
/// See module-level safety model and [`copy_probe`].
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_data_copy(
    handle: *const MolluskAccount,
    buf: *mut u8,
    buf_len: usize,
) -> usize {
    guard(0, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        unsafe { account_ref(handle) }
            // SAFETY: forwarded caller contract.
            .map_or(0, |a| unsafe { copy_probe(&a.inner.data, buf, buf_len) })
    })
}

/// Describe `handle` as a [`MolluskKeyedAccount`] at `pubkey`, to pass back
/// into a `process_*` call. `out`'s data and owner pointers borrow from
/// `handle` and stay valid until it is freed.
///
/// # Safety
///
/// See module-level safety model. `pubkey` must stay valid as long as `out`
/// is used; `out` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_account_keyed(
    handle: *const MolluskAccount,
    pubkey: *const u8,
    out: *mut MolluskKeyedAccount,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(a) = (unsafe { account_ref(handle) }) else {
            return 1;
        };
        if pubkey.is_null() || out.is_null() {
            set_error("null pubkey or out pointer");
            return 2;
        }
        let value = MolluskKeyedAccount {
            pubkey,
            lamports: a.inner.lamports,
            data: a.inner.data.as_ptr(),
            data_len: a.inner.data.len(),
            owner: a.inner.owner.as_ref().as_ptr(),
            executable: a.inner.executable,
            rent_epoch: a.inner.rent_epoch,
        };
        // SAFETY: non-null and valid for writes per caller's contract.
        unsafe { ptr::write_unaligned(out, value) };
        0
    })
}

/// Writes the ed25519 public key for a 32-byte secret seed to `out32`.
///
/// # Safety
///
/// `seed32` must point to 32 readable bytes, `out32` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_pubkey_from_seed(seed32: *const u8, out32: *mut u8) -> i32 {
    guard(-1, || {
        clear_error();
        if seed32.is_null() {
            set_error("null seed pointer");
            return 1;
        }
        if out32.is_null() {
            set_error("null out pointer");
            return 2;
        }
        // SAFETY: non-null, 32 readable bytes per caller's contract.
        let seed = unsafe { *(seed32 as *const [u8; 32]) };
        let pk = Keypair::new_from_array(seed).pubkey();
        // SAFETY: non-null, 32 writable bytes.
        unsafe { write_pubkey(&pk, out32) };
        0
    })
}

/// Derives the canonical PDA for `seeds` under `program_id`. Writes the
/// address to `out32` and the bump to `bump_out` (may be null).
///
/// # Safety
///
/// `seeds[i]` must point to `seed_lens[i]` readable bytes for each
/// `i < seeds_count`; `program_id` to 32 readable bytes; `out32` to 32
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mollusk_find_program_address(
    seeds: *const *const u8,
    seed_lens: *const usize,
    seeds_count: usize,
    program_id: *const u8,
    out32: *mut u8,
    bump_out: *mut u8,
) -> i32 {
    guard(-1, || {
        clear_error();
        // SAFETY: forwarded caller contract.
        let Some(pid) = (unsafe { pubkey_from_ptr(program_id) }) else {
            return 1;
        };
        if out32.is_null() {
            set_error("null out pointer");
            return 2;
        }
        // SAFETY: forwarded caller contract; helper tolerates (null, 0).
        let (Some(ptrs), Some(lens)) = (unsafe {
            (
                slice_from_c(seeds, seeds_count, "seeds"),
                slice_from_c(seed_lens, seeds_count, "seed lengths"),
            )
        }) else {
            return 3;
        };
        let mut parts: Vec<&[u8]> = Vec::with_capacity(seeds_count);
        for (&p, &n) in ptrs.iter().zip(lens) {
            // SAFETY: each seed is valid for `n` bytes per caller contract.
            let Some(s) = (unsafe { slice_from_c(p, n, "seed") }) else {
                return 3;
            };
            parts.push(s);
        }
        let Some((addr, bump)) = Pubkey::try_find_program_address(&parts, &pid) else {
            set_error("no viable bump for these seeds");
            return 4;
        };
        // SAFETY: `out32` non-null, room for 32 bytes.
        unsafe { write_pubkey(&addr, out32) };
        if !bump_out.is_null() {
            // SAFETY: non-null, valid for a 1-byte write.
            unsafe { ptr::write(bump_out, bump) };
        }
        0
    })
}
