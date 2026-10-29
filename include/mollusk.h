/*
 * C ABI for Mollusk
 *
 * This header is hand-maintained and must stay in sync with src/lib.rs.
 * Rust panics are caught at the boundary and reported as errors.
 * Handles are not thread-safe; serialize access to each one.
 * All handles are opaque and must be freed with the matching *_free fn.
 * All pubkeys are 32 raw bytes.
 * Status returns: 0 = ok, non-zero = error; call mollusk_last_error_copy
 * to read a UTF-8 description of the last error on this thread.
 */

#ifndef MOLLUSK_H
#define MOLLUSK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MOLLUSK_CXX_VERSION      "0.1.0"
#define MOLLUSK_UPSTREAM_VERSION "0.16.4"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MolluskHandle MolluskHandle;
typedef struct MolluskContextHandle MolluskContextHandle;
typedef struct MolluskResult MolluskResult;
typedef struct MolluskAccount MolluskAccount;

/* Copy the last thread-local error into `buf`. Returns the full length of
 * the error string. If that exceeds `buf_len`, the buffer is truncated.
 * `buf` may be NULL when `buf_len` is 0 (probe for required size). */
size_t mollusk_last_error_copy(uint8_t *buf, size_t buf_len);

/* Static NUL-terminated mollusk-cxx version (MOLLUSK_CXX_VERSION of the
 * library actually linked). Do not free. */
const uint8_t *mollusk_version(void);

/* Pointers in these structs are borrowed for the duration of a call. */
typedef struct {
    const uint8_t *pubkey;
    bool is_signer;
    bool is_writable;
} MolluskAccountMeta;

typedef struct {
    const uint8_t *program_id;
    const MolluskAccountMeta *accounts;
    size_t accounts_len;
    const uint8_t *data;
    size_t data_len;
} MolluskInstruction;

typedef struct {
    const uint8_t *pubkey;
    uint64_t lamports;
    const uint8_t *data; /* may be NULL when data_len is 0 */
    size_t data_len;
    const uint8_t *owner;
    bool executable;
    uint64_t rent_epoch;
} MolluskKeyedAccount;

/* Default builtins (System, BPF loaders), no programs. NULL on panic. */
MolluskHandle *mollusk_new(void);
/* Never pass the borrowed handle from mollusk_context_mollusk. */
void mollusk_free(MolluskHandle *handle);

/* Add a program from ELF bytes. `loader_id` NULL = upgradeable loader. */
int32_t mollusk_add_program(MolluskHandle *handle,
                            const uint8_t *program_id,
                            const uint8_t *loader_id,
                            const uint8_t *elf,
                            size_t elf_len);
/* Same, from a .so on disk. `path` is UTF-8, not NUL-terminated. */
int32_t mollusk_add_program_from_file(MolluskHandle *handle,
                                      const uint8_t *program_id,
                                      const uint8_t *path,
                                      size_t path_len);
/* SPL Token, Token-2022 and Associated Token Account. */
int32_t mollusk_add_token_programs(MolluskHandle *handle);

/* The account Mollusk stubs in for a program or builtin it knows (free
 * with mollusk_account_free), or NULL. The stateless calls need it for
 * every program an instruction references other than its own, e.g. the
 * System program for a CPI; see mollusk_account_keyed. */
MolluskAccount *mollusk_program_account(const MolluskHandle *handle,
                                        const uint8_t *program_id);

/* Move Clock, SlotHashes and the other sysvars to `slot`. */
int32_t mollusk_warp_to_slot(MolluskHandle *handle, uint64_t slot);

int32_t mollusk_set_compute_unit_limit(MolluskHandle *handle, uint64_t limit);
uint64_t mollusk_get_compute_unit_limit(const MolluskHandle *handle);

uint64_t mollusk_minimum_balance_for_rent_exemption(
    const MolluskHandle *handle, size_t data_len);

typedef struct {
    uint64_t slot;
    int64_t epoch_start_timestamp;
    uint64_t epoch;
    uint64_t leader_schedule_epoch;
    int64_t unix_timestamp;
} MolluskClock;

int32_t mollusk_get_clock(const MolluskHandle *handle, MolluskClock *out);
/* Replaces only Clock; mollusk_warp_to_slot moves the sysvars together. */
int32_t mollusk_set_clock(MolluskHandle *handle, const MolluskClock *clock);

/* One instruction. */
MolluskResult *mollusk_process_instruction(MolluskHandle *handle,
                                           const MolluskInstruction *ix,
                                           const MolluskKeyedAccount *accounts,
                                           size_t accounts_len);

/* Several instructions, each in its own transaction context, each seeing
 * the previous one's resulting accounts. Stops at the first failure.
 * Mollusk doesn't say which one failed: instruction_index is always 0. */
MolluskResult *mollusk_process_instruction_chain(
    MolluskHandle *handle,
    const MolluskInstruction *ixs,
    size_t ixs_len,
    const MolluskKeyedAccount *accounts,
    size_t accounts_len);

/* Several instructions in one transaction context, atomically. `payer`
 * (may be NULL) heads the message as fee payer; no fee is charged. */
MolluskResult *mollusk_process_transaction_instructions(
    MolluskHandle *handle,
    const MolluskInstruction *ixs,
    size_t ixs_len,
    const MolluskKeyedAccount *accounts,
    size_t accounts_len,
    const uint8_t *payer);

/* Takes ownership of `handle` (freed even on failure). */
MolluskContextHandle *mollusk_context_new(MolluskHandle *handle);
void mollusk_context_free(MolluskContextHandle *handle);

/* The context's harness, borrowed until the context is freed. Configure
 * it with the mollusk_* fns above; don't free it or pass it to
 * mollusk_context_new. */
MolluskHandle *mollusk_context_mollusk(MolluskContextHandle *handle);

/* As above, but accounts come from the store, and are written back to it
 * only if everything succeeds. Missing accounts start out empty. */
MolluskResult *mollusk_context_process_instruction(
    MolluskContextHandle *handle, const MolluskInstruction *ix);
MolluskResult *mollusk_context_process_instruction_chain(
    MolluskContextHandle *handle,
    const MolluskInstruction *ixs,
    size_t ixs_len);
MolluskResult *mollusk_context_process_transaction_instructions(
    MolluskContextHandle *handle,
    const MolluskInstruction *ixs,
    size_t ixs_len,
    const uint8_t *payer);

/* A stored account (free with mollusk_account_free), or NULL if absent. */
MolluskAccount *mollusk_context_get_account(MolluskContextHandle *handle,
                                            const uint8_t *pubkey);
/* Create or overwrite a stored account. */
int32_t mollusk_context_set_account(MolluskContextHandle *handle,
                                    const MolluskKeyedAccount *account);

void mollusk_result_free(MolluskResult *handle);

/* 1 = succeeded, 0 = failed, -1 = bad handle. */
int32_t mollusk_result_is_ok(const MolluskResult *handle);
uint64_t mollusk_result_compute_units(const MolluskResult *handle);
uint64_t mollusk_result_execution_time(const MolluskResult *handle);

#define MOLLUSK_ERR_NONE        0
#define MOLLUSK_ERR_INSTRUCTION 1
#define MOLLUSK_ERR_TRANSACTION 2

/* InstructionError variant indices used most in tests. A program that runs
 * out of compute units fails with PROGRAM_FAILED_TO_COMPLETE. */
#define MOLLUSK_IX_ERR_CUSTOM                        25
#define MOLLUSK_IX_ERR_COMPUTATIONAL_BUDGET_EXCEEDED 37
#define MOLLUSK_IX_ERR_PROGRAM_FAILED_TO_COMPLETE    40

/* Same layout and meaning as litesvm-cxx's LiteSvmTxError. `code` is the
 * InstructionError (or TransactionError) variant index; `program_error`
 * is the program's u64 error, with Custom(0) as 1 << 32. */
typedef struct {
    int32_t kind;
    uint32_t code;
    uint8_t instruction_index;
    uint64_t program_error;
} MolluskError;

int32_t mollusk_result_error_info(const MolluskResult *handle,
                                  MolluskError *out);

/* Probe-then-copy accessors: each returns the full length and copies at
 * most `buf_len` bytes (no NUL). `buf` may be NULL when `buf_len` is 0. */
size_t mollusk_result_error_copy(const MolluskResult *handle,
                                 uint8_t *buf, size_t buf_len);
size_t mollusk_result_return_data_copy(const MolluskResult *handle,
                                       uint8_t *buf, size_t buf_len);
size_t mollusk_result_logs_count(const MolluskResult *handle);
size_t mollusk_result_log_copy(const MolluskResult *handle, size_t index,
                               uint8_t *buf, size_t buf_len);

/* Resulting accounts: every account the instructions referenced, after
 * execution (unchanged on failure). Each returned handle is new. */
size_t mollusk_result_accounts_count(const MolluskResult *handle);
MolluskAccount *mollusk_result_account_at(const MolluskResult *handle,
                                          size_t index,
                                          uint8_t *pubkey_out);
MolluskAccount *mollusk_result_get_account(const MolluskResult *handle,
                                           const uint8_t *pubkey);

void mollusk_account_free(MolluskAccount *handle);
uint64_t mollusk_account_lamports(const MolluskAccount *handle);
int32_t mollusk_account_executable(const MolluskAccount *handle);
uint64_t mollusk_account_rent_epoch(const MolluskAccount *handle);
int32_t mollusk_account_owner(const MolluskAccount *handle, uint8_t *out32);
size_t mollusk_account_data_len(const MolluskAccount *handle);
size_t mollusk_account_data_copy(const MolluskAccount *handle,
                                 uint8_t *buf, size_t buf_len);

/* Fill `out` to pass this account back in at `pubkey`. Its data and owner
 * pointers borrow from `handle` (valid until it is freed). */
int32_t mollusk_account_keyed(const MolluskAccount *handle,
                              const uint8_t *pubkey,
                              MolluskKeyedAccount *out);

/* Public key for a 32-byte ed25519 secret seed. */
int32_t mollusk_pubkey_from_seed(const uint8_t *seed32, uint8_t *out32);

/* Canonical program-derived address. `bump_out` may be NULL. */
int32_t mollusk_find_program_address(const uint8_t *const *seeds,
                                     const size_t *seed_lens,
                                     size_t seeds_count,
                                     const uint8_t *program_id,
                                     uint8_t *out32,
                                     uint8_t *bump_out);

#ifdef __cplusplus
}
#endif

#endif /* MOLLUSK_H */
