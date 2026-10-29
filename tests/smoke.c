/*
 * ensure the C ABI works with a simple Caravel program (in this case, the counter example)
 */
#include "mollusk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__,   \
                    #cond);                                                    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void die_last_error(const char *what) {
    char buf[512] = {0};
    mollusk_last_error_copy((uint8_t *)buf, sizeof buf - 1);
    fprintf(stderr, "%s: %s\n", what, buf);
    exit(1);
}

static uint8_t program_id[32], system_program[32], payer[32], counter[32];

static MolluskResult *run(MolluskContextHandle *ctx, uint8_t disc,
                          MolluskAccountMeta *metas, size_t n) {
    MolluskInstruction ix = {program_id, metas, n, &disc, 1};
    MolluskResult *r = mollusk_context_process_instruction(ctx, &ix);
    if (!r) die_last_error("context_process_instruction");
    return r;
}

static uint64_t read_count(MolluskAccount *a) {
    if (!a) return UINT64_MAX;
    uint8_t data[40] = {0};
    mollusk_account_data_copy(a, data, sizeof data);
    mollusk_account_free(a);
    uint64_t v;
    memcpy(&v, data, 8);
    return v;
}

static void expect_error(MolluskResult *r, uint32_t code, uint64_t program_error) {
    MolluskError err;
    CHECK(mollusk_result_is_ok(r) == 0);
    CHECK(mollusk_result_error_info(r, &err) == 0);
    CHECK(err.kind == MOLLUSK_ERR_INSTRUCTION);
    CHECK(err.code == code);
    CHECK(err.program_error == program_error);
    CHECK(mollusk_result_error_copy(r, NULL, 0) > 0);
    mollusk_result_free(r);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <counter.so>\n", argv[0]);
        return 2;
    }

    CHECK(strcmp((const char *)mollusk_version(), MOLLUSK_CXX_VERSION) == 0);

    MolluskHandle *m = mollusk_new();
    if (!m) die_last_error("mollusk_new");
    memset(program_id, 0xC0, sizeof program_id);
    if (mollusk_add_program_from_file(m, program_id, (const uint8_t *)argv[1],
                                      strlen(argv[1])))
        die_last_error("add_program_from_file");
    CHECK(mollusk_add_token_programs(m) == 0);

    uint8_t seeds[64];
    memset(seeds, 1, 32);
    memset(seeds + 32, 2, 32);
    CHECK(mollusk_pubkey_from_seed(seeds, payer) == 0);
    CHECK(mollusk_pubkey_from_seed(seeds + 32, counter) == 0);

    MolluskAccountMeta init[] = {
        {payer, true, true}, {counter, true, true}, {system_program, false, false}};
    MolluskAccountMeta inc[] = {{counter, false, true}, {payer, true, false}};
    uint8_t disc = 0;
    MolluskInstruction init_ix = {program_id, init, 3, &disc, 1};
    MolluskKeyedAccount accts[3] = {
        {payer, 10000000000ULL, NULL, 0, system_program, false, 0},
        {counter, 0, NULL, 0, system_program, false, 0},
    };

    /* stateless: every account but the top-level program is passed in,
     * including the System program the instruction CPIs to */
    MolluskResult *r = mollusk_process_instruction(m, &init_ix, accts, 2);
    CHECK(r == NULL); /* Mollusk panics on the missing account */
    CHECK(mollusk_last_error_copy(NULL, 0) > 0);
    MolluskAccount *sys = mollusk_program_account(m, system_program);
    CHECK(sys && mollusk_account_executable(sys) == 1);
    CHECK(mollusk_account_keyed(sys, system_program, &accts[2]) == 0);
    CHECK(mollusk_program_account(m, payer) == NULL);

    /* the result carries the accounts; nothing is kept */
    r = mollusk_process_instruction(m, &init_ix, accts, 3);
    if (!r) die_last_error("process_instruction");
    CHECK(mollusk_result_is_ok(r) == 1);
    CHECK(mollusk_result_compute_units(r) > 0);
    CHECK(mollusk_result_logs_count(r) > 0);
    char line[256] = {0};
    CHECK(mollusk_result_log_copy(r, 0, (uint8_t *)line, sizeof line - 1) > 0);
    CHECK(strstr(line, "invoke [1]") != NULL);
    MolluskError err;
    CHECK(mollusk_result_error_info(r, &err) == 0);
    CHECK(err.kind == MOLLUSK_ERR_NONE);
    CHECK(mollusk_result_accounts_count(r) == 3);
    uint8_t key[32], owner[32];
    MolluskAccount *a = mollusk_result_account_at(r, 1, key);
    CHECK(a && memcmp(key, counter, 32) == 0);
    CHECK(mollusk_account_owner(a, owner) == 0 && memcmp(owner, program_id, 32) == 0);
    CHECK(mollusk_account_data_len(a) >= 40);
    CHECK(read_count(a) == 0);
    mollusk_result_free(r);

    /* the same instruction, twice in one transaction: the second fails */
    MolluskInstruction twice[] = {init_ix, init_ix};
    r = mollusk_process_transaction_instructions(m, twice, 2, accts, 3, payer);
    CHECK(mollusk_result_is_ok(r) == 0);
    CHECK(mollusk_result_error_info(r, &err) == 0);
    CHECK(err.kind == MOLLUSK_ERR_INSTRUCTION && err.instruction_index == 1);
    mollusk_result_free(r);
    mollusk_account_free(sys);

    /* context: the store keeps what succeeded */
    MolluskContextHandle *ctx = mollusk_context_new(m);
    if (!ctx) die_last_error("context_new");
    m = mollusk_context_mollusk(ctx);
    CHECK(mollusk_context_set_account(ctx, &accts[0]) == 0);

    r = run(ctx, 0, init, 3);
    CHECK(mollusk_result_is_ok(r) == 1);
    mollusk_result_free(r);
    CHECK(read_count(mollusk_context_get_account(ctx, counter)) == 0);

    for (int i = 0; i < 2; i++) {
        r = run(ctx, 1, inc, 2);
        CHECK(mollusk_result_is_ok(r) == 1);
        mollusk_result_free(r);
    }
    r = run(ctx, 2, inc, 2);
    CHECK(mollusk_result_is_ok(r) == 1);
    mollusk_result_free(r);
    CHECK(read_count(mollusk_context_get_account(ctx, counter)) == 1);

    /* a chain persists only as a whole */
    uint8_t d_inc = 1, d_dec = 2;
    MolluskInstruction chain[] = {
        {program_id, inc, 2, &d_inc, 1}, {program_id, inc, 2, &d_dec, 1},
        {program_id, inc, 2, &d_dec, 1}, {program_id, inc, 2, &d_dec, 1}};
    r = mollusk_context_process_instruction_chain(ctx, chain, 4);
    CHECK(mollusk_result_is_ok(r) == 0);
    mollusk_result_free(r);
    CHECK(read_count(mollusk_context_get_account(ctx, counter)) == 1);

    /* decrement past zero: InvalidArgument (variant 1, ERROR_INVALID_ARGUMENT) */
    r = run(ctx, 2, inc, 2);
    CHECK(mollusk_result_is_ok(r) == 1);
    mollusk_result_free(r);
    expect_error(run(ctx, 2, inc, 2), 1, 2ULL << 32);

    /* Caravel rejects duplicate writable accounts with ERROR_CUSTOM(7) */
    MolluskAccountMeta dup[] = {{counter, false, true}, {counter, false, true}};
    expect_error(run(ctx, 1, dup, 2), MOLLUSK_IX_ERR_CUSTOM, 0x107);

    /* running out of CUs surfaces as ProgramFailedToComplete */
    CHECK(mollusk_set_compute_unit_limit(m, 10) == 0);
    CHECK(mollusk_get_compute_unit_limit(m) == 10);
    expect_error(run(ctx, 1, inc, 2), MOLLUSK_IX_ERR_PROGRAM_FAILED_TO_COMPLETE, 0);

    /* sysvars */
    MolluskClock clock;
    CHECK(mollusk_warp_to_slot(m, 1000) == 0);
    CHECK(mollusk_get_clock(m, &clock) == 0 && clock.slot == 1000);
    clock.unix_timestamp = 1234;
    CHECK(mollusk_set_clock(m, &clock) == 0);
    CHECK(mollusk_get_clock(m, &clock) == 0 && clock.unix_timestamp == 1234);
    CHECK(mollusk_minimum_balance_for_rent_exemption(m, 0) > 0);

    /* bad arguments come back as NULL plus an error message */
    MolluskInstruction bad = {NULL, NULL, 0, NULL, 0};
    CHECK(mollusk_context_process_instruction(ctx, &bad) == NULL);
    CHECK(mollusk_last_error_copy(NULL, 0) > 0);

    /* PDA: deterministic */
    const uint8_t *pda_seeds[] = {(const uint8_t *)"counter", payer};
    size_t pda_lens[] = {7, 32};
    uint8_t pda[32], pda2[32], bump = 0, bump2 = 0;
    CHECK(mollusk_find_program_address(pda_seeds, pda_lens, 2, program_id, pda,
                                       &bump) == 0);
    CHECK(mollusk_find_program_address(pda_seeds, pda_lens, 2, program_id, pda2,
                                       &bump2) == 0);
    CHECK(memcmp(pda, pda2, 32) == 0 && bump == bump2);

    mollusk_context_free(ctx);
    if (failures) {
        fprintf(stderr, "smoke: %d check(s) failed\n", failures);
        return 1;
    }
    printf("smoke: ok\n");
    return 0;
}
