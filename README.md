# mollusk-cxx

A C ABI for [Mollusk](https://github.com/anza-xyz/mollusk)

| platform       | link with                                          |
| -------------- | -------------------------------------------------- |
| `darwin-arm64` | `-liconv -lm`                                      |
| `darwin-x64`   | `-liconv -lm`                                      |
| `linux-x64`    | `-lgcc_s -lutil -lrt -lpthread -lm -ldl`           |
| `linux-arm64`  | `-lgcc_s -lutil -lrt -lpthread -lm -ldl`           |

Mollusk has no bank: you hand it the accounts, it runs the instruction and
hands back the resulting accounts. `MolluskContextHandle` adds an account
store for tests that chain state from one instruction to the next.

## Example

```c
#include "mollusk.h"

uint8_t program_id[32] = {0xC0}, system_program[32] = {0};
uint8_t payer[32] = {/* ... */}, counter[32] = {/* ... */};

MolluskHandle *m = mollusk_new();
mollusk_add_program_from_file(m, program_id, (const uint8_t *)"program.so", 10);

MolluskAccount *sys = mollusk_program_account(m, system_program);
MolluskKeyedAccount accounts[3] = {
    {payer, 1000000000, NULL, 0, system_program, false, 0},
    {counter, 0, NULL, 0, system_program, false, 0},
};
mollusk_account_keyed(sys, system_program, &accounts[2]);

uint8_t data[] = {0};
MolluskAccountMeta metas[] = {
    {payer, true, true}, {counter, true, true}, {system_program, false, false}};
MolluskInstruction ix = {program_id, metas, 3, data, sizeof data};

MolluskResult *r = mollusk_process_instruction(m, &ix, accounts, 3);
MolluskError err;
mollusk_result_error_info(r, &err);
if (err.kind == MOLLUSK_ERR_INSTRUCTION)
    printf("failed: program error %llu\n", (unsigned long long)err.program_error);
MolluskAccount *after = mollusk_result_get_account(r, counter);
mollusk_account_free(after);
mollusk_result_free(r);
mollusk_account_free(sys);

MolluskContextHandle *ctx = mollusk_context_new(m); /* takes ownership of m */
mollusk_context_set_account(ctx, &accounts[0]);
r = mollusk_context_process_instruction(ctx, &ix);
mollusk_result_free(r);
mollusk_context_free(ctx);
```

```sh
cc -Ipath/to/include test.c path/to/libs/darwin-arm64/libmollusk.a -liconv -lm
```

`MolluskError` has the same layout as litesvm-cxx's `LiteSvmTxError`.
