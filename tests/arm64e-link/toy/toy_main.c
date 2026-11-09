// Freestanding arm64e toy executable binding to toy_lib.dylib.
// expected.json lists the chained-fixup entry each global must produce.
#include <ptrauth.h>

typedef int (*fn_t)(void);

extern int fn_a(void);
extern int fn_b(void);
extern int lib_value;
extern int lib_array[4];

fn_t __ptrauth(ptrauth_key_asia, 0, 0) exe_auth_bind = fn_a;
fn_t __ptrauth(ptrauth_key_asib, 1, 0x77) exe_auth_bind_addr = fn_b;
int *exe_plain_bind = &lib_value;
int *exe_plain_bind_addend = &lib_array[2];
int *exe_plain_bind_negative = &lib_array[-1];

int exe_data = 5;
int *exe_plain_rebase = &exe_data;

int local_fn(void) { return 9; }
fn_t __ptrauth(ptrauth_key_asia, 0, 0x99) exe_auth_rebase = local_fn;

int main(void) { return fn_a() + exe_auth_bind() + *exe_plain_bind; }
