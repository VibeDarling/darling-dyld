// Freestanding arm64e toy dylib: one pointer per authentication flavour.
// expected.json lists the chained-fixup entry each global must produce.
#include <ptrauth.h>

int fn_a(void) { return 1; }
int fn_b(void) { return 2; }
int fn_c(void) { return 3; }
int fn_d(void) { return 4; }
int fn_e(void) { return 5; }

int lib_value = 42;
int lib_array[4] = {10, 11, 12, 13};

typedef int (*fn_t)(void);

fn_t __ptrauth(ptrauth_key_asia, 0, 0) tbl_ia0 = fn_a;
fn_t __ptrauth(ptrauth_key_asia, 0, 0x1234) tbl_ia_const = fn_b;
fn_t __ptrauth(ptrauth_key_asib, 0, 0x2222) tbl_ib = fn_c;
int *__ptrauth(ptrauth_key_asda, 1, 0x4321) tbl_da_addr = &lib_value;
int *__ptrauth(ptrauth_key_asdb, 1, 0x55) tbl_db_addr = &lib_array[2];

// Vtable-like: every slot is address-diversified, with its own discriminator.
struct vtable {
  fn_t __ptrauth(ptrauth_key_asia, 1, 0x10) m0;
  fn_t __ptrauth(ptrauth_key_asia, 1, 0x11) m1;
  fn_t __ptrauth(ptrauth_key_asia, 1, 0x12) m2;
};
struct vtable lib_vtable = {fn_a, fn_d, fn_e};

int *plain_ptr = &lib_value;
fn_t plain_fn = fn_c;
