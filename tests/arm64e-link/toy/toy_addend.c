// Freestanding arm64e toy executable binding to toy_lib.dylib: only small positive addends on authenticated binds.
// No wide (negative or 32-bit) addend is present, so the imports must come out in format 2 (DYLD_CHAINED_IMPORT_ADDEND)
// and ld64 has to pick that format because of these two addends alone. expected.json, "addend_exe".
#include <ptrauth.h>

extern int lib_array[4];

int *__ptrauth(ptrauth_key_asda, 1, 0x55) small_auth_8 = &lib_array[2];
int *__ptrauth(ptrauth_key_asda, 1, 0x66) small_auth_16 = &lib_array[4];

int main(void) { return 0; }
