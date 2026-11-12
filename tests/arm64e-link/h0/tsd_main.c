// TSD guest test: an arm64e executable that links libmalloc_exclaves_introspector, a cache library whose only
// dependency is libSystem.B and whose text holds 4 `mrs Xt, TPIDRRO_EL0` reads (the site table lists them), and calls its
// malloc_printf export once.
//
// The program checks the translation, not the library's behaviour. kExportOffset is malloc_printf's offset in the
// export trie and kFirstTSDRead the first site the TSD site table lists for this image, both for the one macOS 26.1
// arm64e cache this was written against; the mach header check exits 4 on a different layout.
// Exit codes: 0 translated and the call returned, 3 the read is still an mrs, 4 not the expected image.
// Freestanding like the other H0 programs: the only libSystem import is write(2).
#include <ptrauth.h>

void malloc_printf(const char *format, ...);    // printf-style signature, as in the open-source libmalloc sources
long write(int fd, const void *buf, unsigned long n);

enum { kExportOffset = 0x4828, kFirstTSDRead = 0x48c4 };

int main(void) {
    const char *mh = (const char *)__builtin_ptrauth_strip((void *)malloc_printf, ptrauth_key_asia) - kExportOffset;
    if (*(const unsigned *)mh != 0xFEEDFACFu) return 4;
    if ((*(const unsigned *)(mh + kFirstTSDRead) & 0xFC000000u) != 0x14000000u) return 3;
    malloc_printf("tsd-test marker %d\n", 42);
    static const char done[] = "tsd-test done\n";
    return write(1, done, sizeof(done) - 1) == (long)(sizeof(done) - 1) ? 0 : 2;
}
