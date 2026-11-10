// H0 guest test: an arm64e executable that calls a few libz functions.
// Exit 0 only if every check passes; each failing check has its own exit code.
// Freestanding on purpose: the only libSystem import is write(2), so the import
// table stays small and known (see arm64e-link-h0.rb). Build flags forbid
// compiler-generated memcpy/memset calls.
#include "zlib_decl.h"

long write(int fd, const void *buf, unsigned long n);

enum {
    OK = 0,
    FAIL_VERSION = 1,
    FAIL_COMPRESS_RC,
    FAIL_NOT_SMALLER,
    FAIL_UNCOMPRESS_RC,
    FAIL_UNCOMPRESS_LEN,
    FAIL_ROUNDTRIP_DATA,
    FAIL_CRC32,
    FAIL_ADLER32,
    FAIL_DEFLATE_INIT,
    FAIL_DEFLATE,
    FAIL_DEFLATE_END,
    FAIL_INFLATE_INIT,
    FAIL_INFLATE,
    FAIL_INFLATE_END,
    FAIL_STREAM_LEN,
    FAIL_STREAM_DATA,
};

#define SIZE 4096
static unsigned char input[SIZE];
static unsigned char packed[2 * SIZE];
static unsigned char output[SIZE];

// Alternating 256-byte blocks: runs of one repeated byte, then LCG noise.
static void fill_input(void) {
    unsigned int x = 12345;
    for (unsigned int i = 0; i < SIZE; i++) {
        unsigned int block = i / 256;
        if (block % 2 == 0) {
            input[i] = (unsigned char)(0x40 + block + (i % 256) / 64);
        } else {
            x = x * 1103515245u + 12345u;
            input[i] = (unsigned char)(x >> 16);
        }
    }
}

static int same(const unsigned char *a, const unsigned char *b, unsigned int n) {
    for (unsigned int i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

static void zero(void *p, unsigned long n) {
    volatile unsigned char *c = p;
    for (unsigned long i = 0; i < n; i++) c[i] = 0;
}

static int check_version(void) {
    const char *v = zlibVersion();
    return (v && v[0] == '1' && v[1] == '.') ? OK : FAIL_VERSION;
}

static int check_buffer_api(void) {
    uLongf plen = sizeof packed;
    if (compress(packed, &plen, input, SIZE) != Z_OK) return FAIL_COMPRESS_RC;
    if (plen >= SIZE) return FAIL_NOT_SMALLER;
    uLongf olen = sizeof output;
    if (uncompress(output, &olen, packed, plen) != Z_OK) return FAIL_UNCOMPRESS_RC;
    if (olen != SIZE) return FAIL_UNCOMPRESS_LEN;
    return same(input, output, SIZE) ? OK : FAIL_ROUNDTRIP_DATA;
}

static int check_checksums(void) {
    if (crc32(crc32(0, 0, 0), (const Bytef *)"123456789", 9) != 0xCBF43926UL) return FAIL_CRC32;
    if (adler32(adler32(0, 0, 0), (const Bytef *)"Wikipedia", 9) != 0x11E60398UL) return FAIL_ADLER32;
    return OK;
}

static int check_streams(void) {
    z_stream s;
    zero(&s, sizeof s);
    if (deflateInit_(&s, Z_DEFAULT_COMPRESSION, ZLIB_VERSION_STRING, (int)sizeof s) != Z_OK)
        return FAIL_DEFLATE_INIT;
    zero(packed, sizeof packed);  // so a short deflate() cannot pass on compress()'s leftovers
    s.next_in = input;
    s.avail_in = SIZE;
    s.next_out = packed;
    s.avail_out = sizeof packed;
    if (deflate(&s, Z_FINISH) != Z_STREAM_END) return FAIL_DEFLATE;
    uLong plen = s.total_out;
    if (deflateEnd(&s) != Z_OK) return FAIL_DEFLATE_END;

    zero(output, sizeof output);
    zero(&s, sizeof s);
    if (inflateInit_(&s, ZLIB_VERSION_STRING, (int)sizeof s) != Z_OK) return FAIL_INFLATE_INIT;
    s.next_in = packed;
    s.avail_in = (uInt)plen;
    s.next_out = output;
    s.avail_out = sizeof output;
    if (inflate(&s, Z_FINISH) != Z_STREAM_END) return FAIL_INFLATE;
    uLong olen = s.total_out;
    if (inflateEnd(&s) != Z_OK) return FAIL_INFLATE_END;
    if (olen != SIZE) return FAIL_STREAM_LEN;
    return same(input, output, SIZE) ? OK : FAIL_STREAM_DATA;
}

static void report(int code) {
    char line[] = "h0 zlib OK\n";
    char fail[] = "h0 zlib FAIL 00\n";
    if (code == OK) {
        write(1, line, sizeof line - 1);
        return;
    }
    fail[13] = (char)('0' + code / 10);
    fail[14] = (char)('0' + code % 10);
    write(1, fail, sizeof fail - 1);
}

int main(void) {
    fill_input();
    int rc = check_version();
    if (rc == OK) rc = check_buffer_api();
    if (rc == OK) rc = check_checksums();
    if (rc == OK) rc = check_streams();
    report(rc);
    return rc;
}
