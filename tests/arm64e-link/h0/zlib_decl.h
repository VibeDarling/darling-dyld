// Public zlib 1.x interface, declared locally so the test does not need a host zlib.h.
// Layout of z_stream as in the stable public zlib.h (LP64: uLong is 8 bytes).
#ifndef H0_ZLIB_DECL_H
#define H0_ZLIB_DECL_H

typedef unsigned char Bytef;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef uLong uLongf;
typedef void *voidpf;
typedef voidpf (*alloc_func)(voidpf opaque, uInt items, uInt size);
typedef void (*free_func)(voidpf opaque, voidpf address);

typedef struct z_stream_s {
    const Bytef *next_in;
    uInt avail_in;
    uLong total_in;
    Bytef *next_out;
    uInt avail_out;
    uLong total_out;
    const char *msg;
    struct internal_state *state;
    alloc_func zalloc;
    free_func zfree;
    voidpf opaque;
    int data_type;
    uLong adler;
    uLong reserved;
} z_stream;

#define Z_OK 0
#define Z_STREAM_END 1
#define Z_FINISH 4
#define Z_DEFAULT_COMPRESSION (-1)
#define ZLIB_VERSION_STRING "1.2.12"

const char *zlibVersion(void);
int compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
uLong crc32(uLong crc, const Bytef *buf, uInt len);
uLong adler32(uLong adler, const Bytef *buf, uInt len);
int deflateInit_(z_stream *strm, int level, const char *version, int stream_size);
int deflate(z_stream *strm, int flush);
int deflateEnd(z_stream *strm);
int inflateInit_(z_stream *strm, const char *version, int stream_size);
int inflate(z_stream *strm, int flush);
int inflateEnd(z_stream *strm);

#endif
