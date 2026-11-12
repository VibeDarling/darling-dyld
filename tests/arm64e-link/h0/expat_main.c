// PAC-leaf guest test: an arm64e executable that parses XML with libexpat.
// Exit 0 only if every check passes; each failing check has its own exit code.
// libexpat's __AUTH_CONST holds 260 PAC-signed function pointers (the tokenizer tables of its UTF-8,
// UTF-16 and Latin-1 encodings), and every XML_Parse call goes through them. The handlers below are
// signed pointers of this image that libexpat calls, so signed calls cross images in both directions.
// Freestanding like h0_zlib_main.c: the only libSystem import is write(2).
#include "expat_decl.h"

long write(int fd, const void *buf, unsigned long n);

enum {
    OK = 0,
    FAIL_VERSION = 1,
    FAIL_CREATE,
    FAIL_PARSE_UTF8,
    FAIL_COUNTS_UTF8,
    FAIL_PARSE_CHUNKS,
    FAIL_COUNTS_CHUNKS,
    FAIL_PARSE_UTF16,
    FAIL_COUNTS_UTF16,
    FAIL_NO_ERROR_ON_BAD_DOC,
    FAIL_ERROR_CODE,
};

struct tally {
    int starts, ends, attrs, depth, max_depth;
    unsigned long text_len, text_sum;
};

static void zero(void *p, unsigned long n) {
    volatile unsigned char *c = p;
    for (unsigned long i = 0; i < n; i++) c[i] = 0;
}

static int starts_with(const char *s, const char *prefix) {
    for (; *prefix; s++, prefix++)
        if (*s != *prefix) return 0;
    return 1;
}

static int slen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void on_start(void *user, const char *name, const char **atts) {
    struct tally *t = user;
    (void)name;
    t->starts++;
    for (int i = 0; atts[i]; i += 2) t->attrs++;
    if (++t->depth > t->max_depth) t->max_depth = t->depth;
}

static void on_end(void *user, const char *name) {
    struct tally *t = user;
    (void)name;
    t->ends++;
    t->depth--;
}

static void on_text(void *user, const char *s, int len) {
    struct tally *t = user;
    for (int i = 0; i < len; i++) t->text_sum += (unsigned char)s[i];
    t->text_len += (unsigned long)len;
}

// DOCTYPE with an internal entity (prolog tokenizer), comments, a processing instruction, CDATA, character and
// predefined references, attributes in both quote styles, a multi-byte UTF-8 character, 3 nesting levels.
// Elements: doc, a x3 with an <i> inside each = 1 + 3 + 3 = 7. Attributes: 3 x id + 3 x k + 1 = 7.
// Character data delivered to the handler (all bytes, in UTF-8): see EXPECT_TEXT_*.
static const char doc[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE doc [ <!ENTITY e \"EE\"> ]>\n"
    "<!-- comment -->\n"
    "<?pi data?>\n"
    "<doc v='1'>"
    "<a id=\"1\" k='x'><i>A&amp;B</i></a>"
    "<a id=\"2\" k='y'><i>&#65;&#x42;&e;</i></a>"
    "<a id=\"3\" k='z'><i><![CDATA[<c>]]>\xC3\xA9</i></a>"
    "</doc>\n";

// Text the handler sees: "A&B" (3) + "ABEE" (4) + "<c>" + e-acute (3 + 2 bytes = 5) = 12 bytes.
// Byte sum: A 65 + & 38 + B 66 = 169; A 65 + B 66 + E 69 + E 69 = 269; < 60 + c 99 + > 62 + C3 195 + A9 169 = 585.
#define EXPECT_ELEMENTS 7
#define EXPECT_ATTRS 7
#define EXPECT_TEXT_LEN 12
#define EXPECT_TEXT_SUM (169 + 269 + 585)

static int counts_ok(const struct tally *t) {
    return t->starts == EXPECT_ELEMENTS && t->ends == EXPECT_ELEMENTS && t->attrs == EXPECT_ATTRS
        && t->depth == 0 && t->max_depth == 3 && t->text_len == EXPECT_TEXT_LEN && t->text_sum == EXPECT_TEXT_SUM;
}

static XML_Parser make(const char *encoding, struct tally *t) {
    XML_Parser p = XML_ParserCreate(encoding);
    if (!p) return 0;
    XML_SetUserData(p, t);
    XML_SetElementHandler(p, on_start, on_end);
    XML_SetCharacterDataHandler(p, on_text);
    return p;
}

static int check_utf8_whole(void) {
    struct tally t;
    zero(&t, sizeof t);
    XML_Parser p = make(0, &t);
    if (!p) return FAIL_CREATE;
    int ok = XML_Parse(p, doc, (int)sizeof doc - 1, 1) == XML_STATUS_OK;
    XML_ParserFree(p);
    if (!ok) return FAIL_PARSE_UTF8;
    return counts_ok(&t) ? OK : FAIL_COUNTS_UTF8;
}

// One byte at a time: every token is split across calls, which takes libexpat's partial-token paths.
static int check_utf8_chunks(void) {
    struct tally t;
    zero(&t, sizeof t);
    XML_Parser p = make(0, &t);
    if (!p) return FAIL_CREATE;
    int ok = 1;
    int n = (int)sizeof doc - 1;
    for (int i = 0; ok && i < n; i++) ok = XML_Parse(p, doc + i, 1, i == n - 1) == XML_STATUS_OK;
    XML_ParserFree(p);
    if (!ok) return FAIL_PARSE_CHUNKS;
    return counts_ok(&t) ? OK : FAIL_COUNTS_CHUNKS;
}

// The same logical document in UTF-16LE with a byte order mark: the little2_ tokenizers.
static int check_utf16(void) {
    static const char src[] = "<doc v='1'><a id=\"1\" k='x'><i>A&amp;B</i></a></doc>";
    static char wide[2 + 2 * sizeof src];
    int n = slen(src);
    wide[0] = (char)0xFF;
    wide[1] = (char)0xFE;
    for (int i = 0; i < n; i++) { wide[2 + 2 * i] = src[i]; wide[3 + 2 * i] = 0; }
    struct tally t;
    zero(&t, sizeof t);
    XML_Parser p = make(0, &t);
    if (!p) return FAIL_CREATE;
    int ok = XML_Parse(p, wide, 2 + 2 * n, 1) == XML_STATUS_OK;
    XML_ParserFree(p);
    if (!ok) return FAIL_PARSE_UTF16;
    // 3 elements (doc, a, i), 3 attributes (v, id, k), text "A&B" = 3 bytes, sum 169
    return (t.starts == 3 && t.ends == 3 && t.attrs == 3 && t.text_len == 3 && t.text_sum == 169) ? OK : FAIL_COUNTS_UTF16;
}

static int check_error(void) {
    static const char bad[] = "<a><b></a>";
    struct tally t;
    zero(&t, sizeof t);
    XML_Parser p = make(0, &t);
    if (!p) return FAIL_CREATE;
    int status = XML_Parse(p, bad, (int)sizeof bad - 1, 1);
    int code = XML_GetErrorCode(p);
    XML_ParserFree(p);
    if (status != XML_STATUS_ERROR) return FAIL_NO_ERROR_ON_BAD_DOC;
    return code == XML_ERROR_TAG_MISMATCH ? OK : FAIL_ERROR_CODE;
}

static int run(void) {
    const char *v = XML_ExpatVersion();
    if (!v || !starts_with(v, "expat_")) return FAIL_VERSION;
    int rc = check_utf8_whole();
    if (rc == OK) rc = check_utf8_chunks();
    if (rc == OK) rc = check_utf16();
    if (rc == OK) rc = check_error();
    return rc;
}

static char *put_str(char *p, const char *s) {
    while (*s) *p++ = *s++;
    return p;
}

static void report(int code) {
    char line[64];
    char *p = put_str(line, "h0 expat ");
    if (code == OK) {
        p = put_str(p, "OK ");
        p = put_str(p, XML_ExpatVersion());
    } else {
        p = put_str(p, "FAIL ");
        *p++ = (char)('0' + code / 10);
        *p++ = (char)('0' + code % 10);
    }
    *p++ = '\n';
    write(1, line, (unsigned long)(p - line));
}

int main(void) {
    int rc = run();
    report(rc);
    return rc;
}
