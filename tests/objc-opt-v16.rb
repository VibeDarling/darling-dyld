# Version-16 objc_opt_t layout, ClassHashTable::classCount() and the version-16 selector table.
# Header-only: the test writes raw words at their measured offsets and checks the accessors resolve
# to them. It is not a load of a real cache image.
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
header = File.join(root, 'include', 'objc-shared-cache.h')
abort "missing #{header}" unless File.file?(header)

Dir.mktmpdir('objc-opt-v16-') do |dir|
  File.write(File.join(dir, 'test.cpp'), <<~CPP)
    #include <string.h>
    #include "objc-shared-cache.h"
    #include <assert.h>
    #include <initializer_list>
    #include <stddef.h>
    #include <stdint.h>
    #include <stdio.h>

    static_assert(objc_opt::VERSION == 16, "the header must declare version 16");

    // The version-16 objc_opt_t is 48 bytes: int32 offsets followed by one int64 relative-method
    // field. Words are written raw at their offsets, never through the struct, so a wrong field
    // position makes the accessor read a different word instead of moving with it.
    static void v16_offsets(void)
    {
        alignas(8) uint8_t buf[512];
        memset(buf, 0, sizeof(buf));
        *(uint32_t*)(buf + 0)  = 16;    // version
        *(uint32_t*)(buf + 4)  = 6;     // flags
        *(int32_t*)(buf + 8)   = 64;    // selopt offset
        *(int32_t*)(buf + 12)  = 128;   // headeropt_ro offset
        *(int32_t*)(buf + 16)  = 0;     // legacy clsopt offset
        *(int32_t*)(buf + 20)  = 0;     // legacy protocolopt offset
        *(int32_t*)(buf + 24)  = 192;   // headeropt_rw offset
        *(int32_t*)(buf + 28)  = 0;     // legacy protocolopt2 offset
        *(int32_t*)(buf + 32)  = 256;   // large class table offset
        *(int32_t*)(buf + 36)  = 320;   // large protocol table offset
        // A 64-bit relative-method base whose low word is zero: an int32 read yields 0 and null.
        *(uint64_t*)(buf + 40) = 0x0000000200000000ULL;
        const objc_opt::objc_opt_t* opt = (const objc_opt::objc_opt_t*)buf;
        assert((const uint8_t*)opt->selopt() == buf + 64);
        assert((const uint8_t*)opt->headeropt_ro() == buf + 128);
        assert((const uint8_t*)opt->headeropt_rw() == buf + 192);
        assert((const uint8_t*)opt->classOpt() == buf + 256);
        assert((const uint8_t*)opt->protocolOpt() == buf + 320);
        assert(opt->relativeMethodListsBaseAddress() != NULL);
        assert((uintptr_t)opt->relativeMethodListsBaseAddress() == (uintptr_t)buf + 0x200000000ULL);
        // A zero offset still means null.
        memset((void*)(buf + 32), 0, 8);
        *(uint64_t*)(buf + 40) = 0;
        assert(opt->classOpt() == NULL);
        assert(opt->protocolOpt() == NULL);
        assert(opt->relativeMethodListsBaseAddress() == NULL);
        assert(sizeof(objc_opt::objc_opt_t) == 48);
    }

    // A synthetic class table: capacity 4, mask 3, occupied 3, duplicateCount 7. The duplicate word
    // is placed at the address the layout formula gives, computed here rather than by the header's
    // helpers, so a helper that reads a different address returns zeroes.
    static void fill_class_table(uint8_t* buf, uint32_t occupied, uint32_t capacity,
                                 uint32_t mask, uint32_t dup)
    {
        memset(buf, 0, 2048);
        *(uint32_t*)(buf + 0)  = 0;         // version
        *(uint32_t*)(buf + 4)  = capacity;
        *(uint32_t*)(buf + 8)  = occupied;
        *(uint32_t*)(buf + 12) = 32;        // shift
        *(uint32_t*)(buf + 16) = mask;
        *(uint64_t*)(buf + 24) = 0;         // salt
        // header words end at +32, scramble[256] is 1024 bytes, tab[mask+1], checkbytes[capacity],
        // offsets[capacity], then ObjectData[capacity] and the duplicate count.
        uint8_t* tab = buf + 32 + 1024;
        uint8_t* checkbytes = tab + (mask + 1);
        int32_t* offsets = (int32_t*)(checkbytes + capacity);
        uint8_t* objectOffsets = (uint8_t*)(offsets + capacity);
        *(uint32_t*)(objectOffsets + (size_t)capacity * 8) = dup;
    }

    static void class_count(void)
    {
        alignas(8) uint8_t buf[2048];
        fill_class_table(buf, 3, 4, 3, 7);
        const objc::ClassHashTable* t = (const objc::ClassHashTable*)buf;
        assert(t->classCount() == 10);    // occupied 3 plus duplicateCount 7
        fill_class_table(buf, 3, 4, 3, 0);
        assert(t->classCount() == 3);     // no duplicates: occupied alone is right
    }

    struct TestStringTable : objc::StringHashTable {
        uint32_t versionValue() const { return version; }
        uint32_t capacityValue() const { return capacity; }
        uint32_t occupiedValue() const { return occupied; }
        uint32_t shiftValue() const { return shift; }
        uint32_t maskValue() const { return mask; }
        uint64_t saltValue() const { return salt; }
        const uint32_t* scrambleValues() const { return scramble; }
        const uint8_t* tabValues() const { return tab; }
    };

    // Every fixed field is written as a raw word at its version-16 offset and read back through
    // the header's accessors; nothing is written through the fields themselves.
    static void base_words(void)
    {
        alignas(8) uint8_t buf[2048];
        memset(buf, 0, sizeof(buf));
        *(uint32_t*)(buf + 0)  = 0x11111111;    // version
        *(uint32_t*)(buf + 4)  = 0x22222222;    // capacity
        *(uint32_t*)(buf + 8)  = 0x33333333;    // occupied
        *(uint32_t*)(buf + 12) = 0x44444444;    // shift
        *(uint32_t*)(buf + 16) = 0x55555555;    // mask
        *(uint64_t*)(buf + 24) = 0x6666666677777777ULL; // salt
        for (int i = 0; i < 256; ++i) {
            *(uint32_t*)(buf + 32 + 4 * i) = 0x80000000u + (uint32_t)i; // scramble
            *(uint8_t*)(buf + 1056 + i)    = (uint8_t)(0xA0 + i);      // tab
        }
        const TestStringTable* t = (const TestStringTable*)buf;
        assert(t->versionValue()  == 0x11111111);
        assert(t->capacityValue() == 0x22222222);
        assert(t->occupiedValue() == 0x33333333);
        assert(t->shiftValue()    == 0x44444444);
        assert(t->maskValue()     == 0x55555555);
        assert(t->saltValue()     == 0x6666666677777777ULL);
        for (int i = 0; i < 256; ++i) {
            assert(t->scrambleValues()[i] == 0x80000000u + (uint32_t)i);
            assert(t->tabValues()[i] == (uint8_t)(0xA0 + i));
        }
    }

    struct TestSelectorTable : objc_opt::objc_selopt_t {
        uint32_t capacityValue() const { return capacity; }
        uint32_t occupiedValue() const { return occupied; }
        uint32_t shiftValue() const { return shift; }
        uint32_t maskValue() const { return mask; }
    };

    // Version-16 selector table layout: header words at +0..+16, salt at +24, scramble[256] at +32
    // (1024 bytes), tab[mask+1] at +1056, checkbytes[capacity] after tab, offsets[capacity] after
    // checkbytes. Every address is computed here, not from the header's accessors.
    struct SelTable {
        uint8_t* base;
        uint8_t* tab;
        uint8_t* checkbytes;
        int32_t* offsets;
    };

    static SelTable make_sel_table(uint8_t* buf)
    {
        memset(buf, 0, 4096);
        *(uint32_t*)(buf + 0)  = 0;      // version
        *(uint32_t*)(buf + 4)  = 256;    // capacity
        *(uint32_t*)(buf + 8)  = 7;      // occupied
        *(uint32_t*)(buf + 12) = 64;     // shift: 64 means the high bits contribute nothing
        *(uint32_t*)(buf + 16) = 255;    // mask: tab has mask+1 = 256 entries
        *(uint64_t*)(buf + 24) = 0;      // salt
        for (int i = 0; i < 256; ++i) {
            *(uint32_t*)(buf + 32 + 4 * i) = (uint32_t)i; // scramble[j] = j
            *(uint8_t*)(buf + 1056 + i)    = (uint8_t)i;  // tab[i] = i
        }
        SelTable t = { buf, buf + 1056, NULL, NULL };
        t.checkbytes = t.tab + 256;
        t.offsets = (int32_t*)(t.checkbytes + 256);
        return t;
    }

    // Every slot points at the same string and carries the check byte of "abc".
    static void set_all_slots(SelTable& t, const char* str)
    {
        int32_t offset = (int32_t)(str - (const char*)t.base);
        for (int i = 0; i < 256; ++i) {
            t.checkbytes[i] = (uint8_t)((('a' & 0x7) << 5) | (3 & 0x1f)); // checkbyte("abc")
            t.offsets[i] = offset;
        }
    }

    static void selector_lookup(void)
    {
        alignas(8) uint8_t buf[4096];
        SelTable t = make_sel_table(buf);
        char* str = (char*)(buf + 3000);
        memcpy(str, "abc", 4);
        set_all_slots(t, str);

        const TestSelectorTable* sel = (const TestSelectorTable*)buf;
        assert(sel->capacityValue() == 256);
        assert(sel->occupiedValue() == 7);
        // usedCount keeps the version-15 meaning: the table size the fixup indices range over.
        assert(sel->usedCount() == 256);
        assert(sel->get("abc") == str);
        assert(sel->get("abd") == NULL);        // same check byte; strcmp rejects
        assert(sel->get("zzzz") == NULL);       // check byte rejects
        assert(sel->getIndexForKey("abc") != sel->getSentinelIndex());
        assert(sel->getIndexForKey("zzzz") == sel->getSentinelIndex());
        for (uint32_t k : {0u, 1u, 17u, 255u})
            assert(sel->getEntryForIndex(k) == str);
    }

    static void selector_checkbyte_reject(void)
    {
        alignas(8) uint8_t buf[4096];
        SelTable t = make_sel_table(buf);
        char* str = (char*)(buf + 3000);
        memcpy(str, "zzzz", 5);
        set_all_slots(t, str);

        const TestSelectorTable* sel = (const TestSelectorTable*)buf;
        // The slot's offset points at "zzzz" and would pass strcmp; only the check byte rejects it.
        assert(sel->get("zzzz") == NULL);
    }

    static void selector_entry_index(void)
    {
        alignas(8) uint8_t buf[4096];
        SelTable t = make_sel_table(buf);
        for (int i = 0; i < 256; ++i)
            t.offsets[i] = i * 8;

        const TestSelectorTable* sel = (const TestSelectorTable*)buf;
        for (uint32_t k : {0u, 1u, 17u, 255u})
            assert(sel->getEntryForIndex(k) == (const char*)buf + k * 8);
    }

    // Measured words from the cache's selector table: version, capacity, occupied, shift, mask.
    // A version-15 read would take capacity from +0 and report 0 here, i.e. the wrong table.
    static void real_cache_words(void)
    {
        alignas(8) uint8_t buf[64];
        memset(buf, 0, sizeof(buf));
        *(uint32_t*)(buf + 0)  = 0;
        *(uint32_t*)(buf + 4)  = 0x200000;
        *(uint32_t*)(buf + 8)  = 0x142d04;
        *(uint32_t*)(buf + 12) = 0x2b;
        *(uint32_t*)(buf + 16) = 0x3ffff;

        const TestSelectorTable* t = (const TestSelectorTable*)buf;
        assert(t->capacityValue() == 0x200000);
        assert(t->occupiedValue() == 0x142d04);
        assert(t->shiftValue() == 43);
        assert(t->maskValue() == 0x3ffff);
    }

    int main(void)
    {
        v16_offsets();
        base_words();
        class_count();
        real_cache_words();
        selector_lookup();
        selector_checkbyte_reject();
        selector_entry_index();
        printf("OK objc_opt v16\\n");
        return 0;
    }
  CPP
  cmd = ['clang++', '-std=c++17', '-Wall', '-Werror', '-I', File.join(root, 'include'),
         File.join(dir, 'test.cpp'), '-o', File.join(dir, 'test')]
  out, st = Open3.capture2e(*cmd)
  abort "compile failed:\n#{out}" unless st.success?
  out, st = Open3.capture2e(File.join(dir, 'test'))
  abort "test failed:\n#{out}" unless st.success?
  puts out
  puts 'PASS objc_opt v16 layout, classCount and selector table'
end
