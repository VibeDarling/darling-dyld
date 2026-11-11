# Version-16 objc_opt_t layout and ClassHashTable::classCount(). Header-only: the test synthesizes the
# cache words T0 measured and checks the accessors resolve to them. Not a load of a real cache image.
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
    #include <stddef.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <new>

    // The layout below is the one T0 read out of the cache (L5-facts.md 3): version 16, then the
    // offsets in order. The test writes raw words at those offsets, never through the struct, so a
    // wrong field position makes the accessor read a different word instead of moving with it.
    static_assert(objc_opt::VERSION == 16, "the header must declare version 16");

    static void v16_offsets(void)
    {
        alignas(8) uint8_t buf[512];
        memset(buf, 0, sizeof(buf));
        *(uint32_t*)(buf + 0)  = 16;    // version
        *(uint32_t*)(buf + 4)  = 6;     // flags
        *(int32_t*)(buf + 8)   = 64;    // selopt
        *(int32_t*)(buf + 12)  = 128;   // headeropt_ro
        *(int32_t*)(buf + 16)  = 0;     // unused_clsopt
        *(int32_t*)(buf + 20)  = 0;     // unused_protocolopt
        *(int32_t*)(buf + 24)  = 192;   // headeropt_rw
        *(int32_t*)(buf + 28)  = 0;     // unused_protocolopt2
        *(int32_t*)(buf + 32)  = 256;   // largeSharedCachesClassOffset
        *(int32_t*)(buf + 36)  = 320;   // largeSharedCachesProtocolOffset
        *(int64_t*)(buf + 40)  = 384;   // relativeMethodSelectorBaseAddressOffset
        const objc_opt::objc_opt_t* opt = (const objc_opt::objc_opt_t*)buf;
        assert((const uint8_t*)opt->selopt() == buf + 64);
        assert((const uint8_t*)opt->headeropt_ro() == buf + 128);
        assert((const uint8_t*)opt->headeropt_rw() == buf + 192);
        assert((const uint8_t*)opt->classOpt() == buf + 256);
        assert((const uint8_t*)opt->protocolOpt() == buf + 320);
        assert((const uint8_t*)opt->relativeMethodListsBaseAddress() == buf + 384);
        // A zero offset still means null, as for the v15 accessors.
        memset((void*)(buf + 32), 0, 8);
        *(int64_t*)(buf + 40) = 0;
        assert(opt->classOpt() == NULL);
        assert(opt->protocolOpt() == NULL);
        assert(opt->relativeMethodListsBaseAddress() == NULL);
        // The struct itself must occupy the measured 48 bytes.
        assert(sizeof(objc_opt::objc_opt_t) == 48);
    }

    // A synthetic class table: capacity 4, mask 3, occupied 3, duplicateCount 7. The duplicate word
    // is placed at the address the layout formula gives, computed here rather than by the header's
    // helpers, so a helper that reads a different address returns zeroes.
    struct TestTable : objc::ClassHashTable {
        static void fill(uint8_t* buf, uint32_t dup)
        {
            memset(buf, 0, 2048);
            TestTable* t = new (buf) TestTable();
            t->version  = 0;
            t->capacity = 4;
            t->occupied = 3;
            t->shift    = 32;
            t->mask     = 3;
            // base of tab[] after version..salt (32 bytes) + scramble[256] (1024 bytes)
            uint8_t* tab = (uint8_t*)t + 32 + 1024;
            uint32_t mask_plus_1 = t->mask + 1;
            uint8_t* checkbytes = tab + mask_plus_1;
            int32_t* offsets = (int32_t*)(checkbytes + t->capacity);
            uint8_t* objectOffsets = (uint8_t*)(offsets + t->capacity);
            uint32_t* dupword = (uint32_t*)(objectOffsets + (size_t)t->capacity * 8);
            *dupword = dup;
        }
    };

    static void class_count(void)
    {
        alignas(8) uint8_t buf[2048];
        TestTable::fill(buf, 7);
        const objc::ClassHashTable* t = (const objc::ClassHashTable*)buf;
        assert(t->classCount() == 10);    // occupied 3 plus duplicateCount 7
        TestTable::fill(buf, 0);
        assert(t->classCount() == 3);     // no duplicates: occupied alone is right
    }

    int main(void)
    {
        v16_offsets();
        class_count();
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
  puts 'PASS objc_opt v16 layout and classCount'
end
