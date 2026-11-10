# Layout of the version-4 patch info and the decoder of its flags word (dyld_cache_format.h), checked against
# offsets and bit positions that were measured on a real macOS arm64e cache and are written down here
# independently of the header (which also has static_asserts). Every encoding class of the decoder is exercised,
# including the ones it must refuse.
# Usage: ruby tests/patch-info-v4-format.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))

Dir.mktmpdir('patch-info-v4-format-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stdio.h>
    #include <string.h>
    #include <initializer_list>
    #include "dyld_cache_format.h"
    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)
    #define SIZE_IS(type, n) CHECK(sizeof(type) == (n))
    #define OFF_IS(type, member, n) CHECK(offsetof(type, member) == (n))

    // The encoder is the test's own: bit positions as measured, not shared with the decoder.
    static uint32_t encode(bool auth, unsigned high7, bool bit8, unsigned addend, bool addrDiv, bool keyData, unsigned disc) {
      uint32_t f = auth ? 1 : 0;
      f |= (high7 & 0x7f) << 1;
      f |= bit8 ? (1u << 8) : 0;
      if (auth) f |= (addend & 0x1f) << 9; else f |= (addend & 0x7f) << 9;
      if (auth) f |= (addrDiv ? 1u << 14 : 0) | (keyData ? 1u << 15 : 0) | ((uint32_t)disc << 16);
      return f;
    }
    static dyld_cache_patch_encoding_v4 decoded; static bool explained;
    static void decode(uint32_t f) { memset(&decoded, 0xaa, sizeof decoded); explained = decodeCachePatchFlagsV4(f, &decoded); }

    int main() {
      // --- record sizes and header offsets ---
      SIZE_IS(dyld_cache_patch_info_v4, 152); SIZE_IS(dyld_cache_image_patches_v4, 16); SIZE_IS(dyld_cache_patchable_export_v4, 8);
      SIZE_IS(dyld_cache_patch_client_v4, 12); SIZE_IS(dyld_cache_patch_client_export_v4, 12); SIZE_IS(dyld_cache_patchable_location_v4, 8);
      SIZE_IS(dyld_cache_image_got_clients_v4, 8); SIZE_IS(dyld_cache_got_client_export_v4, 12); SIZE_IS(dyld_cache_patchable_got_location_v4, 16);
      OFF_IS(dyld_cache_patch_info_v4, patchTableVersion, 0); OFF_IS(dyld_cache_patch_info_v4, patchLocationVersion, 4);
      OFF_IS(dyld_cache_patch_info_v4, patchTableArrayAddr, 8); OFF_IS(dyld_cache_patch_info_v4, imageExportsArrayAddr, 24);
      OFF_IS(dyld_cache_patch_info_v4, clientsArrayAddr, 40); OFF_IS(dyld_cache_patch_info_v4, clientExportsArrayAddr, 56);
      OFF_IS(dyld_cache_patch_info_v4, locationArrayAddr, 72); OFF_IS(dyld_cache_patch_info_v4, exportNamesAddr, 88);
      OFF_IS(dyld_cache_patch_info_v4, gotClientsArrayAddr, 104); OFF_IS(dyld_cache_patch_info_v4, gotClientExportsArrayAddr, 120);
      OFF_IS(dyld_cache_patch_info_v4, gotLocationArrayAddr, 136); OFF_IS(dyld_cache_patch_info_v4, gotLocationArrayCount, 144);
      OFF_IS(dyld_cache_patchable_export_v4, nameKind, 4); OFF_IS(dyld_cache_patchable_location_v4, flags, 4);
      OFF_IS(dyld_cache_patchable_got_location_v4, cacheOffsetHi, 4); OFF_IS(dyld_cache_patchable_got_location_v4, flags, 8);
      OFF_IS(dyld_cache_patchable_got_location_v4, reserved, 12);

      // --- the common real encodings ---
      decode(0x4001); CHECK(explained && decoded.authenticated && decoded.usesAddressDiversity && !decoded.keyIsData && decoded.discriminator == 0 && decoded.addend == 0);
      decode(0); CHECK(explained && !decoded.authenticated && decoded.high7 == 0 && decoded.addend == 0);

      // --- every authenticated class: key x address diversity x discriminator, at the edges ---
      for (int key = 0; key < 2; ++key) for (int ad = 0; ad < 2; ++ad)
        for (unsigned disc : {0u, 1u, 0x8000u, 0xffffu}) for (unsigned addend : {0u, 1u, 31u}) for (int bit8 = 0; bit8 < 2; ++bit8) {
          decode(encode(true, 0, bit8, addend, ad, key, disc));
          CHECK(explained && decoded.authenticated && decoded.keyIsData == (bool)key && decoded.usesAddressDiversity == (bool)ad);
          CHECK(decoded.discriminator == disc && decoded.addend == addend && decoded.high7 == 0 && decoded.bit8 == (bool)bit8);
        }
      // --- unauthenticated: high7 and the 7-bit addend (bits 9-15, so bits 14 and 15 are addend bits) ---
      for (unsigned high7 : {0u, 1u, 0x40u, 0x7fu}) for (unsigned addend : {0u, 1u, 31u, 32u, 64u, 127u}) {
        decode(encode(false, high7, false, addend, false, false, 0));
        CHECK(explained && !decoded.authenticated && decoded.high7 == high7 && decoded.addend == addend);
        CHECK(!decoded.usesAddressDiversity && !decoded.keyIsData && decoded.discriminator == 0);
      }
      decode(0xc000); CHECK(explained && decoded.addend == 0x60 && !decoded.keyIsData);   // bits 14,15 of a plain word
      // --- authenticated: bits 14 and 15 are not addend bits ---
      decode(encode(true, 0, false, 31, false, false, 0)); CHECK(explained && decoded.addend == 31 && !decoded.usesAddressDiversity);
      // --- encodings the decoder cannot explain are refused, whatever else is set ---
      decode(encode(true, 1, false, 0, true, false, 0)); CHECK(!explained);       // authenticated with a high7
      decode(encode(true, 0x7f, false, 0, true, true, 0xffff)); CHECK(!explained);
      decode(0x00010000); CHECK(!explained);                                      // plain with a discriminator
      decode(0xffff0000u); CHECK(!explained);
      decode(0x80000000u); CHECK(!explained);
      // bit 8 alone does not make an encoding unexplained
      decode(0x100); CHECK(explained && decoded.bit8 && !decoded.authenticated);
      decode(0x4101); CHECK(explained && decoded.bit8 && decoded.authenticated && decoded.usesAddressDiversity);
      printf(failures ? "RESULT failed\\n" : "RESULT ok\\n");
      return failures != 0;
    }
  CPP
  out, st = Open3.capture2e('clang++', '-std=c++17', '-Wall', '-Werror', "-I#{root}/dyld3/shared-cache", "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test")
  puts out
  abort 'patch info v4 format test failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS patch info v4 layout and flag decoder'
end
