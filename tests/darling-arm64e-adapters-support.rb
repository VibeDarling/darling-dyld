# Shared by tests/darling-arm64e-adapters.rb and tests/darling-arm64e-adapters-hooks.rb: the stubs that let the adapter module
# (dyld3/DarlingArm64eAdapters.cpp) build on this host, and a builder for a native driver around it.
require 'fileutils'
require 'open3'

module AdapterSupport
  HWCAP_PACA = 1 << 30

  SHIM_LOADED = <<~H
    #pragma once
    #include <stdint.h>
    struct linkedit_data_command { uint32_t cmd, cmdsize, dataoff, datasize; };
    struct Diagnostics;
    namespace dyld3 { struct MachOLoaded {
      struct ChainedFixupPointerOnDisk { struct Arm64e {
        static uint64_t signPointer(uint64_t unsignedAddr, void* loc, bool addrDiv, uint16_t diversity, uint8_t key);
      }; };
      struct LayoutInfo { uintptr_t slide, textUnslidVMAddr, linkeditUnslidVMAddr; uint32_t linkeditFileOffset, linkeditFileSize, linkeditSegIndex, lastSegIndex; };
      struct LinkEditInfo { const linkedit_data_command* functionStarts; LayoutInfo layout; };
      void getLinkEditPointers(Diagnostics&, LinkEditInfo&) const;
    }; }
  H
  SHIM_MACHINE = <<~H
    #pragma once
    #include <stdint.h>
    typedef int cpu_subtype_t;
    #define CPU_SUBTYPE_MASK 0xff000000
    #define CPU_SUBTYPE_ARM64E ((cpu_subtype_t) 2)
  H

  # the real signPointer of dyld3/MachOLoaded.cpp, so that the tests exercise the code the dyld build uses
  def self.extract_sign_pointer(source)
    text = source[/^#if !__has_feature\(ptrauth_calls\)[^\n]*\n__attribute__\(\(target\("arch=armv8\.3-a"\)\)\)\n#endif\nuint64_t MachOLoaded::ChainedFixupPointerOnDisk::Arm64e::signPointer\(uint64_t unsignedAddr.*?^\}\n/m]
    abort 'signPointer not found in dyld3/MachOLoaded.cpp' unless text
    text
  end

  def self.pac_host?
    require 'rbconfig'
    hwcap = File.binread('/proc/self/auxv').unpack('Q*').each_slice(2).find { |type, _| type == 16 }&.last.to_i
    RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/ && (hwcap & HWCAP_PACA) != 0 && system('clang++', '--version', out: File::NULL, err: File::NULL)
  end

  # Builds `driver` (a .cpp path) with the module. adapters_text, rows_text and reverse_rows_text replace the module source or a
  # table for a mutant.
  # Returns [executable or nil, compiler messages].
  def self.build(root, dir, name, driver, adapters_text: nil, rows_text: nil, reverse_rows_text: nil)
    work = File.join(dir, name)
    FileUtils.mkdir_p(File.join(work, 'mach'))
    File.write(File.join(work, 'MachOLoaded.h'), SHIM_LOADED)
    File.write(File.join(work, 'mach', 'machine.h'), SHIM_MACHINE)
    FileUtils.cp(File.join(root, 'dyld3/DarlingArm64eAdapters.h'), work)
    File.write(File.join(work, 'DarlingArm64eAdapterRows.inc'), rows_text || File.read(File.join(root, 'dyld3/DarlingArm64eAdapterRows.inc')))
    File.write(File.join(work, 'DarlingArm64eReverseRows.inc'), reverse_rows_text || File.read(File.join(root, 'dyld3/DarlingArm64eReverseRows.inc')))
    File.write(File.join(work, 'DarlingArm64eAdapters.cpp'), adapters_text || File.read(File.join(root, 'dyld3/DarlingArm64eAdapters.cpp')))
    File.write(File.join(work, 'sign.cpp'), "#include <stdint.h>\n#include <assert.h>\n#include \"MachOLoaded.h\"\nusing namespace dyld3;\n#{extract_sign_pointer(File.read(File.join(root, 'dyld3/MachOLoaded.cpp')))}")
    exe = File.join(work, 'host')
    _o, e, st = Open3.capture3('clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wno-unused-function', '-I', work, driver,
                               File.join(work, 'DarlingArm64eAdapters.cpp'), File.join(work, 'sign.cpp'), '-o', exe)
    [st.success? ? exe : nil, e]
  end

  # a mutant that hangs counts as caught: the status is then not a success
  def self.run(exe, *args)
    o, e, st = Open3.capture3('timeout', '20', exe, *args)
    [o + e, st]
  end
end
