# Execute the actual registration method with controlled segments/remap calls.
# Usage: ruby tests/encryption-registration.rb [ImageLoaderMachOCompressed.cpp]
require 'tmpdir'
require 'open3'
source = File.read(ARGV[0] || File.expand_path('../src/ImageLoaderMachOCompressed.cpp', __dir__))
method = source[/void ImageLoaderMachOCompressed::registerEncryption\(.*?\n\}/m]
abort 'registration method missing' unless method
program = <<~'CPP'
  #include <cassert>
  #include <cstdint>
  #include <cstddef>
  #include <cerrno>
  struct encryption_info_command { uint32_t cryptoff, cryptsize, cryptid; };
  struct mach_header { uint32_t cputype, cpusubtype; };
  struct LinkContext { bool verboseMapping; };
  static unsigned calls;
  static int remapResult;
  static void *seenStart;
  static size_t seenLength;
  static uint32_t seenID, seenCPU, seenSubtype;
  int mremap_encrypted(void *start, size_t length, uint32_t id, uint32_t cpu, uint32_t subtype) {
    ++calls; seenStart=start; seenLength=length; seenID=id; seenCPU=cpu; seenSubtype=subtype;
    return remapResult;
  }
  namespace dyld {
    void log(const char *, ...) {}
    void throwf(const char *, ...) { throw 42; }
  }
  class ImageLoaderMachOCompressed {
  public:
    unsigned fSegmentsCount = 2;
    alignas(mach_header) unsigned char bytes[128] = {};
    size_t segFileOffset(unsigned i) { return i == 0 ? 64 : 0; }
    size_t segFileSize(unsigned) { return sizeof(bytes); }
    uintptr_t segActualLoadAddress(unsigned) { return reinterpret_cast<uintptr_t>(bytes); }
    const char *getPath() { return "fixture"; }
    void registerEncryption(const encryption_info_command *, const LinkContext &);
  };
CPP
program += method
program += <<~'CPP'
  int main() {
    ImageLoaderMachOCompressed image;
    auto *header = reinterpret_cast<mach_header *>(image.bytes);
    header->cputype = 123; header->cpusubtype = 456;
    LinkContext context{true};
    image.registerEncryption(nullptr, context); assert(calls == 0);
    encryption_info_command command{32, 16, 0};
    remapResult = -1;
  #ifdef DARLING
    image.registerEncryption(&command, context); assert(calls == 0);
  #else
    bool zeroThrew = false;
    try { image.registerEncryption(&command, context); } catch (int) { zeroThrew = true; }
    assert(zeroThrew && calls == 1 && seenID == 0);
  #endif
    calls = 0; command.cryptid = 1;
    bool threw = false;
    try { image.registerEncryption(&command, context); } catch (int) { threw = true; }
    assert(threw && calls == 1 && seenID == 1);
    assert(seenStart == image.bytes+32 && seenLength == 16 && seenCPU == 123 && seenSubtype == 456);
    remapResult = 0;
    image.registerEncryption(&command, context); assert(calls == 2);
    image.fSegmentsCount = 0;
    image.registerEncryption(&command, context); assert(calls == 2);
  }
CPP
Dir.mktmpdir('dyld-encryption') do |dir|
  input = "#{dir}/probe.cpp"; output = "#{dir}/probe"
  File.write(input, program)
  [[], ['-DDARLING']].each do |flags|
    log, status = Open3.capture2e('clang++', '-std=c++11', '-D__arm64__=1', '-DTARGET_OS_SIMULATOR=0', *flags, input, '-o', output)
    abort log unless status.success?
    abort 'registration probe failed' unless system(output, rlimit_core: 0)
  end
end
puts 'PASS: Darling and non-Darling registration, absent command, zero/nonzero cryptid, remap failure and success'
