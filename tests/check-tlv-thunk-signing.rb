# The TLV thunk that libdyld stores into the descriptors of an arm64e image (src/threadLocalVariables.c): signed with key IA
# and discriminator 0, which is what the blraaz of an arm64e thread-local access authenticates, and left as it was for every
# other image. The extracted code runs natively on an ARM64 Linux host with pointer authentication; the oracle is the arm64e
# call sequence itself, executed against what the code stored. Not a Mach-O loader; see tests/README-cache-tlv.md.
# usage: ruby tests/check-tlv-thunk-signing.rb [checkout] [--no-probes]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'rbconfig'

root = File.realpath(ARGV.reject { |a| a.start_with?('--') }.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/src/threadLocalVariables.c")
priv_header = File.read("#{root}/include/mach-o/dyld_priv.h")

def extract(source, signature)
  source[/^static [^\n]*\b#{signature}\(.*?^\}/m] or abort "#{signature} not found as a static function"
end

FUNCTIONS = %w[dyld_header_is_arm64e tlv_thunk_for_image tlv_normalize_descriptor tlv_storage_size tlv_initialize_descriptors].freeze

abort 'needs an ARM64 host' unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/

# What each probe changes in the extracted code, and why the checks have to notice.
PROBES = [
  ['arm64e image left unsigned (the original bug)', 'd->thunk = (void* (*)(TLVDescriptor*))thunk;', 'd->thunk = tlv_get_addr;'],
  ['thunk of an arm64e image never signed', 'hint #8', 'nop'],
  ['key IB instead of IA', 'hint #8', 'hint #10'],
  ['discriminator 1', 'discriminator __asm__("x16") = 0;', 'discriminator __asm__("x16") = 1;'],
  ['address diversity', 'discriminator __asm__("x16") = 0;', 'discriminator __asm__("x16") = (uint64_t)mh;'],
  ['the flag bits of the subtype not masked', '(header->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E', 'header->cpusubtype == CPU_SUBTYPE_ARM64E'],
  ['cputype not checked', '(header->cputype == CPU_TYPE_ARM64) && ', ''],
  ['every image signed', '(header->cputype == CPU_TYPE_ARM64) && ((header->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E)', 'true'],
  ['a different function signed', '(uint64_t)tlv_get_addr;', '(uint64_t)tlv_free;'],
  ['only the first descriptor given the thunk', 'for (TLVDescriptor* d=start; d < end; ++d) {', 'for (TLVDescriptor* d=start; d < start + 1; ++d) {'],
  ['unsigned result returned after signing', 'return (void*)value;', 'return (void*)tlv_get_addr;'],
].freeze

def build_and_run(root, dir, name, extracted, defines)
  work = File.join(dir, name)
  FileUtils.mkdir_p(work)
  File.write(File.join(work, 'extracted.inc'), extracted)
  exe = File.join(work, 'host')
  out, st = Open3.capture2e('clang', '-std=gnu11', '-Wall', '-Wno-unused-function', '-march=armv8.3-a', *defines, '-I', work,
                            "#{root}/tests/tlv-thunk-signing-host.c", '-o', exe, '-lpthread')
  return [:build_failed, out] unless st.success?
  out, st = Open3.capture2e('timeout', '60', exe)
  return [:skipped, out] if st.exitstatus == 77
  [st.success? && out.include?('RESULT ok') ? :pass : :fail, out]
end

Dir.mktmpdir('tlv-thunk-signing-') do |dir|
  extracted = FUNCTIONS.map { |f| extract(f == 'dyld_header_is_arm64e' ? priv_header : source, f) }.join("\n\n")
  # libdyld is built for arm64 (__arm64__ is Apple's spelling); the second build is what any other architecture compiles.
  variants = { 'arm64-O0' => ['-O0', '-D__arm64__=1'], 'arm64-O2' => ['-O2', '-D__arm64__=1'], 'other-arch' => ['-O1'] }
  variants.each do |name, defines|
    verdict, out = build_and_run(root, dir, name, extracted, defines)
    abort 'needs a host with pointer authentication' if verdict == :skipped
    puts out unless verdict == :pass
    abort "#{name}: #{verdict}" unless verdict == :pass
    puts "ok   #{name}: #{out[/RESULT \w+/]}"
  end
  next if ARGV.include?('--no-probes')

  killed = 0
  PROBES.each_with_index do |(name, from, to), i|
    abort "probe text not found exactly once: #{name}" unless extracted.scan(from).size == 1
    mutant = extracted.sub(from, to)
    results = variants.reject { |n, _| n == 'other-arch' }.map { |n, d| build_and_run(root, dir, "p#{i}-#{n}", mutant, d)[0] }
    if results.include?(:build_failed)
      puts "FAIL probe #{name}: the mutant does not build"
      next
    end
    if results.all? { |r| r == :fail }
      killed += 1
      puts "ok   probe killed: #{name}"
    else
      puts "FAIL probe survived: #{name} (#{results.join(', ')})"
    end
  end
  abort "probes: #{killed}/#{PROBES.size} killed" unless killed == PROBES.size
  puts "PASS TLV thunk signing: 3 builds, #{killed}/#{PROBES.size} probes killed"
end
