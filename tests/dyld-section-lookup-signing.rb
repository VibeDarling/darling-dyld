# What dyld stores into the __dyld section of libdyld (setDyldFuncLookup in src/ImageLoaderMachO.cpp): for an arm64e image a pointer
# signed IA, discriminator 0 (the blraaz in arm64e libdyld's __dyld_func_lookup) to a wrapper that signs the address the lookup
# returns IA, discriminator 0 (the autiza that follows), and the raw function for every other image. The extracted code runs natively on an ARM64 Linux host with pointer
# authentication; the oracle is the arm64e call sequence itself. Not a Mach-O loader.
# usage: ruby tests/dyld-section-lookup-signing.rb [checkout] [--no-probes]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'rbconfig'

root = File.realpath(ARGV.reject { |a| a.start_with?('--') }.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/src/ImageLoaderMachO.cpp")
FUNCTIONS = %w[signForArm64eLibdyld dyldFuncLookupSigned dyldFuncLookupForImage setDyldFuncLookup].freeze
extracted = ([source[/^struct DATAdyld \{.*?^\};/m] || abort('struct DATAdyld missing in src/ImageLoaderMachO.cpp')] +
             FUNCTIONS.map { |f| source[/^static [^\n]*\b#{f}\(.*?^\}/m] || abort("#{f} missing in src/ImageLoaderMachO.cpp") }).join("\n\n")
# The wiring: setupLazyPointerHandler reaches the slot only through setDyldFuncLookup, with the image's own header and the section's size.
def wired?(text)
  text.scan('setDyldFuncLookup(dd, sect->size, mh);').size == 1 && text.scan(/dd->dyldFuncLookup\s*=/).size == 1
end
abort 'setupLazyPointerHandler does not store the lookup through setDyldFuncLookup(dd, sect->size, mh)' unless wired?(source)

unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/ && system('clang++', '--version', out: File::NULL, err: File::NULL)
  puts 'SKIP dyld-section-lookup-signing: needs an ARM64 host and clang++'
  exit 0
end

SHIM_MACHINE = <<~H
  #pragma once
  #include <stdint.h>
  typedef int cpu_subtype_t;
  #define CPU_TYPE_ARM64 ((int32_t)0x0100000c)
  #define CPU_SUBTYPE_MASK 0xff000000
  #define CPU_SUBTYPE_ARM64E ((cpu_subtype_t) 2)
H

PROBES = [
  ['the stored pointer is not signed (the original bug)', 'return signForArm64eLibdyld((void*)&dyldFuncLookupSigned);', 'return (void*)&dyldFuncLookupSigned;'],
  ['the stored pointer is the raw lookup, whose result is not signed', 'return signForArm64eLibdyld((void*)&dyldFuncLookupSigned);', 'return signForArm64eLibdyld((void*)&_dyld_func_lookup);'],
  ['the wrapper does not sign its result', '*address = signForArm64eLibdyld(*address);', ';'],
  ['the wrapper signs a NULL result too', 'if ( *address != NULL )', 'if ( true )'],
  ['the wrapper drops the lookup\'s answer', 'return found;', 'return 1;'],
  ['key IB instead of IA', 'hint #8', 'hint #10'],
  ['no signature at all', 'hint #8', 'nop'],
  ['discriminator 1', 'discriminator __asm__("x16") = 0;', 'discriminator __asm__("x16") = 1;'],
  ['address diversity', 'discriminator __asm__("x16") = 0;', 'discriminator __asm__("x16") = (uint64_t)&value;'],
  ['the flag bits of the subtype not masked', 'dyld3::darling::cpusubtypeIsArm64e(mh->cpusubtype)', '(mh->cpusubtype == CPU_SUBTYPE_ARM64E)'],
  ['cputype not checked', '(mh->cputype == CPU_TYPE_ARM64) && ', ''],
  ['every image gets the wrapper', '(mh->cputype == CPU_TYPE_ARM64) && dyld3::darling::cpusubtypeIsArm64e(mh->cpusubtype)', 'true'],
  ['the slot is written past a short section', 'if ( sectionSize > offsetof(DATAdyld, dyldFuncLookup) ) {', 'if ( true ) {'],
  ['the slot is not written', 'dd->dyldFuncLookup = lookup;', ';'],
].freeze

# probes on the source text outside the extracted code: the call site of the real loader
SOURCE_PROBES = [
  ['the call site stores the raw lookup', 'setDyldFuncLookup(dd, sect->size, mh);', 'dd->dyldFuncLookup = (void*)&_dyld_func_lookup;'],
  ['the call site is for another header', 'setDyldFuncLookup(dd, sect->size, mh);', 'setDyldFuncLookup(dd, sect->size, NULL);'],
].freeze

def build_and_run(root, dir, name, extracted, optimize)
  work = File.join(dir, name)
  FileUtils.mkdir_p(File.join(work, 'mach'))
  File.write(File.join(work, 'mach/machine.h'), SHIM_MACHINE)
  File.write(File.join(work, 'extracted.inc'), extracted)
  exe = File.join(work, 'host')
  out, st = Open3.capture2e('clang++', '-std=gnu++14', '-Wall', '-Wno-unused-function', '-Wno-deprecated-register', '-march=armv8.3-a', optimize,
                            '-D__arm64__=1', '-I', work, '-I', "#{root}/dyld3", "#{root}/tests/dyld-section-lookup-host.cpp", '-o', exe)
  return [:build_failed, out] unless st.success?
  out, st = Open3.capture2e('timeout', '60', exe)
  return [:skipped, out] if st.exitstatus == 77
  [st.success? && out.include?('RESULT ok') ? :pass : :fail, out]
end

Dir.mktmpdir('dyld-section-lookup-') do |dir|
  variants = { 'O0' => '-O0', 'O2' => '-O2' }
  variants.each do |name, flag|
    verdict, out = build_and_run(root, dir, name, extracted, flag)
    abort 'needs a host with pointer authentication' if verdict == :skipped
    puts out unless verdict == :pass
    abort "#{name}: #{verdict}" unless verdict == :pass
    puts "ok   #{name}: #{out[/RESULT \w+/]}"
  end
  next if ARGV.include?('--no-probes')

  killed = 0
  PROBES.each_with_index do |(name, from, to), i|
    abort "probe text not found exactly once: #{name}" unless extracted.scan(from).size == 1
    mutant = extracted.sub(from) { to }
    results = variants.map { |n, flag| build_and_run(root, dir, "p#{i}-#{n}", mutant, flag)[0] }
    if results.include?(:build_failed)
      puts "FAIL probe #{name}: the mutant does not build"
    elsif results.all? { |r| r == :fail }
      killed += 1
      puts "ok   probe killed: #{name}"
    else
      puts "FAIL probe survived: #{name} (#{results.join(', ')})"
    end
  end
  SOURCE_PROBES.each do |name, from, to|
    abort "probe text not found exactly once: #{name}" unless source.scan(from).size == 1
    if wired?(source.sub(from) { to })
      puts "FAIL probe survived: #{name}"
    else
      killed += 1
      puts "ok   probe killed: #{name}"
    end
  end
  total = PROBES.size + SOURCE_PROBES.size
  abort "probes: #{killed}/#{total} killed" unless killed == total
  puts "PASS dyld section lookup signing: 2 builds, #{killed}/#{total} probes killed"
end
