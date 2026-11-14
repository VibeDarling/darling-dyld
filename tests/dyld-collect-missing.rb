# DARLING_DYLD_COLLECT_MISSING: the recorder, the thunks and the guard region of dyld3/DarlingCollectMissing.cpp, compiled
# natively and run on an ARM64 Linux host (the thunks are real instructions, entered and, for the arm64e call sequence,
# called through a signed pointer with blraaz). Not the Mach-O loader: the hooks in src/ImageLoaderMachOCompressed.cpp and
# src/dyld2.cpp are proven by the guest fixture tests/collect-missing-guest.c (see tests/README-collect-missing.md).
# Each probe edits a scratch copy of the source and must make the checks fail.
# usage: ruby tests/dyld-collect-missing.rb [checkout] [--no-probes]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'rbconfig'

root = File.realpath(ARGV.reject { |a| a.start_with?('--') }.fetch(0, File.expand_path('..', __dir__)))
abort 'needs an ARM64 host' unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/

SOURCE = 'dyld3/DarlingCollectMissing.cpp'.freeze

# What each probe changes and why the checks have to notice.
PROBES = [
  ['a weak import gets a thunk like a strong one', "\tif ( !import.weak ) {\n\t\tconst bool data", "\tif ( true ) {\n\t\tconst bool data"],
  ['no deduplication of lines', "\tmapInsert(sLines, key, 0, found);\n\tfree(key);\n\tif ( found )", "\tmapInsert(sLines, key, 0, found);\n\tfree(key);\n\tif ( false )"],
  ['every thunk loads slot 0', '0xD2800000u | (slot << 5)', '0xD2800000u'],
  ['the thunk region stays writable and executable', 'PROT_READ | PROT_EXEC', 'PROT_READ | PROT_WRITE | PROT_EXEC'],
  ['the guard region is readable', 'mmap(nullptr, kGuardRegionBytes, PROT_NONE,', 'mmap(nullptr, kGuardRegionBytes, PROT_READ | PROT_WRITE,'],
  ['no k-constant is data', "(symbol[1] == 'k')", "(symbol[1] == '#')"],
  ['a lazy bind of a data-looking name is still data', '(import.kind != BindKind::Lazy) && collectMissingNameLooksLikeData', 'collectMissingNameLooksLikeData'],
  ['enabled without a path', 'return sOutputPath != nullptr;', 'return true;'],
  ['the trap does not name the symbol', "\tn = appendStr(msg, n, symbol);\n", ''],
  ['an address in a record line', "\tsize_t n = appendStr(line, 0, import.referrer);", "\tsize_t n = appendHex(line, 0, 4096);\n\tn = appendStr(line, n, import.referrer);"],
  ['functions bound to the guard region', 'address = data ? newGuard(import) : newThunk(import);', 'address = newGuard(import);'],
  ['the output file is not close-on-exec', 'O_APPEND | O_CLOEXEC | O_NOFOLLOW', 'O_APPEND | O_NOFOLLOW'],
  ['the output file follows symlinks', 'O_APPEND | O_CLOEXEC | O_NOFOLLOW', 'O_APPEND | O_CLOEXEC'],
  ['an unopenable output file is ignored', "\t\tdyld::halt(\"DARLING_DYLD_COLLECT_MISSING: cannot open the output file\");", "\t\treturn;"],
  ['a short write is ignored', 'if ( (written < 0) || ((size_t)written != length) )', 'if ( written < 0 )'],
  ['no deduplication of guard slots', "\tconst uint32_t slot = mapInsert(sGuardMap, import.symbol, (uint32_t)sGuardCount, found);", "\tfound = false;\n\tconst uint32_t slot = (uint32_t)sGuardCount;"],
  ['every guard at slot 0', 'return (uintptr_t)(sGuards + kStride * slot);', 'return (uintptr_t)sGuards;'],
  ['a negative ordinal loses its sign', "\t\tline[n++] = '-';\n", ''],
  ['the function cap is off by one', 'if ( sThunkCount == kSlotsPerKind )', 'if ( sThunkCount > kSlotsPerKind )'],
  ['the guard cap is off by one', 'if ( sGuardCount == kSlotsPerKind )', 'if ( sGuardCount > kSlotsPerKind )'],
  ['the trap reads any slot', '(slot < sThunkCount) ? &sThunkSlots[slot] : nullptr', '&sThunkSlots[slot]'],
].freeze

def build_and_run(root, dir, name, source_text)
  work = File.join(dir, name)
  FileUtils.mkdir_p(work)
  File.write(File.join(work, 'DarlingCollectMissing.cpp'), source_text)
  exe = File.join(work, 'host')
  out, st = Open3.capture2e('clang++', '-std=gnu++17', '-Wall', '-Wno-unused-function', '-march=armv8.3-a',
                            '-I', "#{root}/dyld3", "#{root}/tests/dyld-collect-missing-host.cpp",
                            File.join(work, 'DarlingCollectMissing.cpp'), '-o', exe)
  return [:build_failed, out] unless st.success?
  out, st = Open3.capture2e('timeout', '120', exe, File.join(work, 'list.txt'), chdir: work)
  [st.success? && out.include?('RESULT ok') ? :pass : :fail, out]
end

original = File.read("#{root}/#{SOURCE}")
failed = false
Dir.mktmpdir('collect-missing-') do |dir|
  status, out = build_and_run(root, dir, 'base', original)
  puts out.lines.grep(/^(CHECK|FAIL|RESULT)/).join
  if status != :pass
    puts "FAIL: the unmodified source does not pass (#{status})"
    puts out unless out.include?('RESULT')
    exit 1
  end
  puts 'PASS dyld-collect-missing checks'
  unless ARGV.include?('--no-probes')
    PROBES.each_with_index do |(why, from, to), i|
      abort "probe '#{why}' does not apply: the text it replaces is gone" unless original.include?(from)
      status, = build_and_run(root, dir, "probe#{i}", original.gsub(from) { to })
      if status == :pass
        puts "FAIL probe survived: #{why}"
        failed = true
      else
        puts "ok probe caught (#{status}): #{why}"
      end
    end
  end
end
exit(failed ? 1 : 0)
