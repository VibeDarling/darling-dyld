#!/usr/bin/env ruby
# Host-side test of the L5 test: source bookkeeping, the native run of the harness (which validates the
# verdict rules and the hash gate), and the structure of the built arm64e executable. Nothing Mach-O is
# executed (the host cannot run it); the guest results belong in README.md.
# Usage: LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/Darling/MacOSX.sdk \
#          [PREFIX=/path/to/private/prefix] ruby tests/arm64e-link/l5/arm64e-l5-probe.rb
# The native part needs only clang; the Mach-O part SKIPs without LD64 and SDKROOT.
require 'fileutils'
require 'tmpdir'
require 'open3'

HERE = __dir__
LD64 = ENV['LD64'].to_s
SDKROOT = ENV['SDKROOT'].to_s
PREFIX = ENV['PREFIX'].to_s
$failures = 0

def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

def py(*args, env: {})
  Open3.capture3(env, 'python3', '-I', *args)
end

BUILD = File.join(HERE, 'build_l5.py')
SRC = File.read(File.join(HERE, 'l5_test.c'))
DECL = File.read(File.join(HERE, 'l5_decl.h'))
IMPORTS = File.readlines(File.join(HERE, 'l5_imports.txt')).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }

# ---------------------------------------------------------------- source bookkeeping
table = SRC[/const struct check checks\[\] = \{(.*?)\n\};/m, 1].to_s
rows = table.scan(/\{"(check\d\d_\w+)", (l5_check\d\d), 0\}/)
check 'the check table lists eight checks, 01..08 in order',
      rows.size == 8 && rows.map(&:first) == %w[check01_served check02_getclass check03_createinstance
                                                 check04_msgsend check05_subclass check06_apis
                                                 check07_callbacks check08_dispose], rows.inspect
rows.each_with_index do |(name, fn), i|
  n = format('%02d', i + 1)
  body = SRC[/^static int #{fn}\(void\) \{.*?^\}/m].to_s
  check "check #{n} (#{name}) prints exactly one OKMARK #{n} line, after at least one l5_fail path",
        body.scan(/OKMARK #{n} /).size == 1 && (body.index('l5_fail(') || body.size) < body.index("OKMARK #{n} "), fn
  check "check #{n} has a native stub that fails instead of passing", SRC.include?(
    "static int #{fn}(void) { return l5_fail(\"guest-only check\"); }")
end
%w[check02_getclass check03_createinstance].each do |name|
  fn = "l5_check#{name[/\d+/]}"
  body = SRC[/^static int #{fn}\(void\) \{.*?^\}/m].to_s
  check "#{name} reads the isa with object_getClass and never dereferences the object (arm64e isas are not plain Class pointers)",
        body.include?('object_getClass(') && !body.match?(/\*\(void \*\*\)/), body.scan(/\*\(void \*\*\)\w+/).inspect
end
selftests = SRC[/const struct check l5_selftests\[\] = \{(.*?)\n\};/m, 1].to_s
st = selftests.scan(/\{"(l5_selftest_\w+)", (l5_st_\w+), "(\w+)"\}/).map { |n, _f, e| [n, e] }
expected_st = [%w[l5_selftest_ok ok], %w[l5_selftest_failed failed],
               %w[l5_selftest_exit0_without_mark failed], %w[l5_selftest_hang hung],
               %w[l5_selftest_fault faulted], %w[l5_selftest_hash_ok ok],
               %w[l5_selftest_hash_rejects_skew ok], %w[l5_selftest_policy_line ok], %w[l5_selftest_objc_lines ok],
               %w[l5_selftest_mark_match ok], %w[l5_selftest_double_mark failed]]
check 'the selftests cover every verdict class and the double-mark and hash rules, with their expected verdicts',
      st == expected_st, st.inspect
check 'every name in l5_imports.txt is declared in l5_decl.h',
      IMPORTS.all? { |n| DECL.match?(/\b#{Regexp.escape(n)}\s*\(/) },
      IMPORTS.reject { |n| DECL.match?(/\b#{Regexp.escape(n)}\s*\(/) }.inspect
SPIS = %w[_dyld_objc_class_count _dyld_get_dlopen_image_header _dyld_objc_register_callbacks
        _dyld_lookup_section_info _dyld_for_objc_header_opt_rw _dyld_for_objc_header_opt_ro]
check 'l5_imports.txt names none of the dyld4 objc SPIs (they are imported from libSystem)',
      (IMPORTS & SPIS).empty?, (IMPORTS & SPIS).inspect
check 'check 07 observes libobjc\'s registration through the loader log: the test never registers callbacks of its own',
      !SRC.include?('_dyld_objc_register_callbacks') && !DECL.include?('_dyld_objc_register_callbacks') &&
      %w[objc\ register_callbacks\ version= objc\ mapped\  objc\ init\ ].all? { |t| SRC.include?(t) } &&
      SRC[/^static int l5_check07\(void\) \{.*?^\}/m].to_s.include?('loader=?')
sources = %w[l5_test.c l5_decl.h l5_imports.txt build_l5.py].map { |f| File.read(File.join(HERE, f)) }
check 'no home path or user name in the l5 sources',
      sources.none? { |t| t.match?(%r{/home/|/Users/}) }
check 'the driver takes check 01\'s policy from the loader line, not from a file',
      SRC.include?('cache load source /usr/lib/libobjc.A.dylib: policy=') && !SRC.match?(/policy.*File|fopen.*policy/)

# ---------------------------------------------------------------- the guest runner
Dir.mktmpdir('l5-runner-') do |dir|
  FileUtils.mkdir_p([File.join(dir, 'l5'), File.join(dir, 'abi'), File.join(dir, 'probe'), File.join(dir, 'cache')])
  FileUtils.cp(File.join(HERE, 'run_l5.sh'), File.join(dir, 'l5', 'run_l5.sh'))
  stub = File.join(dir, 'abi', 'run_guest.sh')
  File.write(stub, "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$STUB_OUT\"\nenv >> \"$STUB_OUT.env\"\n")
  File.chmod(0o755, stub)
  env = { 'DARLING_GUEST_BUILD' => 'x', 'PROBE_DIR' => File.join(dir, 'probe'), 'CACHE_DIR' => File.join(dir, 'cache'),
          'STUB_OUT' => File.join(dir, 'stub.out') }
  _o, e, st = Open3.capture3(env, 'bash', File.join(dir, 'l5', 'run_l5.sh'), 'l5-', '1', '1')
  guest = File.exist?(env['STUB_OUT']) ? File.read(env['STUB_OUT']) : ''
  launcher_env = File.exist?(env['STUB_OUT'] + '.env') ? File.read(env['STUB_OUT'] + '.env') : ''
  check 'run_l5.sh runs against a stub launcher (Darling is not booted)', st.success? && !guest.empty?, e[0, 200]
  c3 = guest[/CONFIG c3; (.*?)"\$E"/m, 1].to_s
  check 'the c3 guest command sets the cache variable, DYLD_PRINT_OBJC_NOTIFICATIONS=1 and DARLING_DYLD_POLICY_LOG=1',
        c3.include?('DYLD_PRINT_OBJC_NOTIFICATIONS=1') && c3.include?('DARLING_DYLD_POLICY_LOG=1') &&
        c3.include?('DYLD_SHARED_CACHE_SPLIT_DIR='), c3
  c1 = guest[/CONFIG c1; (.*?); echo CONFIG selftest/m, 1]
  st = guest[/CONFIG selftest; (.*)/m, 1]
  check 'the c1 and selftest commands are present and set no DYLD variable',
        !c1.nil? && !st.nil? && !c1.include?('DYLD_') && !st.include?('DYLD_') && !guest.split('CONFIG c3').first.include?('DYLD_'),
        [c1, st].inspect
  check 'no DYLD variable reaches the launcher environment', !launcher_env.include?('DYLD_PRINT_OBJC_NOTIFICATIONS') &&
        !launcher_env.include?('DARLING_DYLD_POLICY_LOG') && !launcher_env.include?('DYLD_SHARED_CACHE_SPLIT_DIR'), launcher_env.lines.grep(/DYLD_/).inspect
end

# ---------------------------------------------------------------- the native harness
Dir.mktmpdir('l5-native-') do |dir|
  bin = File.join(dir, 'l5_native')
  _o, e, st = py(BUILD, 'native', '--out', bin)
  check 'the native harness builds', st.success?, e[0, 300]
  next unless st.success?
  out, st = Open3.capture2e(bin, 'selftest')
  check 'the selftest set passes: every verdict class classified as expected, no mismatch',
        st.success? && out.include?('ok=6 not_ok=5 expect_mismatches=0'), out.lines.last
  out, st = Open3.capture2e(bin, 'selftest-wrong')
  check 'a wrong expected verdict makes the driver exit 1 with an EXPECT-MISMATCH',
        !st.success? && out.include?('EXPECT-MISMATCH expected=hung'), out.lines.grep(/MISMATCH/).first
  skew = File.join(dir, 'l5_native_skew')
  _o, e, st = py(BUILD, 'native', '--out', skew, '--hash-skew', '1')
  check 'the hash mutation builds', st.success?, e[0, 300]
  if st.success?
    out, st = Open3.capture2e(skew, 'selftest')
    line = out.lines.grep(/l5_selftest_hash_ok/)
    check 'the check-04 hash gate rejects a wrong expected value (the -DL5_HASH_SKEW mutation)',
          !st.success? && line.any? { |l| l.include?('verdict=failed') && l.include?('EXPECT-MISMATCH') }, line.first
  end
  anyp = File.join(dir, 'l5_native_policy_any')
  _o, e, st = py(BUILD, 'native', '--out', anyp, '--policy-any')
  check 'the policy mutation builds', st.success?, e[0, 300]
  if st.success?
    out, st = Open3.capture2e(anyp, 'selftest')
    line = out.lines.grep(/l5_selftest_policy_line/)
    check 'check 01 rejects a libobjc policy other than cache (the -DL5_POLICY_ANY mutation accepting any source is killed)',
          !st.success? && line.any? { |l| l.include?('verdict=failed') && l.include?('EXPECT-MISMATCH') }, line.first
  end
  rows.each_with_index do |(name, _fn), i|
    n = i + 1
    out, st = Open3.capture2e(bin, 'run', n.to_s)
    check "check #{name} is guest-only: its native run exits 1 with FAILED check=#{format('%02d', n)}",
          !st.success? && out.include?("FAILED check=#{format('%02d', n)} reason=guest-only check"), out[0, 160]
  end
end

# ---------------------------------------------------------------- the fault handler's signature
# dyld's arm64e adapters wrap every plain export an arm64e image binds (with or without the cache): an
# unsigned sigaction handler becomes a poisoned pointer and the first fault hangs. The arm64e build must
# therefore hand sigaction the pointer exactly as the compiler signed it. Checked on the compiled
# assembly: every place the code takes l5_on_fault's address signs it (paciza) and never strips it
# (xpaci) before the next unrelated instruction.
def handler_signature_problems(asm)
  lines = asm.lines
  sites = lines.each_index.select { |i| lines[i].match?(/adrp\s+x\d+, _l5_on_fault@PAGE/) }
  return ['no code takes the address of l5_on_fault'] if sites.empty?
  sites.flat_map do |i|
    reg = lines[i][/adrp\s+(x\d+),/, 1]
    at = "asm line #{i + 1}"
    # the compiler emits the address and its signature back to back: adrp, add, paciza on one register
    unless lines[i + 1].to_s.match?(/\badd\s+#{reg}, #{reg}, _l5_on_fault@PAGEOFF/) && lines[i + 2].to_s.match?(/\bpaciza\s+#{reg}\b/)
      next ["the address of l5_on_fault is not signed right after it is formed (#{at})"]
    end
    problem = nil
    stored = false
    lines[(i + 3)..(i + 16)].to_a.each do |l|
      if l.match?(/\bxpaci\s+#{reg}\b/)
        problem = "the handler is stripped (xpaci #{reg}) before it is stored (#{at})"
        break
      elsif l.match?(/\bst[pr]\s+#{reg}\b/)
        stored = true
        break
      elsif l.match?(/^\s*(?!cmp|cmn|tst|cbz|cbnz|b\.|stp|str)\w+\s+#{reg}\b/)
        problem = "the signed handler register #{reg} is overwritten before the store (#{at}): #{l.strip}"
        break
      end
    end
    problem ||= "the signed l5_on_fault in #{reg} is never stored (#{at})" unless stored
    [problem].compact
  end
end

if SDKROOT.empty?
  puts 'SKIP the fault-handler signature check: set SDKROOT'
else
  Dir.mktmpdir('l5-sig-') do |dir|
    o, e, st = py('-c', "import sys; sys.path.insert(0, #{HERE.inspect}); import build_l5; " \
                        "print('\\n'.join(build_l5.cflags(sys.argv[1])))", SDKROOT)
    check 'the build flags are readable from build_l5.cflags', st.success? && !o.empty?, e[0, 300]
    next unless st.success?
    flags = o.lines.map(&:chomp)
    asm_of = lambda do |text, name|
      src = File.join(dir, "#{name}.c")
      File.write(src, text)
      out = File.join(dir, "#{name}.s")
      _o, err, ok = Open3.capture3('clang', '--target=arm64e-apple-macos13', '-S', '-I', HERE, *flags, src, '-o', out)
      ok.success? ? File.read(out) : (puts "FAIL compile #{name}: #{err[0, 300]}"; $failures += 1; nil)
    end
    good = asm_of.call(SRC, 'l5_signed')
    if good
      check 'the arm64e build hands sigaction the signed handler: paciza, no xpaci, at every use',
            handler_signature_problems(good).empty?, handler_signature_problems(good).inspect
      check 'the handler does not depend on PROBE_CONFIG', !SRC[/static void l5_install_handlers.*?^\}/m].to_s.include?('PROBE_CONFIG')
    end
    stripped_src = SRC.sub('sa.handler = (void *)l5_on_fault;', 'sa.handler = STRIP((void *)l5_on_fault);')
    check 'the mutation source differs (the stripped handler is really injected)', stripped_src != SRC
    mut = asm_of.call(stripped_src, 'l5_stripped')
    check 'a stripped handler (the pre-fix code) is rejected by the signature check',
          !mut.nil? && handler_signature_problems(mut).any? { |p| p.include?('xpaci') }, mut && handler_signature_problems(mut).inspect
    if good
      store = good.lines.index { |l| l.match?(/\bstp\s+x16, x\d+, \[sp, #8\]/) }
      check 'the assembly has the handler store the mutations below rewrite', !store.nil?
      if store
        lines = good.lines
        after = lines.dup.insert(store, "\txpaci\tx16\n").join
        check 'a strip between the signing and the store is rejected',
              handler_signature_problems(after).any? { |p| p.include?('xpaci') }, handler_signature_problems(after).inspect
        sign = (0...store).to_a.reverse.find { |j| lines[j].match?(/\bpaciza\s+x16\b/) }
        dead = lines.dup.tap { |l| l[sign] = "\tpaciza\tx17\n" if sign }.join
        over = lines.dup.insert(store, "\tmov\tx16, x8\n").join
        check 'overwriting the signed register before the store is rejected',
              handler_signature_problems(over).any? { |p| p.include?('overwritten') }, handler_signature_problems(over).inspect
        check 'a signature on another register (the stored x16 stays unsigned) is rejected',
              handler_signature_problems(dead).any? { |p| p.include?('not signed right after') }, handler_signature_problems(dead).inspect
      end
    end
  end
end

# ---------------------------------------------------------------- the built probe
if LD64.empty? || SDKROOT.empty?
  puts 'SKIP the Mach-O part: set LD64 and SDKROOT'
else
  Dir.mktmpdir('l5-macho-') do |dir|
    outdir = File.join(dir, 'build')
    _o, e, st = py(BUILD, 'build', '--out', outdir, env: { 'LD64' => LD64, 'SDKROOT' => SDKROOT })
    check 'the probe builds and its structural checks pass', st.success?, (e + _o)[0, 400]
    next unless st.success?
    exe = File.join(outdir, 'l5_probe')
    check 'the build derives exactly the declared libobjc imports from the test\'s own undefined names',
          _o.match?(/imports: \d+ libSystem, #{IMPORTS.size} libobjc/), _o.lines.last
    subtype = File.binread(exe, 12)[8, 4].unpack1('V') & 0x00ffffff
    check 'the executable is arm64e (cpusubtype 2)', subtype == 2, format('0x%x', subtype)
    _o, _e, st = py(BUILD, 'check', exe, env: { 'LD64' => LD64, 'SDKROOT' => SDKROOT })
    check 'the standalone structural check passes on the built executable', st.success?, _o[0, 300]
    clean = File.join(dir, 'clean')
    FileUtils.mkdir_p(clean)
    _o, _e, st = py(BUILD, 'check', exe, '--prefix', clean, env: { 'LD64' => LD64, 'SDKROOT' => SDKROOT })
    check 'a prefix without a link-only stub passes the installed-stub scan', st.success?, _o[0, 300]
    planted = File.join(dir, 'planted', 'usr', 'lib')
    FileUtils.mkdir_p(planted)
    FileUtils.cp(File.join(outdir, 'stubs-arm64e', 'libobjc.A.linkonly.dylib'),
                 File.join(planted, 'libobjc.A.dylib'))
    _o, _e, st = py(BUILD, 'check', exe, '--prefix', File.join(dir, 'planted'),
                    env: { 'LD64' => LD64, 'SDKROOT' => SDKROOT })
    check 'a stub planted under the real libobjc name fails the scan (it is found by structure, not name)',
          !st.success? && _e.include?('under another name'), _e[0, 300]
    unless PREFIX.empty?
      _o, _e, st = py(BUILD, 'check', exe, '--prefix', PREFIX, env: { 'LD64' => LD64, 'SDKROOT' => SDKROOT })
      check "no link-only stub is installed in #{PREFIX}", st.success?, _o[0, 300]
    end
  end
end

puts($failures.zero? ? 'OK arm64e-l5-probe' : "FAILED arm64e-l5-probe: #{$failures}")
exit($failures.zero? ? 0 : 1)
