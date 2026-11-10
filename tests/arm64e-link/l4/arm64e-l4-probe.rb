# Host-side test of the L4 C++ test (plan rung L4): source bookkeeping, the native run of the same
# checks (validates the checks themselves), mutation probes of the checks and the harness, and the
# structure of the built arm64e executable and the plain arm64 control. Nothing Mach-O is executed
# (the host cannot run it); the guest results belong in README.md.
# Usage: LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/Darling/MacOSX.sdk \
#          LIBCXX_INCLUDE=/path/to/darling/src/external/libcxx/include \
#          [DARLING_USR_LIB=/path/to/prefix/libexec/darling/usr/lib] [CACHE_EXPORTS_DIR=/path/to/L4-facts-data] \
#          ruby tests/arm64e-link/l4/arm64e-l4-probe.rb
# The native part needs only clang and g++; the Mach-O part SKIPs without LD64, SDKROOT or LIBCXX_INCLUDE.
require 'json'
require 'tmpdir'
require 'open3'

HERE = __dir__
LD64 = ENV['LD64'].to_s
SDKROOT = ENV['SDKROOT'].to_s
LIBCXX_INCLUDE = ENV['LIBCXX_INCLUDE'].to_s
DARLING_USR_LIB = ENV['DARLING_USR_LIB'].to_s
CACHE_EXPORTS_DIR = ENV['CACHE_EXPORTS_DIR'].to_s
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

BUILD = File.join(HERE, 'build_l4.py')
MACHO_ENV = { 'LD64' => LD64, 'SDKROOT' => SDKROOT, 'LIBCXX_INCLUDE' => LIBCXX_INCLUDE }.freeze

have_native = %w[clang g++].all? { |t| system(t, '--version', out: File::NULL, err: File::NULL) }
unless have_native
  puts 'SKIP arm64e-l4-probe: clang and g++ must run'
  exit 0
end

# ---------------------------------------------------------------- source bookkeeping
src = File.read(File.join(HERE, 'l4_checks.cpp'))
table = src[/const struct check checks\[\] = \{(.*?)\n\};/m, 1].to_s
rows = table.scan(/\{"([a-z0-9_]+)", (\w+), ([A-Z_]+)((?: ";need=[^"]*")?)\}/)
names = rows.map(&:first)
EXPECTED_COUNT = 28
check "the check table lists #{EXPECTED_COUNT} checks with unique names", rows.size == EXPECTED_COUNT && names.uniq.size == EXPECTED_COUNT, rows.size
check 'checks are grouped q1..q6 in order and every Q4 group has a check',
      names.map { |n| n[/\Aq(\d)_/, 1].to_i } == names.map { |n| n[/\Aq(\d)_/, 1].to_i }.sort &&
      names.map { |n| n[/\Aq(\d)_/, 1] }.uniq == %w[1 2 3 4 5 6]
rows.each_with_index do |(name, fn, _exp, _need), i|
  body = src[/^int #{fn}\(\) \{.*?^\}/m].to_s
  # a check may report through a helper: the exit-path check from the atexit handler it registers first (it
  # runs last), the served-from-cache checks from the function that measures
  helper = { 'atexit_and_static_destructor' => 'void exit_first_registered', 'served_libcxx' => 'int served_by_cache',
             'served_cxa_throw' => 'int served_by_cache' }[fn]
  body += src[/^#{helper}\(.*?^\}/m].to_s if helper
  check "check #{i + 1} (#{name}) reports through PASS() or ok_mark(g_check)", body.match?(/PASS\(\)|ok_mark\(g_check\)/), fn
end
macros = src.scan(/^#define (EXP_\w+) "([^"]*)"/).to_h
check 'every expectation macro names c1, c2, c3 and native', macros.size >= 3 &&
      macros.values.all? { |v| %w[c1 c2 c3 native].all? { |c| v.include?("#{c}=") } }, macros.inspect
user_class = names.select { |n| n.include?('known_ld64_addend') }
check 'the checks that use typeinfo defined in this executable are named known_ld64_addend and expect "any" on arm64e',
      user_class.size == 4 && rows.select { |r| r[0].include?('known_ld64_addend') }.all? { |r| macros[r[2]].include?('c3=any') },
      user_class.inspect
check 'the not-from-cache checks expect failed (a recorded fact) without the cache and ok on the cache',
      rows.select { |r| r[0].start_with?('q1_') }.all? { |r| macros[r[2]].include?('c2=failed') && macros[r[2]].include?('c3=ok') }
check 'no std::sort of an arithmetic range (libc++ extern template; the cache lacks it, T0)', !src.match?(/std::(stable_)?sort/)
check 'no home path or user name in the sources',
      Dir[File.join(HERE, '*')].reject { |f| File.basename(f) == File.basename(__FILE__) }.none? { |f| File.file?(f) && File.read(f).match?(%r{/home/|/Users/}) }

# ---------------------------------------------------------------- native build and run
def run_native(exe, config, *args)
  o, e, st = Open3.capture3({ 'PROBE_CONFIG' => config }, exe, *args)
  [o + e, st.exitstatus]
end

def verdicts(out)
  out.scan(/^RESULT (\d+) (\S+) (ok|faulted|hung|failed)(.*)$/).to_h { |n, name, v, rest| [name, [v, rest]] }
end

Dir.mktmpdir('l4-probe-') do |tmp|
  native = File.join(tmp, 'l4native')
  _o, e, st = py(BUILD, 'native', '--out', native)
  check 'build_l4.py builds the native probe', st.success?, e[0, 500]
  unless st.success?
    puts "#{$failures} FAILED"
    exit 1
  end
  out, rc = run_native(native, 'native')
  base = verdicts(out)
  check 'the native run has one RESULT per check', base.size == EXPECTED_COUNT, base.size
  check 'native: every check is ok except the two served-from-cache checks, which record "not from cache"',
        base.reject { |n, _| n.start_with?('q1_') }.all? { |_, (v, _)| v == 'ok' } &&
        base.select { |n, _| n.start_with?('q1_') }.all? { |_, (v, r)| v == 'failed' && r.include?('expected_not_ok=failed') }, base.reject { |_, (v, _)| v == 'ok' }.keys.inspect
  check 'native: the run meets its table (expect_mismatches=0, exit 0)', out.include?('expect_mismatches=0') && rc.zero?, rc
  check 'native: the not-from-cache fact is printed with the image that served the function',
        out.scan(/^  \| FACT served .*in_cache=no/).size == 2
  check 'native: output the child cannot see itself is required (cout line, static dtor, exit flush)',
        %w[L4-COUT-LINE L4-STATIC-DTOR L4-FLUSHED-BY-EXIT].all? { |t| out.include?(t) }
  st_out, st_rc = run_native(native, 'none', 'selftest')
  check 'native: the harness self-test passes', st_rc.zero? && st_out.include?('expect_mismatches=0') && st_out.include?('ok=3 faulted=3 hung=1 failed=2'), st_out[-300..]
  c1_out, c1_rc = run_native(native, 'c1')
  check 'native under config c1: the table expects the same verdicts', c1_rc.zero? && c1_out.include?('expect_mismatches=0')
  c3_out, c3_rc = run_native(native, 'c3')
  check 'config c3 on a run without the cache is a mismatch on exactly the two served-from-cache checks (table-driven verdicts)',
        c3_rc == 1 && c3_out.scan(/^RESULT .*EXPECT-MISMATCH/).size == 2 && c3_out.scan(/^RESULT 0[12] .*EXPECT-MISMATCH expected=ok/).size == 2
  zz_out, zz_rc = run_native(native, 'zz')
  check 'a configuration without a table entry is a mismatch for every check, not a pass',
        zz_rc == 1 && zz_out.scan(/EXPECT-MISMATCH expected=\(no entry for the configuration\)/).size == EXPECTED_COUNT

  # ------------------------------------------------------------ mutation probes
  # each probe edits one thing in a copy of l4_checks.cpp, rebuilds the native probe, and must change
  # the verdict of exactly the named check (and no other) away from the baseline
  probes = [
    ['the rethrow is dropped', [['catch (int &v) { stage = 1; REQUIRE(v == 3); throw; }', 'catch (int &v) { stage = 1; REQUIRE(v == 3); }']], 'q2_rethrow', 'failed'],
    ['the value thrown through three frames arrives changed', [['REQUIRE(v == 41)', 'REQUIRE(v == 40)']], 'q2_throw_through_nested_frames', 'failed'],
    ['the cleanup destructor does not record its order', [['~Counter() { *c = ++next; }', '~Counter() { *c = 0; }']], 'q2_cleanup_landing_pad', 'failed'],
    ['out_of_range becomes a type the logic_error handler does not catch', [['throw std::out_of_range("range")', 'throw std::runtime_error("range")']], 'q2_std_exception_hierarchy', 'faulted'],
    ['the lambda behind std::function does not throw', [['if (v > 0) throw std::runtime_error("from function")', 'if (v > 9) throw std::runtime_error("from function")']], 'q2_exception_through_std_function', 'failed'],
    ['catch(...) is replaced by a handler for int', [['try { throw 3.5; } catch (...) { caught++; }', 'try { throw 3.5; } catch (int) { caught++; }']], 'q2_catch_all', 'faulted'],
    ['the capturing lambda loses its string capture', [['result += static_cast<long>(label.size());', 'result += 0;']], 'q4_thread_capturing_lambda', 'failed'],
    ['call_once runs its body in every thread', [['std::call_once(flag, [&] { runs++; })', 'runs++']], 'q4_call_once_across_threads', 'failed'],
    ['the thread_local destructor does not count', [['~TlProbe() { g_tl_dtors++; }', '~TlProbe() { }']], 'q4_thread_local_destructor', 'failed'],
    ['atexit loses a handler registration', [['REQUIRE(std::atexit(exit_second) == 0);', '']], 'q5_atexit_and_static_destructor', 'failed'],
    ['the static destructor prints nothing (the required output is missing)', [['std::cout << "L4-STATIC-DTOR";', 'g_arm_static_dtor = 1;']], 'q5_atexit_and_static_destructor', 'failed'],
    ['exit skips the flush (_Exit)', [["    ok_mark(g_check);\n    std::exit(0);\n}\n\n// ----", "    ok_mark(g_check);\n    std::_Exit(0);\n}\n\n// ----"]], 'q5_exit_flushes_cout', 'failed'],
    ['the function-local static is not static (every thread initialises)', [['static Lazy<I> x; return x.v;', 'Lazy<I> x; return x.v;']], 'q6_static_local_contention', 'failed'],
    ['the first initialisation of the guarded static does not throw', [['g_flaky_attempts++ == 0', 'g_flaky_attempts++ == 99']], 'q6_static_local_init_throws', 'failed'],
    ['the cout line is not printed (the required output is missing)', [['std::cout << "L4-COUT-LINE " << 42 << \' \' << 1.25 << std::endl;', 'std::cout << "x" << std::endl;']], 'q3_cout_and_cerr', 'failed'],
    ['the harness expectation for a check says faulted while it passes (EXPECT-MISMATCH)',
     [['#define EXP_STD "c1=ok,c2=any,c3=ok,native=ok"', '#define EXP_STD "c1=ok,c2=any,c3=ok,native=faulted"']], :all_mismatch, nil]
  ]
  killed = 0
  probes.each_with_index do |(desc, edits, target, verdict), i|
    mutant = src.dup
    applied = edits.all? do |old, new|
      mutant.scan(old).size == 1 && (mutant = mutant.sub(old) { new })
    end
    unless applied
      check "probe #{i + 1} applies: #{desc}", false, 'the old text does not occur exactly once in l4_checks.cpp'
      next
    end
    File.write(File.join(tmp, 'l4_checks.cpp'), mutant)
    exe = File.join(tmp, "mutant#{i}")
    _o, e, st = py(BUILD, 'native', '--out', exe, '--checks', File.join(tmp, 'l4_checks.cpp'))
    unless st.success?
      check "probe #{i + 1} compiles: #{desc}", false, e[0, 300]
      next
    end
    mout, = run_native(exe, 'native')
    now = verdicts(mout)
    if target == :all_mismatch
      mism = mout.scan(/^RESULT \d+ (\S+) .*EXPECT-MISMATCH/).flatten
      # every check on EXP_STD (not the cache facts, not the known_ld64_addend ones) now expects faulted
      ok = mism.size == names.size - 2 - user_class.size && mism.none? { |n| n.start_with?('q1_') || n.include?('known_') }
      check "probe #{i + 1} killed by the expectation table: #{desc}", ok, mism.size
      killed += 1 if ok
      next
    end
    changed = base.keys.select { |n| now[n].nil? || now[n][0] != base[n][0] }
    ok = changed == [target] && now[target][0] == verdict
    killed += 1 if ok
    check "probe #{i + 1} killed by #{target} (#{verdict}): #{desc}", ok, "changed #{changed.inspect} now #{changed.map { |n| now[n]&.first }.inspect}"
  end
  check "mutation probes killed: #{killed} of #{probes.size}", killed == probes.size && probes.size >= 8

  # ------------------------------------------------------------ Mach-O build and structure
  unless File.executable?(LD64) && File.file?(LD64) && File.directory?(SDKROOT) &&
         File.file?(File.join(LIBCXX_INCLUDE, '__config_site'))
    puts 'SKIP the Mach-O checks: set LD64, SDKROOT and LIBCXX_INCLUDE (Darling libc++ headers)'
    puts "#{$failures.zero? ? 'ALL PASS' : "#{$failures} FAILED"}"
    exit($failures.zero? ? 0 : 1)
  end
  out_dir = File.join(tmp, 'out')
  _o, e, st = py(BUILD, 'build', '--out', out_dir, env: MACHO_ENV)
  check 'build_l4.py builds the arm64e executable, the plain control and their stubs', st.success?, e[0, 800]
  unless st.success?
    puts "#{$failures} FAILED"
    exit 1
  end
  e64 = File.join(out_dir, 'l4_probe_arm64e')
  ctl = File.join(out_dir, 'l4_probe_arm64')
  %w[arm64e arm64].zip([e64, ctl]).each do |arch, path|
    _o, e, st = py(BUILD, 'check', path, arch, env: MACHO_ENV)
    check "structure of l4_probe_#{arch}", st.success?, e[0, 500]
  end

  # a control with the right cpusubtype but one PAC instruction: only the instruction scan can refuse it
  data = File.binread(ctl).bytes
  off = (0x1000...data.size - 4).step(4).find { |o| data[o, 4] == [0, 0, 0, 0] }
  File.binwrite(File.join(tmp, 'ctl_with_pac'), (data[0, off] + [0x7F, 0x23, 0x03, 0xD5] + data[off + 4..]).pack('C*'))
  [
    ['the control is not accepted as arm64e', [ctl, 'arm64e'], /cpusubtype|authenticated|PAC|pacibsp/],
    ['the arm64e executable is not accepted as the control', [e64, 'arm64'], /cpusubtype|PAC instructions/],
    ['a control carrying one PAC instruction is refused by the instruction scan', [File.join(tmp, 'ctl_with_pac'), 'arm64'], /PAC instructions \{'pacibsp': 1\}/]
  ].each do |desc, args, pattern|
    _o, e, st = py(BUILD, 'check', *args, env: MACHO_ENV)
    check desc, !st.success? && e.match?(pattern), e[0, 300]
  end

  # an arm64e link without -init_offsets keeps the signed __mod_init_func that Darling's dyld would call raw
  mod = File.join(tmp, 'mod_init')
  snippet = "import sys; sys.path.insert(0, #{HERE.inspect}); import build_l4; build_l4.ARM64E_LD_ARGS = []; " \
            "build_l4.build_probe('arm64e', #{mod.inspect}) if __import__('os').makedirs(#{mod.inspect}, exist_ok=True) is None else 0"
  _o, e, st = py('-B', '-c', snippet, env: MACHO_ENV)
  _o2, e2, st2 = py(BUILD, 'check', File.join(mod, 'l4_probe_arm64e'), 'arm64e', env: MACHO_ENV)
  check 'an arm64e executable linked without -init_offsets is refused (signed __mod_init_func)',
        st.success? && !st2.success? && e2.include?('__init_offsets'), (e + e2)[0, 400]

  # names go to exactly one library, an unknown name is an error, not a silent stub entry
  _o, e, st = py('-B', '-c', "import sys; sys.path.insert(0, #{HERE.inspect}); import build_l4; " \
                       "build_l4.partition(['_ZNSt3__14coutE', 'not_a_library_symbol'], set(), set())", env: MACHO_ENV)
  check 'a name no library is known to export is an error', !st.success? && e.include?('not_a_library_symbol'), e[-200..]

  dump = lambda do |path|
    o, e, st = py(File.join(HERE, '..', 'arm64e_link.py'), 'dump', path)
    st.success? ? JSON.parse(o)['chained'] : (puts e; { 'fixups' => [], 'imports' => [] })
  end
  df = dump.call(e64)
  imports = df['imports'].map { |i| i['name'] }
  sym = lambda do |arch, lib|
    File.readlines(File.join(out_dir, "stubs-#{arch}", "symbols-#{lib}.txt")).reject { |l| l.start_with?('#') }.map { |l| "_#{l.strip}" }
  end
  cxx, abi = sym.call('arm64e', 'libc++'), sym.call('arm64e', 'libc++abi')
  check 'the libc++ and libc++abi stubs export disjoint name sets, every name is imported by the executable',
        (cxx & abi).empty? && (cxx + abi).all? { |n| imports.include?(n) }, ((cxx & abi) + ((cxx + abi) - imports)).first(5).inspect
  by_lib = df['fixups'].select { |f| f['import'] }.group_by { |f| f['lib'] }.transform_values { |v| v.map { |f| f['import'] }.uniq }
  check 'the executable binds exactly the libc++ stub names from libc++ and the libc++abi stub names from libc++abi',
        by_lib['/usr/lib/libc++.1.dylib'].to_a.sort == cxx.sort && by_lib['/usr/lib/libc++abi.dylib'].to_a.sort == abi.sort,
        by_lib.transform_values(&:size).inspect
  check 'the stubs are link-only: system install names, traps, never referenced by build path',
        File.binread(e64).include?('/usr/lib/libc++.1.dylib') && !File.binread(e64).include?(out_dir) &&
        Dir[File.join(out_dir, 'stubs-*', '*.dylib')].size == 4 && Dir[File.join(out_dir, '**', '*.dylib')].all? { |f| f.include?('.linkonly.') }
  ctl_stub = File.join(out_dir, 'stubs-arm64', 'libc++.1.linkonly.dylib')
  check 'the control links plain arm64 stubs (cpusubtype 0) of the same names',
        sym.call('arm64', 'libc++') == cxx && sym.call('arm64', 'libc++abi') == abi && File.binread(ctl_stub)[8, 4].unpack1('V').zero?

  # the open ABI defect (ABI-README item 3): documented, not hidden
  vt = ->(fx) { fx.select { |x| x['import'].to_s.start_with?('__ZTVN10__cxxabiv') && x['section'] != '__DATA_CONST,__auth_got' && x['section'] != '__DATA_CONST,__got' } }
  check 'the arm64e executable has user typeinfo vtable binds', vt.call(df['fixups']).size >= 6
  check 'DOCUMENTS THE LD64 DEFECT: authenticated typeinfo vtable binds carry addend 0, not 16 (checks named known_ld64_addend)',
        vt.call(df['fixups']).all? { |x| x['kind'] == 'auth_bind' && x['addend'] == 0 }, vt.call(df['fixups']).map { |x| x['addend'] }.uniq.inspect
  # the shipped names exist in Darling's own libraries (needs the built dylibs)
  if File.directory?(DARLING_USR_LIB)
    exp = lambda do |lib|
      o, = Open3.capture2('llvm-nm', '-gU', '--defined-only', File.join(DARLING_USR_LIB, lib))
      o.lines.map { |l| l.split.last }
    end
    check 'every libc++ stub name is exported by Darling libc++.1.dylib', (cxx - exp.call('libc++.1.dylib')).empty?, (cxx - exp.call('libc++.1.dylib')).first(5).inspect
    check 'every libc++abi stub name is exported by Darling libc++abi.dylib', (abi - exp.call('libc++abi.dylib')).empty?
    listed = File.readlines(File.join(HERE, 'libcxxabi_exports.txt')).reject { |l| l.start_with?('#') }.map { |l| "_#{l.strip}" }.sort
    check 'libcxxabi_exports.txt is the export list of that libc++abi.dylib', listed == exp.call('libc++abi.dylib').sort
  else
    puts 'SKIP the checks against Darling\'s built libc++ and libc++abi: set DARLING_USR_LIB'
  end

  # the export-name lists of the cache's libc++ and libc++abi (task T0 of the L4 plan: names only,
  # one Mach-O name per line, exports-cache-libc++.1.txt and exports-cache-libc++abi.txt)
  if File.directory?(CACHE_EXPORTS_DIR)
    lines = ->(f) { File.readlines(File.join(CACHE_EXPORTS_DIR, f)).map(&:strip) }
    check 'every libc++ stub name is exported by the cache\'s libc++ (direct or re-exported)',
          (cxx - lines.call('exports-cache-libc++.1.txt')).empty?, (cxx - lines.call('exports-cache-libc++.1.txt')).first(5).inspect
    check 'every libc++abi stub name is exported by the cache\'s libc++abi',
          (abi - lines.call('exports-cache-libc++abi.txt')).empty?, (abi - lines.call('exports-cache-libc++abi.txt')).first(5).inspect
  else
    puts 'SKIP the checks against the cache\'s export lists: set CACHE_EXPORTS_DIR'
  end
end

puts "#{$failures.zero? ? 'ALL PASS' : "#{$failures} FAILED"}"
exit($failures.zero? ? 0 : 1)
