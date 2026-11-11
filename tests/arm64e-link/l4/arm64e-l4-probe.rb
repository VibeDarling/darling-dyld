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
require 'fileutils'

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
# the plan's 28 checks (q1..q6), the 8 diagnostics x1..x8 that bisect the c3 throw failure (recorded only), the 2 diagnostics y1 and
# y2 on the cache's terminate-handler slot (recorded only) and the 8 checks z1..z8 that drive the dyld reverse adapters from plain code
PLAN_COUNT = 28
DIAG_COUNT = 8
SLOT_COUNT = 2
REVERSE_COUNT = 8
EXPECTED_COUNT = PLAN_COUNT + DIAG_COUNT + SLOT_COUNT + REVERSE_COUNT
plan_names = names.select { |n| n.start_with?('q') }
diag_names = names.select { |n| n.start_with?('x') }
slot_names = names.select { |n| n.start_with?('y') }
reverse_names = names.select { |n| n.start_with?('z') }
check "the check table lists #{EXPECTED_COUNT} checks with unique names", rows.size == EXPECTED_COUNT && names.uniq.size == EXPECTED_COUNT, rows.size
check "#{PLAN_COUNT} checks are grouped q1..q6 in order and every Q4 group has a check, followed by the #{DIAG_COUNT} diagnostics x1..x8, y1 and y2, and z1..z8",
      plan_names.size == PLAN_COUNT && names == plan_names + diag_names + slot_names + reverse_names && diag_names.size == DIAG_COUNT &&
      diag_names.map { |n| n[/\Ax(\d)_/, 1] } == %w[1 2 3 4 5 6 7 8] && slot_names.map { |n| n[/\Ay(\d)_/, 1] } == %w[1 2] &&
      reverse_names.map { |n| n[/\Az(\d)_/, 1] } == %w[1 2 3 4 5 6 7 8] &&
      plan_names.map { |n| n[/\Aq(\d)_/, 1].to_i } == plan_names.map { |n| n[/\Aq(\d)_/, 1].to_i }.sort &&
      plan_names.map { |n| n[/\Aq(\d)_/, 1] }.uniq == %w[1 2 3 4 5 6]
rows.each_with_index do |(name, fn, _exp, _need), i|
  body = src[/^int #{fn}\(\) \{.*?^\}/m].to_s
  # a check may report through a helper: the exit-path check from the atexit handler it registers first (it
  # runs last), the served-from-cache checks from the function that measures
  helper = { 'atexit_and_static_destructor' => 'void exit_first_registered', 'served_libcxx' => 'int served_by_cache',
             'served_cxa_throw' => 'int served_by_cache' }.fetch(fn) { fn.start_with?('x') && body.include?('x_init_primary(') ? 'int x_init_primary' : nil }
  body += src[/^#{helper}\(.*?^\}/m].to_s if helper
  # z6 hands plain code a handler that fails authentication: it must stop the process, so it never reaches a PASS
  reports = fn == 'z6_corrupted_return_stops' ? body.match?(/p\.get\(\);.*return fail\(/m) : body.match?(/PASS\(\)|ok_mark\(g_check\)/)
  check "check #{i + 1} (#{name}) reports through PASS() or ok_mark(g_check)", reports, fn
end
macros = src.scan(/^#define (EXP_\w+) "([^"]*)"/).to_h
check 'the diagnostics x and y are recorded only: every configuration says any',
      rows.select { |r| r[0].start_with?('x') || r[0].start_with?('y') }.all? { |r| macros[r[2]] == 'c1=any,c2=any,c3=any,native=any' }
check 'the reverse-adapter checks z expect ok in c3 (z6 faulted, once its child reached the corrupting call) and are recorded only elsewhere',
      rows.select { |r| r[0].start_with?('z') }.all? { |r| macros[r[2]] == (r[0].start_with?('z6_') ? 'c1=any,c2=any,c3=faulted,native=any;need=Z6-BEFORE-GET' : 'c1=any,c2=any,c3=ok,native=any') }
z6_body = src[/^int z6_corrupted_return_stops\(\).*?^\}/m].to_s
marker, corrupting = z6_body.index('put("Z6-BEFORE-GET'), z6_body.index('p.get()')
check 'z6 prints its marker immediately before the corrupting get, so a crash before that point cannot satisfy its faulted expectation',
      marker && corrupting && marker < corrupting, z6_body[0, 200]
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

# ---------------------------------------------------------------- the harness's handler policy
# Under the dyld adapters (c2, c3) the harness has to hand over the compiler-signed pointer of its fault handler and thread
# callbacks, because the adapters poison a stripped one; in every other configuration it strips. The host cannot run
# Mach-O, so the policy is extracted from the harness and run natively with a STRIP that flips a bit.
HARNESS = File.read(File.join(HERE, '..', 'abi', 'abi_harness.c'))

def handler_policy_ok(harness, dir)
  streq = harness[/^static int streq\(.*$/] or return [false, 'streq missing']
  policy = harness[/^static int adapters_on\(void\).*$/] or return [false, 'adapters_on missing']
  code = harness[/^static void \*harness_code\(void \*p\).*$/] or return [false, 'harness_code missing']
  File.write(File.join(dir, 'policy.c'), <<~C)
    #include <stdint.h>
    #include <stdio.h>
    #define STRIP(p) ((void *)((uintptr_t)(p) ^ 1))
    static const char *g_config = "none";
    #{streq}
    #{policy}
    #{code}
    int main(void) {
      static const char *signed_in[] = {"c2", "c3"};
      static const char *stripped_in[] = {"c1", "native", "none", "", "c", "c2x", "c33", "C2"};
      int bad = 0;
      for (unsigned i = 0; i < 2; i++) { g_config = signed_in[i]; if (harness_code((void *)0x1000) != (void *)0x1000) { printf("%s was stripped\\n", g_config); bad++; } }
      for (unsigned i = 0; i < 8; i++) { g_config = stripped_in[i]; if (harness_code((void *)0x1000) != (void *)0x1001) { printf("'%s' was not stripped\\n", g_config); bad++; } }
      return bad;
    }
  C
  _o, e, st = Open3.capture3('clang', '-O1', '-Wall', File.join(dir, 'policy.c'), '-o', File.join(dir, 'policy'))
  return [false, e[0, 300]] unless st.success?
  o, st = Open3.capture2e(File.join(dir, 'policy'))
  [st.success?, o]
end

Dir.mktmpdir('l4-policy-') do |dir|
  ok, why = handler_policy_ok(HARNESS, dir)
  check 'the harness hands the compiler-signed handler pointer under c2 and c3 and a stripped one under every other configuration', ok, why
  bare = HARNESS.scan(/STRIP\(\(void \*\)(?:on_fault|st_\w+)\)/)
  check 'every code pointer the harness gives sigaction, pthread_create and pthread_key_create goes through harness_code',
        bare.empty? && HARNESS.scan(/harness_code\(\(void \*\)(?:on_fault|st_\w+)\)/).size == 4, bare.inspect
  policy_probes = [
    ['no configuration signs', 'streq(g_config, "c2") || streq(g_config, "c3")', '0'],
    ['c3 is stripped', 'streq(g_config, "c2") || streq(g_config, "c3")', 'streq(g_config, "c2")'],
    ['c2 is stripped', 'streq(g_config, "c2") || streq(g_config, "c3")', 'streq(g_config, "c3")'],
    ['every configuration signs', 'streq(g_config, "c2") || streq(g_config, "c3")', '1'],
    ['the policy is inverted', 'adapters_on() ? p : STRIP(p)', 'adapters_on() ? STRIP(p) : p'],
    ['a configuration matched by prefix', 'streq(g_config, "c2") ||', 'g_config[0] == \'c\' && g_config[1] == \'2\' ||']
  ]
  policy_killed = policy_probes.each_with_index.count do |(desc, old, new), i|
    mutant = HARNESS.sub(old) { new }
    mdir = File.join(dir, "m#{i}")
    Dir.mkdir(mdir)
    ok = HARNESS.scan(old).size == 1 && mutant != HARNESS && !handler_policy_ok(mutant, mdir)[0]
    check "policy probe #{i + 1} killed: #{desc}", ok
    ok
  end
  check "handler policy probes killed: #{policy_killed} of #{policy_probes.size}", policy_killed == policy_probes.size
end

# ---------------------------------------------------------------- the driver's adapter-warning filter
# dyld prints about a hundred "arm64e adapters: ... has no adapter" warnings at the start of every child when the cache is
# served; the driver drops them from what it judges, so that the OKMARK still fits. Run natively on text shaped like a child's.
def warning_filter_ok(harness, dir)
  fn = harness[/^static int drop_adapter_warnings\(char \*out\) \{.*?^\}/m] or return [false, 'drop_adapter_warnings missing']
  File.write(File.join(dir, 'filter.c'), <<~C)
    #include <stdio.h>
    #include <string.h>
    #{fn}
    static int bad;
    static void run(const char *in, const char *want, int want_dropped) {
      char buf[2048]; strcpy(buf, in);
      int dropped = drop_adapter_warnings(buf);
      if (strcmp(buf, want) || dropped != want_dropped) { printf("input [%s] gave [%s] dropped %d\\n", in, buf, dropped); bad++; }
    }
    #define W "dyld: warning, arm64e adapters: _x is imported by an arm64e image and has no adapter (r); calls with a signed pointer fault"
    int main(void) {
      run("", "", 0);
      run("OKMARK 03\\n", "OKMARK 03\\n", 0);
      run(W "\\n" W "\\n" "OKMARK 03\\n", "OKMARK 03\\n", 2);
      run("a\\n" W "\\nb\\n", "a\\nb\\n", 1);
      run(W, "", 1);                                          /* the last line has no newline */
      run("a\\n" W, "a\\n", 1);
      run("a\\nb", "a\\nb", 0);                                /* a kept last line without a newline stays without one */
      run("x " W "\\n", "x " W "\\n", 0);                      /* only a line that starts with the tag is dyld's */
      run("dyld: warning, something else\\n", "dyld: warning, something else\\n", 0);
      run("dyld: warning, arm64e adapters\\n", "dyld: warning, arm64e adapters\\n", 0);   /* a prefix of the tag */
      run("\\n\\n", "\\n\\n", 0);
      return bad;
    }
  C
  _o, e, st = Open3.capture3('clang', '-O1', '-Wall', File.join(dir, 'filter.c'), '-o', File.join(dir, 'filter'))
  return [false, e[0, 300]] unless st.success?
  o, st = Open3.capture2e(File.join(dir, 'filter'))
  [st.success?, o]
end

Dir.mktmpdir('l4-filter-') do |dir|
  ok, why = warning_filter_ok(HARNESS, dir)
  check 'the driver drops dyld\'s adapter warnings from a child\'s output, counts them and keeps every other line', ok, why
  check 'the driver\'s output buffer is far larger than the warnings of one child', HARNESS[/static char out\[1 << (\d+)\]/, 1].to_i >= 16
  filter_probes = [
    ['the warnings are not dropped', 'if (match) dropped++;', 'if (0) dropped++;'],
    ['the dropped lines are not counted', 'if (match) dropped++;', 'if (match) {}'],
    ['a line is matched anywhere, not at its start', 'if (r + i >= e || r[i] != tag[i])', 'if (r + i >= e)'],
    ['the tag is only a prefix of itself', 'static const char tag[] = "dyld: warning, arm64e adapters:";',
     'static const char tag[] = "dyld: warning, arm64e";'],
    ['the last line without a newline is lost', 'if (*e == \'\\n\') *w++ = \'\\n\';', '*w++ = \'\\n\';'],
    ['the text after the dropped lines is lost', 'r = *e ? e + 1 : e;', 'r = *e ? e + 1 : e; if (match) break;']
  ]
  filter_killed = filter_probes.each_with_index.count do |(desc, old, new), i|
    mdir = File.join(dir, "m#{i}")
    Dir.mkdir(mdir)
    ok = HARNESS.scan(old).size == 1 && !warning_filter_ok(HARNESS.sub(old) { new }, mdir)[0]
    check "filter probe #{i + 1} killed: #{desc}", ok
    ok
  end
  check "adapter-warning filter probes killed: #{filter_killed} of #{filter_probes.size}", filter_killed == filter_probes.size
end

# ---------------------------------------------------------------- the matrix runner's guest command
# run_matrix.sh is copied next to a stub of run_guest.sh that records the command it would run in the guest.
MATRIX = File.read(File.join(HERE, 'run_matrix.sh'))

def matrix_commands(script, dir, env)
  FileUtils.mkdir_p([File.join(dir, 'l4'), File.join(dir, 'abi'), File.join(dir, 'probe'), File.join(dir, 'cache')])
  File.write(File.join(dir, 'l4', 'run_matrix.sh'), script)
  File.write(File.join(dir, 'abi', 'run_guest.sh'), "#!/bin/sh\nprintf '[%s][%s] %s\\n' \"${DYLD_SHARED_CACHE_SPLIT_DIR:-}\" \"${DYLD_SHARED_CACHE_SPLIT_POLICY:-}\" \"$*\" >> \"$GUEST_LOG\"\n")
  FileUtils.chmod(0o755, [File.join(dir, 'l4', 'run_matrix.sh'), File.join(dir, 'abi', 'run_guest.sh')])
  File.write(File.join(dir, 'policy.txt'), "x\n")
  log = File.join(dir, 'guest.log')
  File.delete(log) if File.exist?(log)
  base = { 'DARLING_GUEST_BUILD' => dir, 'PROBE_DIR' => File.join(dir, 'probe'), 'CACHE_DIR' => File.join(dir, 'cache'), 'GUEST_LOG' => log }
  _o, e, st = Open3.capture3(base.merge(env), File.join(dir, 'l4', 'run_matrix.sh'), 't', '1', '1')
  st.success? && File.exist?(log) ? File.read(log) : "FAILED #{e}"
end

def matrix_policy_ok(script, root)
  FileUtils.mkdir_p(root)
  policy = "/Volumes/SystemRoot#{File.realpath(root)}/policy.txt"
  on = matrix_commands(script, root, 'L4_CONFIGS' => 'c3', 'L4_POLICY' => File.join(root, 'policy.txt'))
  off = matrix_commands(script, root, 'L4_CONFIGS' => 'c3')
  both = matrix_commands(script, root, 'L4_CONFIGS' => 'c2 c3', 'L4_POLICY' => File.join(root, 'policy.txt'))
  c3_part = both[/PROBE_CONFIG=c3[^;]*/].to_s
  cache = File.realpath(File.join(root, 'cache'))
  policy_file = File.realpath(File.join(root, 'policy.txt'))
  on.scan('DYLD_SHARED_CACHE_SPLIT_POLICY=').size == 1 && on.include?(" DYLD_SHARED_CACHE_SPLIT_POLICY=#{policy} ") &&
    on.include?('DYLD_SHARED_CACHE_SPLIT_DIR=') && !off.include?('POLICY') && off.include?('PROBE_CONFIG=c3 DYLD_SHARED_CACHE_SPLIT_DIR=') &&
    c3_part.include?(policy) && !both[/PROBE_CONFIG=c2[^;]*/].to_s.include?('POLICY') &&
    launcher_env_clean?(on) && launcher_env_clean?(off) && launcher_env_clean?(both) &&
    matrix_records_ok(on, root, [['l4_probe_arm64e', 'c3', cache, policy_file]]) &&
    matrix_records_ok(off, root, [['l4_probe_arm64e', 'c3', cache, '']]) &&
    matrix_records_ok(both, root, [['l4_probe_arm64e', 'c2', '', ''], ['l4_probe_arm64e', 'c3', cache, policy_file]])
end

# The command that reaches the guest is also executed here against two stubs that record their basename,
# PROBE_CONFIG and the two cache variables: the log text cannot tell `C=x` from `C[0]=`, `C+=`,
# `${C:=}`, `printf -v C` or `read C`, and neither can it show a variable exported under an indirect name.
def matrix_default_records(root)
  cache = File.realpath(File.join(root, 'cache'))
  [%w[l4_probe_arm64 c1] + ['', ''], %w[l4_probe_arm64e c2] + ['', ''],
   ['l4_probe_arm64e', 'c3', cache, ''], ['l4_probe_arm64e', '', '', ''], ['l4_probe_arm64', '', '', '']]
end

# run_guest.sh is launched with the caller's environment, so both variables must stay empty on every
# invocation: setting them on the launcher makes launchd load the cache itself (run_matrix.sh:8-10).
def launcher_env_clean?(log)
  log.lines.all? do |l|
    m = l.match(/\A\[([^\]]*)\]\[([^\]]*)\] /)
    m && m[1].empty? && m[2].empty?
  end
end

def matrix_records_ok(log, root, expected)
  records = File.join(root, 'records.txt')
  FileUtils.rm_f(records)
  stub = "#!/bin/sh\nprintf '%s|%s|%s|%s\\n' \"$(basename \"$0\")\" \"${PROBE_CONFIG:-}\" \"${DYLD_SHARED_CACHE_SPLIT_DIR:-}\" \"${DYLD_SHARED_CACHE_SPLIT_POLICY:-}\" >> \"$RECORDS\"\n"
  probe_dir = File.realpath(File.join(root, 'probe'))
  %w[l4_probe_arm64 l4_probe_arm64e].each do |name|
    path = File.join(probe_dir, name)
    File.write(path, stub)
    FileUtils.chmod(0o755, path)
  end
  return false unless log.lines.size == 1
  return false if log.include?("\r")
  return false unless log.scan('/bin/bash -c ').size == 1
  line = log[%r{/bin/bash -c (.*)}, 1].to_s
  return false if line.empty?
  _o, _e, st = Open3.capture3({ 'RECORDS' => records }, '/bin/bash', '-c', line.gsub('/Volumes/SystemRoot', ''))
  return false unless st.success? && File.exist?(records)
  File.readlines(records).map { |l| l.chomp.split('|', -1) } == expected
end

# the assignment itself: c1 is the plain control, c2 and c3 the arm64e probe, the cache directory on
# c3 only, and the self-test runs both builds
def matrix_assignments_ok(script, root)
  FileUtils.mkdir_p(root)
  log = matrix_commands(script, root, {})
  probe = "/Volumes/SystemRoot#{File.realpath(File.join(root, 'probe'))}"
  cache = "/Volumes/SystemRoot#{File.realpath(File.join(root, 'cache'))}"
  # the script itself must assign each variable once (an `export VAR=` outside the command would reach
  # every guest run through the launcher's environment)
  code = script.lines.reject { |l| l.lstrip.start_with?('#') }.join
  static_ok = code.scan('DYLD_SHARED_CACHE_SPLIT_DIR=').size == 1 &&
    code.scan(/\bE=/).size == 1 && code.scan(/\bC=/).size == 1 &&
    log.include?("E=#{probe}/l4_probe_arm64e; C=#{probe}/l4_probe_arm64") &&
    log.scan('DYLD_SHARED_CACHE_SPLIT_DIR=').size == 1 &&
    log.scan(/\bE=/).size == 1 && log.scan(/\bC=/).size == 1 &&
    log[/PROBE_CONFIG=c1[^;]*/].to_s == 'PROBE_CONFIG=c1 $C' &&
    log[/PROBE_CONFIG=c2[^;]*/].to_s == 'PROBE_CONFIG=c2 $E' &&
    log[/PROBE_CONFIG=c3[^;]*/].to_s == "PROBE_CONFIG=c3 DYLD_SHARED_CACHE_SPLIT_DIR=#{cache} $E" &&
    log.include?('$E selftest; $C selftest')
  static_ok && launcher_env_clean?(log) && matrix_records_ok(log, root, matrix_default_records(root))
end

Dir.mktmpdir('l4-matrix-') do |dir|
  check 'run_matrix.sh puts DYLD_SHARED_CACHE_SPLIT_POLICY, as the guest path of L4_POLICY, on the c3 command only and only when set',
        matrix_policy_ok(MATRIX, dir)
  check 'run_matrix.sh runs c1 on the plain control, c2 and c3 on the arm64e probe, gives only c3 the cache directory and self-tests both builds',
        matrix_assignments_ok(MATRIX, File.join(dir, 'assign'))
  mroot = File.join(dir, 'multiline')
  mlog = matrix_commands(MATRIX, mroot, {})
  mrecords = matrix_default_records(mroot)
  check 'run_matrix log extraction rejects more than one line, a CR, or a second launcher',
        matrix_records_ok(mlog, mroot, mrecords) &&
        !matrix_records_ok(mlog + "# noise\n", mroot, mrecords) &&
        !matrix_records_ok(mlog.sub("\n", "\r\n"), mroot, mrecords) &&
        !matrix_records_ok(mlog.chomp + " /bin/bash -c true\n", mroot, mrecords)
  matrix_probes = [
    ['the policy is never set', '$policy \\$E', ' \\$E'],
    ['the policy is set on every command', 'PROBE_CONFIG=c2 \\$E', 'PROBE_CONFIG=c2 DYLD_SHARED_CACHE_SPLIT_POLICY=/x \\$E'],
    ['the policy is the host path, without the guest root', 'policy=" DYLD_SHARED_CACHE_SPLIT_POLICY=${GUEST_ROOT:-/Volumes/SystemRoot}$(cd', 'policy=" DYLD_SHARED_CACHE_SPLIT_POLICY=$(cd'],
    ['the policy is set although L4_POLICY is empty', 'if [ -n "${L4_POLICY:-}" ]; then', 'if true; then'],
    ['the policy file name is lost', '/$(basename "$L4_POLICY")', '']
  ]
  matrix_killed = matrix_probes.each_with_index.count do |(desc, old, new), i|
    mdir = File.join(dir, "m#{i}")
    ok = MATRIX.scan(old).size == 1 && !matrix_policy_ok(MATRIX.sub(old) { new }, mdir)
    check "run_matrix probe #{i + 1} killed: #{desc}", ok
    ok
  end
  check "run_matrix probes killed: #{matrix_killed} of #{matrix_probes.size}", matrix_killed == matrix_probes.size
  assignment_probes = [
    ['c1 runs the arm64e probe', 'PROBE_CONFIG=c1 \\$C', 'PROBE_CONFIG=c1 \\$E'],
    ['c2 runs the plain control', 'PROBE_CONFIG=c2 \\$E', 'PROBE_CONFIG=c2 \\$C'],
    ['c3 runs the plain control', 'pwd)$policy \\$E', 'pwd)$policy \\$C'],
    ['c2 is given the cache directory', 'PROBE_CONFIG=c2 \\$E', 'PROBE_CONFIG=c2 DYLD_SHARED_CACHE_SPLIT_DIR=/x \\$E'],
    ['c3 loses the cache directory', 'DYLD_SHARED_CACHE_SPLIT_DIR=${GUEST_ROOT:-/Volumes/SystemRoot}$(cd "$CACHE_DIR" && pwd)', ''],
    ['the self-test runs one build only', '\\$E selftest; \\$C selftest', '\\$E selftest'],
    ['the executable variables are swapped', 'E=$g/l4_probe_arm64e; C=$g/l4_probe_arm64',
     'E=$g/l4_probe_arm64; C=$g/l4_probe_arm64e'],
    ['the cache directory is exported for every command', 'cmd="E=$g/l4_probe_arm64e; C=$g/l4_probe_arm64"',
     'cmd="export DYLD_SHARED_CACHE_SPLIT_DIR=/x; E=$g/l4_probe_arm64e; C=$g/l4_probe_arm64"'],
    ['the control variable is reassigned before c1', 'PROBE_CONFIG=c1 \\$C',
     'C=$g/l4_probe_arm64e; PROBE_CONFIG=c1 \\$C'],
    ['the control variable is reassigned with a tab before c1', 'cmd="$cmd; PROBE_CONFIG=c1 \\$C"',
     'cmd="$cmd;' + "\t" + 'C=$g/l4_probe_arm64e; PROBE_CONFIG=c1 \\$C"'],
    ['the control variable is set as an array element', 'PROBE_CONFIG=c1 \\$C',
     'C[0]=$g/l4_probe_arm64e; PROBE_CONFIG=c1 \\$C'],
    ['the control variable is set through printf -v', 'PROBE_CONFIG=c1 \\$C',
     'printf -v C $g/l4_probe_arm64e; PROBE_CONFIG=c1 \\$C'],
    ['the cache directory is exported on the host side', "set -u\n",
     "set -u\nexport DYLD_SHARED_CACHE_SPLIT_DIR=/x\n"],
    ['the cache directory is exported indirectly on the launcher', "set -u\n",
     "set -u\nV=DYLD_SHARED_CACHE_SPLIT_DIR; export \"\$V=/x\"\n"],
    ['the cache directory is exported indirectly inside the guest', 'PROBE_CONFIG=c1 \\$C',
     'V=DYLD_SHARED_CACHE_SPLIT_DIR; export \"\\$V=/x\"; PROBE_CONFIG=c1 \\$C'],
    ['the policy is exported indirectly on the launcher', "set -u\n",
     "set -u\nV=DYLD_SHARED_CACHE_SPLIT_POLICY; export \"\$V=/x\"\n"],
    ['the policy is set indirectly inside the guest on c2', 'PROBE_CONFIG=c2 \\$E',
     'V=DYLD_SHARED_CACHE_SPLIT_POLICY; export \"\\$V=/x\"; PROBE_CONFIG=c2 \\$E']
  ]
  assignment_killed = assignment_probes.each_with_index.count do |(desc, old, new), i|
    ok = MATRIX.scan(old).size == 1 && !matrix_assignments_ok(MATRIX.sub(old) { new }, File.join(dir, "a#{i}"))
    check "run_matrix assignment probe #{i + 1} killed: #{desc}", ok
    ok
  end
  check "run_matrix assignment probes killed: #{assignment_killed} of #{assignment_probes.size}",
        assignment_killed == assignment_probes.size
end

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
  check 'native: every check is ok except the two served-from-cache checks, which record "not from cache", and z1..z8, which need the plain Mach-O dylib',
        base.reject { |n, _| n.start_with?('q1_', 'z') }.all? { |_, (v, _)| v == 'ok' } &&
        base.select { |n, _| n.start_with?('q1_') }.all? { |_, (v, r)| v == 'failed' && r.include?('expected_not_ok=failed') } &&
        base.select { |n, _| n.start_with?('z') }.size == REVERSE_COUNT && base.select { |n, _| n.start_with?('z') }.all? { |_, (v, _)| v == 'failed' },
        base.reject { |_, (v, _)| v == 'ok' }.keys.inspect
  check 'native: the run meets its table (expect_mismatches=0, exit 0)', out.include?('expect_mismatches=0') && rc.zero?, rc
  check 'native: the not-from-cache fact is printed with the image that served the function',
        out.scan(/^  \| FACT served .*in_cache=no/).size == 2
  check 'native: output the child cannot see itself is required (cout line, static dtor, exit flush)',
        %w[L4-COUT-LINE L4-STATIC-DTOR L4-FLUSHED-BY-EXIT].all? { |t| out.include?(t) }
  st_out, st_rc = run_native(native, 'none', 'selftest')
  check 'native: the harness self-test passes', st_rc.zero? && st_out.include?('expect_mismatches=0') && st_out.include?('ok=4 faulted=4 hung=1 failed=2'), st_out[-300..]
  check 'native: the self-test reports the 137 exit as faulted', st_out.match?(/^RESULT \d+ selftest_exit_137_is_faulted faulted( |$)/),
        st_out.lines.grep(/selftest_exit_137/).join
  ns_out, ns_rc = run_native(native, 'none', 'needstop')
  check 'native: a death before the text a faulted expectation needs falls to failed, a death after it stays faulted, a hang stays hung, and both designed mismatches remain',
        ns_rc == 1 && ns_out.match?(/^RESULT \d+ selftest_fault_before_its_required_text_is_failed failed( |$)/) &&
        ns_out.match?(/^RESULT \d+ selftest_need_printed_then_fault faulted( |$)/) &&
        ns_out.match?(/^RESULT \d+ selftest_hang_is_not_failed_by_a_faulted_need hung( |$)/) &&
        ns_out.include?('expect_mismatches=2'), ns_out[-400..]
  check 'native: the driver drops and counts a child line shaped like dyld\'s adapter warning',
        st_out.include?('ADAPTER-WARNINGS-DROPPED 1') && !st_out.include?('dyld: warning, arm64e adapters:'),
        st_out.lines.grep(/ADAPTER-WARNINGS|arm64e adapters/).join
  c1_out, c1_rc = run_native(native, 'c1')
  check 'native under config c1: the table expects the same verdicts', c1_rc.zero? && c1_out.include?('expect_mismatches=0')
  c3_out, c3_rc = run_native(native, 'c3')
  check 'config c3 on a run without the cache is a mismatch on exactly the two served-from-cache checks and z1..z8 (table-driven verdicts)',
        c3_rc == 1 && c3_out.scan(/^RESULT .*EXPECT-MISMATCH/).size == 2 + REVERSE_COUNT && c3_out.scan(/^RESULT 0[12] .*EXPECT-MISMATCH expected=ok/).size == 2 &&
        c3_out.scan(/^RESULT \d+ z\d_\S+ failed.*EXPECT-MISMATCH/).size == REVERSE_COUNT
  zz_out, zz_rc = run_native(native, 'zz')
  check 'a configuration without a table entry is a mismatch for every check, not a pass',
        zz_rc == 1 && zz_out.scan(/EXPECT-MISMATCH expected=\(no entry for the configuration\)/).size == EXPECTED_COUNT
  %w[c1x c2x].each do |near|
    near_out, near_rc = run_native(native, near)
    check "a configuration that extends #{near[0, 2]} (#{near}) is not matched by the keyed table: every check mismatches",
          near_rc == 1 && near_out.scan(/EXPECT-MISMATCH expected=\(no entry for the configuration\)/).size == EXPECTED_COUNT,
          near_rc
  end

  # the driver and the configuration matcher are exercised natively by rebuilding the probe from a
  # mutated abi_harness.c: each mutation must change a line the checks above read
  harness_probes = [
    { desc: 'the 137 exit is not a fault', config: 'none', args: ['selftest'],
      old: 'else if (code > 128) {', new: 'else if (code == 129) {',
      killed: ->(out, _rc) { out.match?(/^RESULT \d+ selftest_exit_137_is_faulted failed( |$)/) } },
    { desc: 'the driver does not drop the adapter warnings', config: 'none', args: ['selftest'],
      old: 'int dropped = drop_adapter_warnings(out);', new: 'int dropped = 0;',
      killed: ->(out, _rc) { !out.include?('ADAPTER-WARNINGS-DROPPED 1') && out.include?('dyld: warning, arm64e adapters:') } },
    { desc: 'a death before the text a faulted expectation needs is still credited', config: 'none', args: ['needstop'],
      old: 'if (alts && names_faulted(alts, alen) && v == 1 && need[0] && !contains(out, need)) { verdict = "failed"; v = 3; }', new: '',
      killed: ->(out, _rc) { out.match?(/^RESULT \d+ selftest_fault_before_its_required_text_is_failed faulted( |$)/) } },
    { desc: 'a configuration key matches by prefix', config: 'c1x', args: [],
      old: 'match = i == klen && !config[i];', new: 'match = i == klen;',
      killed: ->(out, _rc) { out.scan(/EXPECT-MISMATCH/).size != EXPECTED_COUNT } },
    { desc: 'a hang is demoted by the need rule', config: 'none', args: ['needstop'],
      old: 'names_faulted(alts, alen) && v == 1 && need[0]', new: 'names_faulted(alts, alen) && need[0]',
      killed: ->(out, _rc) { out.match?(/^RESULT \d+ selftest_hang_is_not_failed_by_a_faulted_need failed( |$)/) } },
    { desc: 'a death after the text a faulted expectation needs is demoted too', config: 'none', args: ['needstop'],
      old: 'names_faulted(alts, alen) && v == 1 && need[0] && !contains(out, need)',
      new: 'names_faulted(alts, alen) && v == 1 && need[0] && 1',
      killed: ->(out, _rc) { out.match?(/^RESULT \d+ selftest_need_printed_then_fault failed( |$)/) } }
  ]
  harness_killed = 0
  harness_probes.each_with_index do |p, i|
    mutant = HARNESS.sub(p[:old]) { p[:new] }
    unless HARNESS.scan(p[:old]).size == 1 && mutant != HARNESS
      check "harness driver probe #{i + 1} applies: #{p[:desc]}", false, 'the old text does not occur exactly once in abi_harness.c'
      next
    end
    hpath = File.join(tmp, "abi_harness#{i}.c")
    File.write(hpath, mutant)
    hexe = File.join(tmp, "harness_mutant#{i}")
    _o, e, st = py(BUILD, 'native', '--out', hexe, '--harness', hpath)
    unless st.success?
      check "harness driver probe #{i + 1} compiles: #{p[:desc]}", false, e[0, 300]
      next
    end
    hout, hrc = run_native(hexe, p[:config], *p[:args])
    ok = p[:killed].call(hout, hrc)
    check "harness driver probe #{i + 1} killed: #{p[:desc]}", ok, hout.lines.grep(/selftest_exit_137|ADAPTER-WARNINGS|selftest_fault_before|EXPECT-MISMATCH/).first(3).join
    harness_killed += 1 if ok
  end
  check "harness driver probes killed: #{harness_killed} of #{harness_probes.size}",
        harness_killed == harness_probes.size

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
    ['the diagnostic that allocates and frees an exception sees no memory', [['REQUIRE(p != nullptr);', 'REQUIRE(p == nullptr);']], 'x3_allocate_free_exception', 'failed'],
    ['the diagnostic that sets the terminate handler sees another one come back', [['REQUIRE(old == h && std::get_terminate() == h);', 'REQUIRE(old != h && std::get_terminate() == h);']], 'x2_set_get_terminate', 'failed'],
    ['the diagnostic that finds get_unexpected by name finds nothing', [['REQUIRE(f() != nullptr);', 'REQUIRE(f() == nullptr);']], 'x8_get_unexpected_via_dlsym', 'failed'],
    ['the counterfactual diagnostic catches the wrong value', [['try { throw 7; } catch (int v) { REQUIRE(v == 7); }', 'try { throw 7; } catch (int v) { REQUIRE(v == 8); }']], 'y2_set_signed_terminate_then_init', 'failed'],
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
      ok = mism.size == plan_names.size - 2 - user_class.size && mism.none? { |n| n.start_with?('q1_') || n.include?('known_') }
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

  # the plain dylib that z1..z8 load: plain arm64, imports exactly the two handler functions from libc++, no PAC instruction
  plain_dir = File.join(tmp, 'plain')
  _o, e, st = py(File.join(HERE, 'build_plain_dylib.py'), 'build', '--out', plain_dir, env: MACHO_ENV)
  check 'build_plain_dylib.py builds l4_plain.dylib and its structural checks pass', st.success?, e[0, 500]
  plain = File.join(plain_dir, 'l4_plain.dylib')
  if st.success? && system('llvm-nm', '--version', out: File::NULL, err: File::NULL)
    undefined, = Open3.capture2('llvm-nm', '-m', plain)
    check 'l4_plain.dylib imports exactly std::set_terminate and std::get_terminate, both from libc++',
          undefined.lines.grep(/\(undefined\)/).map { |l| l.split[2] }.sort == %w[__ZSt13get_terminatev __ZSt13set_terminatePFvvE] &&
          undefined.lines.grep(/\(undefined\)/).all? { |l| l.include?('(from libc++)') }, undefined
  end
  if st.success?
    pdata = File.binread(plain).bytes
    poff = (0x1000...pdata.size - 4).step(4).find { |o| pdata[o, 4] == [0, 0, 0, 0] }
    File.binwrite(File.join(tmp, 'plain_with_pac'), (pdata[0, poff] + [0x7F, 0x23, 0x03, 0xD5] + pdata[poff + 4..]).pack('C*'))
    _o, e, st = py(File.join(HERE, 'build_plain_dylib.py'), 'check', File.join(tmp, 'plain_with_pac'), env: MACHO_ENV)
    check 'a plain dylib carrying one PAC instruction is refused', !st.success? && e.include?("PAC instructions {'pacibsp': 1}"), e[0, 300]
    _o, e, st = py(File.join(HERE, 'build_plain_dylib.py'), 'check', e64, env: MACHO_ENV)
    check 'the arm64e executable is not accepted as the plain dylib', !st.success? && e.include?('cpusubtype') && e.include?('not an arm64 dylib'), e[0, 300]
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
    built = exp.call('libc++abi.dylib').sort
    # the file is the exact export list of the libc++abi build that made the stub names: an added or
    # dropped name is drift to explain, not something the stubs may paper over
    check 'libcxxabi_exports.txt matches Darling libc++abi.dylib exactly and lists every stub name it routes',
          !listed.empty? && listed == built && (abi - listed).empty?, ((listed - built) | (built - listed)).first(10).inspect
  else
    puts 'SKIP the checks against Darling\'s built libc++ and libc++abi: set DARLING_USR_LIB'
  end

  # the export-name lists of the cache's libc++ and libc++abi (task T0 of the L4 plan: names only,
  # one Mach-O name per line, exports-cache-libc++.1.txt and exports-cache-libc++abi.txt)
  if File.directory?(CACHE_EXPORTS_DIR)
    lines = ->(f) { File.readlines(File.join(CACHE_EXPORTS_DIR, f)).map(&:strip) }
    check 'every libc++ stub name is exported by the cache\'s libc++ (direct or re-exported)',
          (cxx - lines.call('exports-cache-libc++.1.txt')).empty?, (cxx - lines.call('exports-cache-libc++.1.txt')).first(5).inspect
    check 'the two names l4_plain.dylib imports from libc++ are exported by the cache\'s libc++ (re-exported from libc++abi)',
          %w[__ZSt13set_terminatePFvvE __ZSt13get_terminatev].all? { |n| lines.call('exports-cache-libc++.1.txt').include?(n) }
    check 'every libc++abi stub name is exported by the cache\'s libc++abi',
          (abi - lines.call('exports-cache-libc++abi.txt')).empty?, (abi - lines.call('exports-cache-libc++abi.txt')).first(5).inspect
  else
    puts 'SKIP the checks against the cache\'s export lists: set CACHE_EXPORTS_DIR'
  end
end

puts "#{$failures.zero? ? 'ALL PASS' : "#{$failures} FAILED"}"
exit($failures.zero? ? 0 : 1)
