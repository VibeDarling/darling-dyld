# Host-side test of the ABI probe (plan rung L2): builds the arm64e probe, its three signing
# variants and the plain arm64 control, checks their structure and the harness's own bookkeeping.
# Nothing is executed (the host cannot run Mach-O); the guest results are in README.md.
# Usage: LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/Darling/MacOSX.sdk \
#          ruby tests/arm64e-link/abi/arm64e-abi-probe.rb
# SKIP without LD64, SDKROOT or clang.
require 'json'
require 'tmpdir'
require 'open3'

HERE = __dir__
LD64 = ENV['LD64'].to_s
SDKROOT = ENV['SDKROOT'].to_s
$failures = 0

def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

unless File.executable?(LD64) && File.file?(LD64) && File.directory?(SDKROOT) &&
       system('clang', '--version', out: File::NULL, err: File::NULL)
  puts 'SKIP arm64e-abi-probe: set LD64 (in-tree ld64) and SDKROOT (Darling SDK root); clang must run'
  exit 0
end

def py(*args, env: {})
  Open3.capture3(env, 'python3', '-I', *args)
end

def build_script(*args)
  py(File.join(HERE, 'build_abi.py'), *args, env: { 'LD64' => LD64, 'SDKROOT' => SDKROOT })
end

# ---------------------------------------------------------------- source bookkeeping
def strip_comments(s)
  s.gsub(%r{/\*.*?\*/}m, '').gsub(%r{//[^\n]*}, '')
end

src = strip_comments(File.read(File.join(HERE, 'abi_checks.c')))
table = src[/const struct check checks\[\] = \{(.*?)\n\};/m, 1].to_s
rows = table.scan(/\{"([a-z0-9_]+)", (\w+), ("[a-z]+"|0)\}/)
expects = rows.map { |r| r[2] == '0' ? nil : r[2][1..-2] }
names = rows.map(&:first)
check 'the check table lists 32 checks with unique names', rows.size == 32 && names.uniq.size == 32, rows.size
marks = src.scan(/ok_mark\((\d+)\)|wait_async\(\d+, (\d+)\)|neg_finished\((\d+),/).flatten.compact.map(&:to_i)
check 'every check number 1..32 has exactly one verdict path', marks.sort == (1..32).to_a, marks.sort.inspect
check 'checks 01-20 carry no expectation (their verdicts are the measurement)', expects[0, 20].all?(&:nil?)
check 'checks 21-23 and 29-30 expect ok', (expects[20, 3] + expects[28, 2]).all? { |e| e == 'ok' }
check 'checks 24-28 and 31-32 expect faulted', (expects[23, 5] + expects[30, 2]).all? { |e| e == 'faulted' }
nf = src[/static int neg_finished\(int number.*?\n\}\n/m].to_s
check 'neg_finished marks ok only when the check had no signature to authenticate',
      nf.include?('if (!applied)') && nf.include?('ok_mark(number)') && nf.include?('fail(why)')
# Source hints only: the behavioural proof of corrupt() is the guest selftest row below (the host
# cannot execute Mach-O). Scoped to the function body, this rejects a no-op corrupt() that keeps the
# signature assignment.
corrupt_body = src[/\bvoid \*corrupt\(void \*p\) \{(.*?)\n\}\n/m, 1].to_s
check 'HINT (source): corrupt() flips a bit derived from the signature, not a fixed bit',
      !src.include?('PACBIT') && corrupt_body.include?('sig = v ^ (uintptr_t)STRIP(p)') &&
      corrupt_body.match?(/v \^ \(sig & \(0 - sig\)\)/)
check 'checks 21-23 hand their pointer through hand()',
      (20..22).all? { |i| src[/static int #{rows[i][1]}\(void\).*?\n\}/m].to_s.include?('hand(') }
neg = (23..27).to_a + [30, 31]
check 'the negative checks report through neg_finished, never by printing their own OKMARK',
      neg.all? { |i|
        b = src[/static int #{rows[i][1]}\(void\).*?\n\}\n/m].to_s
        b.include?("neg_finished(#{i + 1},") && !b.include?("ok_mark(#{i + 1})")
      }
rows.each_with_index do |(name, fn), i|
  # the function (or the handler/callback it registers) must print its own number
  fbody = src[/static int #{fn}\(void\).*?\n\}\n|static int #{fn}\(void\) \{[^\n]*\n/m].to_s
  handler = fbody.scan(/\b(h_\w+|key_dtor|thr_run|once_init|cmp_int|on_image)\b/).flatten.first
  hbody = handler ? src[/(?:static void|static void \*|static int) \*?#{handler}\([^\n]*\n(?:[^\n]*\n)*?\}\n|[^\n]*#{handler}\([^\n]*\{[^\n]*\n/m].to_s : ''
  check "check #{i + 1} (#{name}) prints OKMARK #{i + 1}",
        (fbody + hbody).match?(/ok_mark\(#{i + 1}\)|wait_async\(\d+, #{i + 1}\)|neg_finished\(#{i + 1},/), fn
end

cxx = File.read(File.join(HERE, 'abi_cxx.cpp'))
check 'the DWARF fixture states the B key and the RA sign state in its CFI',
      cxx.include?('.cfi_b_key_frame') && cxx.include?('.cfi_negate_ra_state')
check 'the DWARF fixture does not rely on .cfi_escape to select DWARF mode', !cxx.include?('.cfi_escape')
check 'HINT (source): the DWARF corruption is derived from the saved signature, not a fixed bit',
      !cxx.include?('1ULL << 50') && !cxx.include?('PACBIT') && cxx.match?(/xpaci/)

harness = File.read(File.join(HERE, 'abi_harness.c'))
check 'the driver compares expectations in the unmutated arm64e checks build only',
      harness.include?('int reference = streq(set->name, "checks") && ' \
                       'streq(ABI_VARIANT, "arm64e") && !mutate;')
check 'a reference mismatch sets the exit status',
      harness.include?('EXPECT-MISMATCH expected=') &&
      harness.include?('if (streq(ABI_VARIANT, "arm64e") && !mutate) return (mismatches || collisions) ? 1 : 0;')
check 'a reference PAC collision prints PAC-COLLISION-MISMATCH and fails the run',
      harness.include?('put("PAC-COLLISION-MISMATCH check=");') && harness.include?('collisions++;')
# The behavioural proof of corrupt(): a selftest row in the self-test set that calls it (and STRIP) on
# values handed through hand(). The source hints above are not evidence on their own.
sel_table = harness[/static const struct check selftests\[\] = \{(.*?)\n\};/m, 1].to_s
sel_rows = sel_table.scan(/\{"([a-z0-9_]+)", (\w+), "ok"\}/)
corrupt_rows = sel_rows.select { |name, _fn| name.include?('corrupt') }
check 'the selftest set has a corrupt() row with an ok expectation', corrupt_rows.size == 1,
      sel_rows.map(&:first).inspect
if corrupt_rows.size == 1
  row_body = harness[/static int #{corrupt_rows[0][1]}\(void\).*?\n\}\n/m].to_s
  check 'the corrupt() selftest row exercises corrupt() and STRIP on handed values',
        row_body.include?('hand(') && row_body.include?('corrupt(') && row_body.include?('STRIP('),
        corrupt_rows[0][1]
end

# ---------------------------------------------------------------- compile-only, both archs
%w[arm64e arm64].each do |arch|
  { 'abi_harness.c' => %w[-fblocks], 'abi_checks.c' => %w[-fblocks], 'abi_cxx.cpp' => %w[-fexceptions -nostdinc++] }.each do |file, flags|
    _o, e, st = Open3.capture3({ 'SDKROOT' => nil }, 'clang', "--target=#{arch}-apple-macos13", '-ffreestanding', '-fno-builtin',
                               '-fsyntax-only', '-Wall', '-Wextra', '-Werror', *flags, File.join(HERE, file))
    check "#{file} compiles without warnings for #{arch}", st.success?, e[0, 300]
  end
end

# ---------------------------------------------------------------- build and structure
VARIANTS = { 'arm64e_noret' => 'noret', 'arm64e_noret_unsigned' => 'noret_unsigned',
             'arm64e_noret_unsigned_addend' => 'noret_unsigned_addend', 'arm64e_nosign' => 'nosign' }.freeze
AUTH_GOT = '__DATA_CONST,__auth_got'.freeze

Dir.mktmpdir('abi-probe-') do |out|
  _o, e, st = build_script('build', '--out', out)
  built = st.success?
  check 'build_abi.py builds the arm64e probe, the control and the variants', built, e[0, 600]
  unless built
    puts 'the checks that need the built files are not run'
    puts "#{$failures} FAILED"
    exit 1
  end
  VARIANTS.merge('arm64e' => nil, 'arm64' => nil).each do |suffix, variant|
    path = File.join(out, "abi_probe_#{suffix}")
    arch = suffix.start_with?('arm64e') ? 'arm64e' : 'arm64'
    args = ['check', path, arch] + (variant ? ['--variant', variant] : [])
    _o, e, st = build_script(*args)
    check "structure of abi_probe_#{suffix}", st.success?, e[0, 400]
  end

  e64 = File.join(out, 'abi_probe_arm64e')
  ctl = File.join(out, 'abi_probe_arm64')
  noret = File.join(out, 'abi_probe_arm64e_noret')

  # a control with the right cpusubtype but one PAC instruction: only the instruction scan can refuse it
  data = File.binread(ctl).bytes
  off = (0x1000...data.size - 4).step(4).find { |o| data[o, 4] == [0, 0, 0, 0] }
  File.binwrite(File.join(out, 'ctl_with_pac'), (data[0, off] + [0x7F, 0x23, 0x03, 0xD5] + data[off + 4..]).pack('C*'))

  # mutation probes of the structural checks: each wrong claim must be refused, for the stated reason
  [
    ['the control is not accepted as arm64e', [ctl, 'arm64e'], /cpusubtype|authenticated/],
    ['the arm64e probe is not accepted as the control', [e64, 'arm64'], /cpusubtype|PAC instructions/],
    ['a control carrying one PAC instruction is refused by the instruction scan',
     [File.join(out, 'ctl_with_pac'), 'arm64'], /PAC instructions \{'pacibsp': 1\}/],
    ['a noret build is not accepted as the full arm64e probe', [noret, 'arm64e'], /pacibsp|paciasp/],
    ['the full arm64e probe is not accepted as a noret variant', [e64, 'arm64e', '--variant', 'noret'], /still signs return/],
    ['the full arm64e probe is not accepted as nosign', [e64, 'arm64e', '--variant', 'nosign'], /nosign still authenticates/],
    ['noret_unsigned is not accepted as the addend variant',
     [File.join(out, 'abi_probe_arm64e_noret_unsigned'), 'arm64e', '--variant', 'noret_unsigned_addend'], /addend 0, expected a plain bind with addend 16/]
  ].each do |desc, args, pattern|
    _o, e, st = build_script('check', *args)
    check desc, !st.success? && e.match?(pattern), e[0, 300]
  end

  dump = lambda do |path|
    o, e, st = py(File.join(HERE, '..', 'arm64e_link.py'), 'dump', path)
    st.success? ? JSON.parse(o)['chained']['fixups'] : (puts e; [])
  end
  a = dump.call(noret)
  b = dump.call(File.join(out, 'abi_probe_arm64e_noret_unsigned'))
  c = dump.call(File.join(out, 'abi_probe_arm64e_noret_unsigned_addend'))
  n = dump.call(File.join(out, 'abi_probe_arm64e_nosign'))
  f = dump.call(e64)
  vt = ->(fx) { fx.select { |x| x['import'].to_s.start_with?('__ZTV') && x['section'] != AUTH_GOT } }

  # the unsign rewrite changes exactly the authenticated binds outside __auth_got, nothing else
  check 'unsigned variant keeps the fixup count', a.size == b.size && a.size > 100, "#{a.size} vs #{b.size}"
  changed = a.zip(b).select { |x, y| x['kind'] != y['kind'] }
  expect = a.select { |x| x['kind'] == 'auth_bind' && x['section'] != AUTH_GOT }
  check 'only the authenticated binds outside __auth_got changed kind',
        changed.size == expect.size && changed.all? { |x, y| x['kind'] == 'auth_bind' && y['kind'] == 'bind' }
  check 'the personality slot and the typeinfo vtable pointers are among them',
        expect.map { |x| x['import'] }.include?('___gxx_personality_v0') &&
        expect.any? { |x| x['import'].include?('class_type_info') }, expect.map { |x| x['import'] }.uniq.inspect
  check 'rewritten fixups keep import, address and chain link',
        changed.all? { |x, y| %w[import vmaddr next section].all? { |k| x[k] == y[k] } }
  check 'the call stubs still authenticate: every __auth_got bind stays signed',
        b.select { |x| x['section'] == AUTH_GOT }.all? { |x| x['kind'] == 'auth_bind' } &&
        b.count { |x| x['section'] == AUTH_GOT } > 30

  # the vtable address point (+16): the in-tree ld64 drops it from authenticated binds (a defect of
  # the 3.3a link recipe's linker, README); a plain bind keeps it; the addend variant restores it
  check 'the arm64e link has typeinfo vtable binds', vt.(f).size >= 2 && vt.(f).all? { |x| x['kind'] == 'auth_bind' }
  check 'DOCUMENTS THE LD64 DEFECT: authenticated typeinfo vtable binds carry addend 0, not 16',
        vt.(f).all? { |x| x['addend'] == 0 }, vt.(f).map { |x| x['addend'] }.inspect
  check 'unsigning alone leaves addend 0', vt.(b).size == vt.(f).size && vt.(b).all? { |x| x['kind'] == 'bind' && x['addend'] == 0 }
  check 'the addend variant puts 16 on every typeinfo vtable bind',
        vt.(c).size == vt.(f).size && vt.(c).all? { |x| x['kind'] == 'bind' && x['addend'] == 16 }
  # (rebase targets differ between the two links: the variant name is a string in the image)
  rest = b.zip(c).select { |x, _y| x['import'] && !(x['import'].start_with?('__ZTV') && x['section'] != AUTH_GOT) }
  check 'the addend variant changes no other bind', rest.size > 50 && rest.all? { |x, y| x['raw'] == y['raw'] },
        rest.count { |x, y| x['raw'] != y['raw'] }
  check 'a plain bind keeps the addend in the same ld64 (nosign)', vt.(n).size == vt.(f).size && vt.(n).all? { |x| x['kind'] == 'bind' && x['addend'] == 16 }

  # the symbolizer resolves an offset to the right function of a built image
  nm, = Open3.capture2('llvm-nm', '-n', '--defined-only', ctl)
  main_addr = nm.lines.map(&:split).find { |p| p[2] == '_main' }[0].to_i(16)
  log = File.join(out, 'fault.log')
  File.write(log, "FAULT check=1 sig=11 pc_in=#{ctl}+0x#{(main_addr + 4 - 0x100000000).to_s(16)} lr_in=#{ctl}+0x0\n")
  o, e, st = py(File.join(HERE, 'symbolize_faults.py'), log)
  check 'symbolize_faults.py names _main+0x4', st.success? && o.include?('_main+0x4'), (o + e)[0, 300]
  File.write(log, "FAULT check=2 sig=11 pc_in=/no/such/image.dylib+0x10 lr_in=#{ctl}+0x#{(main_addr + 4 - 0x100000000).to_s(16)}\n")
  o, _e, st = py(File.join(HERE, 'symbolize_faults.py'), log)
  check 'symbolize_faults.py reports an unreadable image and still names a readable one',
        st.success? && o.include?('image.dylib+0x10 (symbols unreadable)') && o.include?('_main'), o[0, 300]
end

puts "#{$failures.zero? ? 'ALL PASS' : "#{$failures} FAILED"}"
exit($failures.zero? ? 0 : 1)
