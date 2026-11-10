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
src = File.read(File.join(HERE, 'abi_checks.c'))
table = src[/const struct check checks\[\] = \{(.*?)\n\};/m, 1].to_s
names = table.scan(/\{"([a-z0-9_]+)", (\w+)\}/)
check 'the check table lists 15 checks with unique names', names.size == 15 && names.map(&:first).uniq.size == 15, names.size
body = src
marks = body.scan(/ok_mark\((\d+)\)|wait_async\(\d+, (\d+)\)/).flatten.compact.map(&:to_i)
check 'every check number 1..15 has exactly one ok_mark', marks.sort == (1..15).to_a, marks.sort.inspect
names.each_with_index do |(name, fn), i|
  # the function (or the handler/callback it registers) must print its own number
  fbody = src[/static int #{fn}\(void\).*?\n\}\n|static int #{fn}\(void\) \{[^\n]*\n/m].to_s
  handler = fbody.scan(/\b(h_\w+|key_dtor|thr_run|once_init|cmp_int|on_image)\b/).flatten.first
  hbody = handler ? src[/(?:static void|static void \*|static int) \*?#{handler}\([^\n]*\n(?:[^\n]*\n)*?\}\n|[^\n]*#{handler}\([^\n]*\{[^\n]*\n/m].to_s : ''
  check "check #{i + 1} (#{name}) prints OKMARK #{i + 1}", (fbody + hbody).match?(/ok_mark\(#{i + 1}\)|wait_async\(\d+, #{i + 1}\)/), fn
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
Dir.mktmpdir('abi-probe-') do |out|
  _o, e, st = build_script('build', '--out', out)
  check 'build_abi.py builds the arm64e probe, the control and the variants', st.success?, e[0, 600]
  exes = { 'arm64e' => nil, 'arm64' => nil, 'arm64e_noret' => 'noret', 'arm64e_noret_unsigned' => 'noret_unsigned',
           'arm64e_nosign' => 'nosign' }
  exes.each do |suffix, variant|
    path = File.join(out, "abi_probe_#{suffix}")
    arch = suffix.start_with?('arm64e') ? 'arm64e' : 'arm64'
    args = ['check', path, arch] + (variant ? ['--variant', variant] : [])
    _o, e, st = build_script(*args)
    check "structure of abi_probe_#{suffix}", st.success?, e[0, 400]
  end

  # mutation probes of the structural checks: each wrong claim must be refused
  e64 = File.join(out, 'abi_probe_arm64e')
  ctl = File.join(out, 'abi_probe_arm64')
  noret = File.join(out, 'abi_probe_arm64e_noret')
  [
    ['the control is not accepted as arm64e', [ctl, 'arm64e'], /cpusubtype|authenticated/],
    ['the arm64e probe is not accepted as the control', [e64, 'arm64'], /cpusubtype|PAC instructions/],
    ['a noret build is not accepted as the full arm64e probe', [noret, 'arm64e'], /pacibsp|paciasp/],
    ['the full arm64e probe is not accepted as a noret variant', [e64, 'arm64e', '--variant', 'noret'], /still signs return/]
  ].each do |desc, args, pattern|
    _o, e, st = build_script('check', *args)
    check desc, !st.success? && e.match?(pattern), e[0, 300]
  end

  # the unsign rewrite changes exactly the authenticated binds outside __auth_got, nothing else
  dump = lambda do |path|
    o, e, st = py(File.join(HERE, '..', 'arm64e_link.py'), 'dump', path)
    st.success? ? JSON.parse(o)['chained']['fixups'] : (puts e; [])
  end
  a = dump.call(noret)
  b = dump.call(File.join(out, 'abi_probe_arm64e_noret_unsigned'))
  check 'unsigned variant keeps the fixup count', a.size == b.size && a.size > 100, "#{a.size} vs #{b.size}"
  changed = a.zip(b).select { |x, y| x['kind'] != y['kind'] }
  expect = a.select { |x| x['kind'] == 'auth_bind' && x['section'] != '__DATA_CONST,__auth_got' }
  check 'only the authenticated binds outside __auth_got changed kind',
        changed.size == expect.size && changed.all? { |x, y| x['kind'] == 'auth_bind' && y['kind'] == 'bind' }
  check 'the personality slot and the typeinfo vtable pointers are among them',
        expect.map { |x| x['import'] }.include?('___gxx_personality_v0') &&
        expect.any? { |x| x['import'].include?('class_type_info') }, expect.map { |x| x['import'] }.uniq.inspect
  same = changed.all? { |x, y| %w[import vmaddr addend next section].all? { |k| x[k] == y[k] } }
  check 'rewritten fixups keep import, address, addend and chain link', same
  check 'the call stubs still authenticate: every __auth_got bind stays signed',
        b.select { |x| x['section'] == '__DATA_CONST,__auth_got' }.all? { |x| x['kind'] == 'auth_bind' } &&
        b.count { |x| x['section'] == '__DATA_CONST,__auth_got' } > 30

  # the symbolizer resolves an offset to the right function of a built image
  nm, = Open3.capture2('llvm-nm', '-n', '--defined-only', ctl)
  main_addr = nm.lines.map(&:split).find { |p| p[2] == '_main' }[0].to_i(16)
  log = File.join(out, 'fault.log')
  File.write(log, "FAULT check=1 sig=11 pc_in=#{ctl}+0x#{(main_addr + 4 - 0x100000000).to_s(16)} lr_in=#{ctl}+0x0\n")
  o, e, st = py(File.join(HERE, 'symbolize_faults.py'), log)
  check 'symbolize_faults.py names _main+0x4', st.success? && o.include?('_main+0x4'), (o + e)[0, 300]
  o, = py(File.join(HERE, 'symbolize_faults.py'), log, '--map', '/nowhere=/elsewhere')
  check 'symbolize_faults.py rejects nothing it cannot read silently (missing image is reported)',
        !File.read(log).empty? && o.include?('_main'), o[0, 200]
end

puts "#{$failures.zero? ? 'ALL PASS' : "#{$failures} FAILED"}"
exit($failures.zero? ? 0 : 1)
