# The PAC-leaf test: the H0 recipe applied to libexpat, a cache leaf whose data holds 260
# PAC-signed function pointers. Builds the arm64e executable and the link-only stubs, checks the structure
# (structure only: nothing is executed on the guest side), then runs the program natively against the
# host libexpat to check its logic and exit codes, including injected failures.
# Usage: LD64=/path/to/aarch64-apple-darwin20-ld ruby tests/arm64e-link/h0/arm64e-link-pac-leaf.rb
require 'json'
require 'tmpdir'
require 'open3'

HERE = __dir__
LD64 = ENV['LD64'].to_s
$failures = 0

def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

unless !LD64.empty? && File.file?(LD64) && File.executable?(LD64)
  puts 'SKIP arm64e-link-pac-leaf: set LD64 to the in-tree ld64 binary'
  exit 0
end
unless system('clang', '--version', out: File::NULL, err: File::NULL)
  puts 'SKIP arm64e-link-pac-leaf: clang not runnable'
  exit 0
end

def build_h0(*args)
  Open3.capture3('python3', '-I', File.join(HERE, 'build_h0.py'), *args)
end

EXPECTED_FILE = File.join(HERE, 'expected-expat.json')
LIBEXPAT = '/usr/lib/libexpat.1.dylib'

Dir.mktmpdir('arm64e-link-pac-leaf-') do |tmp|
  out = File.join(tmp, 'out')
  o, e, st = build_h0('build', '--out', out, '--leaf', 'libexpat')
  check('build and structural checks pass', st.success?, e)
  exe = File.join(out, 'h0_expat_main')
  check('the executable and both link-only stubs exist',
        [exe, File.join(out, 'libexpat.1.linkonly.dylib'), File.join(out, 'libSystem.B.linkonly.dylib')].all? { |f| File.file?(f) })
  check('the report names libexpat first and libSystem second',
        o.lines.grep(/LC_LOAD_DYLIB/).map { |l| l[/\S+\.dylib/] } == [LIBEXPAT, '/usr/lib/libSystem.B.dylib'], o)

  # the expectation file must be able to fail: swap the two dependencies and the check has to object
  exp = JSON.parse(File.read(EXPECTED_FILE))
  exp['load_dylibs'].reverse!
  swapped = File.join(tmp, 'swapped.json')
  File.write(swapped, JSON.generate(exp))
  _o, e, st = build_h0('check', exe, '--expected', swapped)
  check('a swapped dependency order in the expectation is rejected', !st.success?, e)
  exp = JSON.parse(File.read(EXPECTED_FILE))
  exp['imports'].reject! { |i| i['name'] == '_XML_SetUserData' }
  dropped = File.join(tmp, 'dropped.json')
  File.write(dropped, JSON.generate(exp))
  _o, e, st = build_h0('check', exe, '--expected', dropped)
  check('an import missing from the expectation is rejected', !st.success?, e)

  # the program's logic and exit codes, natively against the host libexpat
  cflags = %w[-O1 -ffreestanding -fno-builtin -fno-stack-protector]
  src = File.join(HERE, 'expat_main.c')
  native = File.join(tmp, 'native')
  _o, _e, st = Open3.capture3('clang', *cflags, src, '-lexpat', '-o', native)
  if st.success?
    o, _e, st = Open3.capture3(native)
    check('native run against the host libexpat exits 0 with the OK line',
          st.exitstatus.zero? && o.match?(/\Ah0 expat OK expat_\d+\.\d+\.\d+\n\z/), "#{st.exitstatus} #{o.inspect}")
    shims = {
      1 => 'const char *XML_ExpatVersion(void) { return "xpat_2"; }',
      2 => 'void *XML_ParserCreate(const char *e) { return 0; }',
      3 => 'int XML_Parse(void *p, const char *s, int n, int f) { return 0; }',
    }
    shims.each do |code, body|
      shim = File.join(tmp, "shim#{code}.c")
      File.write(shim, body + "\n")
      bin = File.join(tmp, "native#{code}")
      _o, e, st = Open3.capture3('clang', *cflags, src, shim, '-lexpat', '-o', bin)
      unless st.success?
        check("native fault injection builds (exit #{code})", false, e)
        next
      end
      o, _e, st = Open3.capture3(bin)
      check("injected failure returns exit code #{code} and says so",
            st.exitstatus == code && o == "h0 expat FAIL #{format('%02d', code)}\n", "#{st.exitstatus} #{o.inspect}")
    end
  else
    puts 'SKIP native logic checks: cannot link the test program against a host libexpat'
  end
end

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
