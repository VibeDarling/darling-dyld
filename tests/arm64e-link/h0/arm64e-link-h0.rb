# Build the H0 test executable and its link-only stubs with the arm64e recipe and
# check the result (structure only: nothing is executed on the guest side).
# Needs Ruby, python3, clang, the in-tree ld64 and the Darling SDK.
# Usage: LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/MacOSX.sdk \
#          ruby tests/arm64e-link/h0/arm64e-link-h0.rb
# Also compiles the test program natively against the host libz (if available) to
# check its logic and exit codes.
require 'json'
require 'tmpdir'
require 'open3'
require 'fileutils'

HERE = __dir__
RECIPE_DIR = File.dirname(HERE)
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

unless !LD64.empty? && File.file?(LD64) && File.executable?(LD64) && !SDKROOT.empty? && File.directory?(SDKROOT)
  puts 'SKIP arm64e-link-h0: set LD64 (in-tree ld64 binary) and SDKROOT (Darling SDK root)'
  exit 0
end
unless system('clang', '--version', out: File::NULL, err: File::NULL)
  puts 'SKIP arm64e-link-h0: clang not runnable'
  exit 0
end

def py(script_dir, script, *args)
  Open3.capture3('python3', '-I', File.join(script_dir, script), *args)
end

def build(dir, out, *args)
  py(dir, 'build_h0.py', 'build', '--out', out, *args)
end

def dump(path)
  out, err, st = py(RECIPE_DIR, 'arm64e_link.py', 'dump', path)
  raise "dump #{path} failed: #{err}" unless st.success?
  JSON.parse(out)
end

def load_command_ids(data)
  off = 32
  Array.new(data.unpack1('@16V')) do
    cmd, size = data[off, 8].unpack('VV')
    off += size
    cmd
  end
end

def symbol_list(file)
  File.readlines(file, chomp: true).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
end

EXPECTED = JSON.parse(File.read(File.join(HERE, 'expected.json')))
LIBZ = '/usr/lib/libz.1.dylib'
LIBSYSTEM = '/usr/lib/libSystem.B.dylib'

Dir.mktmpdir('arm64e-link-h0-') do |tmp|
  # ---- the real build, checked a second time here with the recipe's dump
  out = File.join(tmp, 'stub')
  o, e, st = build(HERE, out)
  check('build with stub libSystem succeeds and passes its own checks', st.success?, e + o)
  exe = File.join(out, 'h0_zlib_main')
  stub_imports = nil
  if st.success?
    d = dump(exe)
    check('executable is arm64e (cpusubtype 2) and an executable', d['cpusubtype'] == 2 && d['filetype'] == 2)
    check('dependencies are exactly libz then libSystem', d['load_dylibs'] == [LIBZ, LIBSYSTEM], d['load_dylibs'].inspect)
    check('compat versions are 1.0.0 for both', d['load_dylib_versions'].map(&:last) == %w[1.0.0 1.0.0])
    check('LC_MAIN entry present', d['entry_offset'].to_i.positive?)
    want = EXPECTED['imports'].map { |i| [i['name'], [i['lib'] == LIBZ ? 1 : 2, i['lib']]] }.sort
    got = d['chained']['imports'].map { |i| [i['name'], [i['ordinal'], i['lib']]] }.sort
    check('imports are exactly the expected names from the expected ordinals', got == want, "#{got} vs #{want}")
    fx = d['chained']['fixups']
    check('one fixup per import and every one an auth bind in __auth_got',
          fx.size == want.size && fx.all? { |f| f['kind'] == 'auth_bind' && f['section'] == '__DATA_CONST,__auth_got' })
    check('every auth bind is key IA, address diversity, diversity 0',
          fx.all? { |f| f['key'] == 'IA' && f['addr_div'] == true && f['diversity'].zero? })
    check('no imports from the main executable or a flat lookup', d['chained']['imports'].none? { |i| i['ordinal'] <= 0 })
    stub_imports = got
    ids = load_command_ids(File.binread(exe))
    check('no LC_DYLD_INFO(_ONLY) load command', (ids & [0x22, 0x80000022]).empty?)

    %w[libz.1.linkonly.dylib libSystem.B.linkonly.dylib].each do |f|
      s = dump(File.join(out, f))
      names = symbol_list(File.join(HERE, f.start_with?('libz') ? 'libz_symbols.txt' : 'libsystem_symbols.txt')).map { |n| "_#{n}" }
      check("#{f} exports exactly its symbol list (#{names.size})", s['symbols'].keys.sort == names.sort)
      check("#{f} has no dependencies and no fixups", s['load_dylibs'].empty? && s['chained']['fixups'].empty?)
    end
    libz = dump(File.join(out, 'libz.1.linkonly.dylib'))
    check('libz stub install name /usr/lib/libz.1.dylib, current 1.2.12, compat 1.0.0',
          libz['install_name'] == LIBZ && libz['install_versions'] == %w[1.2.12 1.0.0])
    check('every executable import from libz is exported by the libz stub',
          got.select { |_n, (_o, lib)| lib == LIBZ }.all? { |n, _| libz['symbols'].key?(n) })
  end

  # ---- same executable against the SDK's libSystem.dylib: identical import table
  sdk_out = File.join(tmp, 'sdk')
  o, e, st = build(HERE, sdk_out, '--libsystem', 'sdk')
  check('build against the SDK libSystem.dylib succeeds', st.success?, e + o)
  if st.success?
    d = dump(File.join(sdk_out, 'h0_zlib_main'))
    got = d['chained']['imports'].map { |i| [i['name'], [i['ordinal'], i['lib']]] }.sort
    check('SDK libSystem gives the same dependencies and import table as the stub',
          d['load_dylibs'] == [LIBZ, LIBSYSTEM] && got == stub_imports)
  end

  # ---- failure paths
  syms = File.join(tmp, 'libz_without_compress.txt')
  File.write(syms, symbol_list(File.join(HERE, 'libz_symbols.txt')).reject { |n| n == 'compress' }.join("\n") + "\n")
  _o, e, st = build(HERE, File.join(tmp, 'f1'), '--libz-symbols', syms)
  check('a stub without _compress fails the link', !st.success? && e.include?('_compress'), e)

  extra = File.join(tmp, 'expected_extra.json')
  File.write(extra, JSON.generate(EXPECTED.merge('imports' => EXPECTED['imports'] + [{ 'name' => '_deflateReset', 'lib' => LIBZ }])))
  _o, e, st = py(HERE, 'build_h0.py', 'check', exe, '--expected', extra)
  check('an expected import that the executable lacks fails the check', !st.success? && e.include?('_deflateReset'), e)

  renamed = File.join(tmp, 'expected_renamed.json')
  text = File.read(File.join(HERE, 'expected.json')).gsub(LIBZ, '/usr/lib/libz.2.dylib')
  File.write(renamed, text)
  _o, e, st = py(HERE, 'build_h0.py', 'check', exe, '--expected', renamed)
  check('a different libz install name fails the check', !st.success? && e.include?('libz.2.dylib'), e)

  _o, e, st = py(HERE, 'build_h0.py', 'check', File.join(HERE, 'libz_stub.c'))
  check('checking a non-Mach-O file fails loudly', !st.success? && e.include?('Mach-O'), e)

  # ---- mutation probes: each edit to a scratch copy of the recipe must break the build
  def probe(tmp, name, file, from, to)
    root = File.join(tmp, "probe-#{name}")
    FileUtils.mkdir_p(root)
    FileUtils.cp_r(Dir.glob(File.join(RECIPE_DIR, '*.{py,json}')), root)
    FileUtils.cp_r(File.join(RECIPE_DIR, 'h0'), root)
    FileUtils.rm_f(File.join(root, 'h0', 'arm64e-link-h0.rb'))
    path = File.join(root, file)
    src = File.read(path)
    return [name, false, "probe text not found in #{file}"] unless src.include?(from)
    File.write(path, src.sub(from) { to })
    o, e, st = build(File.join(root, 'h0'), File.join(root, 'out'))
    [name, !st.success?, st.success? ? 'build and checks still passed' : (e + o).lines.first(4).join]
  end

  probes = [
    ['wrong stub install name', 'h0/build_h0.py', '("/usr/lib/libz.1.dylib", "libz_symbols.txt"',
     '("/usr/lib/libz.2.dylib", "libz_symbols.txt"'],
    ['import from the wrong ordinal (link order swapped)', 'h0/build_h0.py', 'libs, ld_args = [libz, libsystem], []',
     'libs, ld_args = [libsystem, libz], []'],
    ['caps byte not cleared', 'arm64e_link.py', 'struct.pack_into("<I", out, 8, cpusubtype & ~CAPS_MASK)',
     'struct.pack_into("<I", out, 8, cpusubtype)'],
    ['missing exported symbol (_compress)', 'h0/libz_symbols.txt', "\ncompress\n", "\n"],
    ['extra undefined symbol in the test source', 'h0/h0_zlib_main.c', 'int main(void) {',
     "int h0_unexpected(void);\nint main(void) {\n    h0_unexpected();"],
    ['extra import the stub does provide (deflateReset)', 'h0/h0_zlib_main.c', 'int main(void) {',
     "int deflateReset(z_stream *);\nint main(void) {\n    deflateReset(0);"],
    ['stub function without a trap', 'h0/libz_stub.c', '__builtin_trap();', ';'],
  ]
  probes.each do |name, file, from, to|
    n, killed, detail = probe(tmp, name.gsub(/\W+/, '_'), file, from, to)
    check("mutation probe killed: #{name}", killed, detail)
    puts "     reason: #{detail.lines.reject { |l| l.start_with?('ld: warning') }.first(3).map(&:strip).join(' | ')}" if killed
  end

  # ---- the test program's logic and exit codes, natively against the host libz
  native = File.join(tmp, 'native')
  cflags = %w[-O1 -ffreestanding -fno-builtin -fno-stack-protector]
  src = File.join(HERE, 'h0_zlib_main.c')
  _o, _e, st = Open3.capture3('clang', *cflags, src, '-lz', '-o', native)
  if st.success?
    o, _e, st = Open3.capture3(native)
    check('native run against the host libz exits 0 with the OK line', st.exitstatus.zero? && o == "h0 zlib OK\n", "#{st.exitstatus} #{o.inspect}")
    shims = {
      1 => 'const char *zlibVersion(void) { return "2.0"; }',
      2 => 'int compress(unsigned char *d, unsigned long *l, const unsigned char *s, unsigned long n) { return 5; }',
      4 => 'int uncompress(unsigned char *d, unsigned long *l, const unsigned char *s, unsigned long n) { return 5; }',
      7 => 'unsigned long crc32(unsigned long c, const unsigned char *b, unsigned int n) { return 0; }',
      8 => 'unsigned long adler32(unsigned long c, const unsigned char *b, unsigned int n) { return 0; }',
    }
    shims.each do |code, body|
      shim = File.join(tmp, "shim#{code}.c")
      File.write(shim, body + "\n")
      bin = File.join(tmp, "native#{code}")
      _o, e, st = Open3.capture3('clang', *cflags, src, shim, '-lz', '-o', bin)
      unless st.success?
        check("native fault injection builds (exit #{code})", false, e)
        next
      end
      o, _e, st = Open3.capture3(bin)
      check("injected failure returns exit code #{code} and says so",
            st.exitstatus == code && o == format("h0 zlib FAIL %02d\n", code), "#{st.exitstatus} #{o.inspect}")
    end
  else
    puts 'SKIP native logic checks: cannot link the test program against a host libz'
  end
end

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
