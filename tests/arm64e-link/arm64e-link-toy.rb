# Build a toy arm64e dylib and executable with the host link recipe
# (tests/arm64e-link/arm64e_link.py) and check the chained fixups it produces
# against toy/expected.json. Structural only: nothing is executed.
# Needs Ruby, python3, clang and the in-tree ld64.
# Usage: LD64=/path/to/aarch64-apple-darwin20-ld ruby tests/arm64e-link/arm64e-link-toy.rb
# ARM64E_LINK_SCRIPT=/path/to/arm64e_link.py runs the test against another copy of the script.
require 'json'
require 'tmpdir'
require 'open3'

HERE = __dir__
SCRIPT = ENV.fetch('ARM64E_LINK_SCRIPT', File.join(HERE, 'arm64e_link.py'))
LD64 = ENV['LD64'].to_s
unless !LD64.empty? && File.file?(LD64) && File.executable?(LD64)
  puts 'SKIP arm64e-link-toy: set LD64 to the in-tree ld64 binary (aarch64-apple-darwin20-ld)'
  exit 0
end
CLANG = ENV.fetch('CLANG', 'clang')
unless system(CLANG, '--version', out: File::NULL, err: File::NULL)
  puts "SKIP arm64e-link-toy: #{CLANG} not runnable"
  exit 0
end

CFLAGS = %w[-ffreestanding -fno-stack-protector -O1].freeze
$failures = 0

def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

def tool(*args, env: {}, unset: [])
  env = env.dup
  unset.each { |k| env[k] = nil }
  Open3.capture3(env, 'python3', '-I', SCRIPT, *args)
end

def build_args(sources, out, kind, extra = [])
  cf = CFLAGS.map { |f| "--cflag=#{f}" }
  ['build', '-v', '--out', out, '--kind', kind, '--no-implicit-dylibs', *cf, *extra, *sources]
end

def dump(path)
  out, err, st = tool('dump', path)
  raise "dump #{path} failed: #{err}" unless st.success?
  JSON.parse(out)
end

def at(dump, sym, off)
  base = dump['symbols'].fetch(sym) { raise "symbol #{sym} missing from #{dump['file']}" }
  base + off
end

def by_addr(dump)
  dump['chained']['fixups'].to_h { |f| [f['vmaddr'], f] }
end

# Compare one fixup with its expected-table row; returns a list of mismatch strings.
def compare(dump, fix, row)
  bad = []
  want = lambda { |name, expected, actual| bad << "#{name} #{actual.inspect} != #{expected.inspect}" unless expected == actual }
  want.call('kind', row['kind'], fix['kind'])
  want.call('auth bit', %w[auth_rebase auth_bind].include?(row['kind']), fix['auth'])
  want.call('raw bit63', fix['auth'], fix['raw'].to_i(16)[63] == 1)
  if fix['auth']
    want.call('key', row['key'], fix['key'])
    want.call('addr_div', row['addr_div'], fix['addr_div'])
    want.call('diversity', row['diversity'], fix['diversity'])
  end
  case row['kind']
  when 'auth_rebase'
    want.call('target offset', at(dump, *row['target']) - dump['image_base'], fix['target'])
  when 'rebase'
    want.call('target vmaddr', at(dump, *row['target']), fix['target'])
    want.call('high8', 0, fix['high8'])
  when 'auth_bind', 'bind'
    want.call('import', row['import'], fix['import'])
    want.call('addend', row['addend'], fix['addend'])
    want.call('lib', dump['load_dylibs'].first, fix['lib'])
    want.call('lib ordinal', 1, fix['lib_ordinal'])
  end
  bad
end

def check_table(dump, rows, label)
  fixes = by_addr(dump)
  rows.each do |row|
    addr = at(dump, *row['at'])
    fix = fixes[addr]
    if fix.nil?
      check("#{label} #{row['at'].join('+')} has a fixup", false, format('none at 0x%x', addr))
      next
    end
    bad = compare(dump, fix, row)
    check("#{label} #{row['at'].join('+')} #{row['kind']} #{row['key']} #{row['diversity']}",
          bad.empty?, bad.join('; '))
  end
end

def check_chains(dump, label)
  fixups = dump['chained']['fixups']
  fixups.group_by { |f| [f['segment'], f['page']] }.each do |(seg, page), group|
    group = group.sort_by { |f| f['chain_index'] }
    ok = group.each_cons(2).all? { |a, b| a['next'] * 8 == b['vmaddr'] - a['vmaddr'] } && group.last['next'].zero?
    check("#{label} #{seg} page #{page} chain strides (#{group.size} fixups)", ok)
  end
  fixups.each do |f|
    plain = %w[rebase bind].include?(f['kind'])
    check("#{label} plain #{format('0x%x', f['vmaddr'])} has no auth bit", !f['auth'] && f['raw'].to_i(16)[63].zero?) if plain
  end
  base = dump['image_base']
  starts = dump['chained']['starts'].to_h { |s| [s['segment'], s] }
  check("#{label} every segment with fixups has a starts record",
        (fixups.map { |f| f['segment'] } - starts.keys).empty?)
  starts.each do |name, s|
    seg = dump['segments'].find { |x| x['name'] == name }
    check("#{label} #{name} page size", s['page_size'] == 0x4000)
    check("#{label} #{name} segment_offset", s['segment_offset'] == seg['vmaddr'] - base)
    check("#{label} #{name} page_count", s['page_count'] == (seg['vmsize'] + s['page_size'] - 1) / s['page_size'])
    s['page_starts'].each_with_index do |ps, p|
      first = fixups.find { |f| f['segment'] == name && f['page'] == p && f['chain_index'].zero? }
      expect = first ? first['vmaddr'] - seg['vmaddr'] - p * s['page_size'] : 0xFFFF
      check("#{label} #{name} page #{p} start", ps == expect, "start #{ps} expected #{expect}")
    end
  end
end

def compile_raw(dir, src, name, target = 'arm64e-apple-macos13')
  out = File.join(dir, name)
  o, st = Open3.capture2e(CLANG, "--target=#{target}", '-c', *CFLAGS, src, '-o', out)
  raise "clang failed for #{src}: #{o}" unless st.success?
  out
end

def set_subtype(src, dst, subtype)
  data = File.binread(src)
  data[8, 4] = [subtype].pack('V')
  File.binwrite(dst, data)
end

Dir.mktmpdir('arm64e-link-') do |dir|
  lib_src = File.join(HERE, 'toy/toy_lib.c')
  exe_src = File.join(HERE, 'toy/toy_main.c')
  expected = JSON.parse(File.read(File.join(HERE, 'toy/expected.json')))
  lib_out = File.join(dir, 'libtoy.dylib')
  exe_out = File.join(dir, 'toy_main')

  # --- build with the recipe
  out, err, st = tool(*build_args([lib_src], lib_out, 'dylib', ['--install-name', expected['lib']['install_name']]),
                      env: { 'LD64' => LD64 })
  check('toy dylib builds and verifies', st.success?, err)
  link_line = err.lines.find { |l| l.start_with?("+ #{LD64} ") }.to_s
  compile_line = err.lines.find { |l| l.start_with?("+ #{CLANG} ") }.to_s
  check('compile line targets arm64e', compile_line.include?('--target=arm64e-apple-macos13'), compile_line)
  check('link line uses -arch arm64e -fixup_chains', link_line.include?('-arch arm64e') && link_line.include?('-fixup_chains'), link_line)
  check('link line passes the platform version', link_line.include?('-platform_version macos 13.0 13.0'), link_line)
  check('link line never uses dynamic_lookup', !link_line.empty? && !link_line.include?('dynamic_lookup'), link_line)
  check('link input is the patched object', link_line.include?('0_toy_lib.o') && !link_line.include?('.raw.o'), link_line)
  raw = File.join(dir, '0_toy_lib.raw.o')
  check('raw object keeps the caps byte', File.exist?(raw) && File.binread(raw, 4, 8).unpack1('V') == 0x80000002)
  patched = File.join(dir, '0_toy_lib.o')
  check('patched object has the caps byte cleared', File.exist?(patched) && File.binread(patched, 4, 8).unpack1('V') == 2)

  out, err, st = tool(*build_args([exe_src], exe_out, 'exe', ['--entry', '_main', '--lib', lib_out]),
                      env: { 'LD64' => LD64 })
  check('toy executable builds and verifies', st.success?, err)
  check('executable link line never uses dynamic_lookup', !err.include?('dynamic_lookup'), err)

  if File.exist?(lib_out) && File.exist?(exe_out)
    lib = dump(lib_out)
    exe = dump(exe_out)

    # --- dylib
    check('dylib cputype ARM64', lib['cputype'] == 0x0100000c)
    check('dylib cpusubtype arm64e without caps', lib['cpusubtype'] == 2)
    check('dylib filetype', lib['filetype'] == 6)
    check('dylib install name', lib['install_name'] == expected['lib']['install_name'], lib['install_name'].inspect)
    check('dylib loads nothing (-no_implicit_dylibs)', lib['load_dylibs'].empty?, lib['load_dylibs'].inspect)
    check('dylib has no imports', lib['chained']['imports'].empty?)
    check('dylib fixup count matches the table', lib['chained']['fixups'].size == expected['lib']['fixups'].size,
          "#{lib['chained']['fixups'].size} vs #{expected['lib']['fixups'].size}")
    check_table(lib, expected['lib']['fixups'], 'lib')
    check_chains(lib, 'lib')

    # --- executable
    check('exe cpusubtype arm64e without caps', exe['cpusubtype'] == 2)
    check('exe filetype', exe['filetype'] == 2)
    check('exe LC_LOAD_DYLIB', exe['load_dylibs'] == [expected['exe']['load_dylib']], exe['load_dylibs'].inspect)
    check('exe import names', exe['chained']['imports'].map { |i| i['name'] }.sort == expected['exe']['imports'].sort,
          exe['chained']['imports'].map { |i| i['name'] }.inspect)
    check('exe imports are real dylib ordinals', exe['chained']['imports'].all? { |i| i['ordinal'] == 1 })
    ag = expected['exe']['auth_got']
    auth_got = exe['chained']['fixups'].select { |f| f['section'] == ag['section'] }
    others = exe['chained']['fixups'] - auth_got
    check('exe fixup count matches the table', others.size == expected['exe']['fixups'].size,
          "#{others.size} vs #{expected['exe']['fixups'].size}")
    check_table(exe, expected['exe']['fixups'], 'exe')
    check('exe __auth_got entries are auth binds', !auth_got.empty? && auth_got.all? do |f|
      f['kind'] == ag['kind'] && f['key'] == ag['key'] && f['addr_div'] == ag['addr_div'] && f['diversity'] == ag['diversity']
    end, auth_got.inspect)
    check('exe __auth_got imports', auth_got.map { |f| f['import'] }.sort == ag['imports'].sort, auth_got.map { |f| f['import'] }.inspect)
    check_chains(exe, 'exe')

    # --- parser fails loud on a corrupted chain
    bad = File.join(dir, 'libtoy.badnext')
    data = File.binread(lib_out)
    first = lib['chained']['fixups'].min_by { |f| f['vmaddr'] }
    seg = lib['segments'].find { |s| s['name'] == '__DATA' }
    off = seg['fileoff'] + (first['vmaddr'] - seg['vmaddr'])
    val = data[off, 8].unpack1('Q<') | (0x7ff << 51)
    data[off, 8] = [val].pack('Q<')
    File.binwrite(bad, data)
    _o, e, s = tool('verify', bad)
    check('verify rejects a chain that leaves its page', !s.success? && e.include?('leaves page'), e)
    # LC_DYSYMTAB is 80 bytes; its first words read as non-zero rebase/bind sizes once relabelled LC_DYLD_INFO_ONLY.
    info = File.join(dir, 'libtoy.dyldinfo')
    data = File.binread(lib_out)
    off = 32
    data.unpack1('@16V').times do
      cmd, size = data[off, 8].unpack('VV')
      data[off, 4] = [0x80000022].pack('V') if cmd == 0xB
      off += size
    end
    File.binwrite(info, data)
    _o, e, s = tool('verify', info)
    check('verify rejects LC_DYLD_INFO rebase/bind data next to chained fixups', !s.success? && e.include?('LC_DYLD_INFO'), e)
    trunc = File.join(dir, 'libtoy.trunc')
    File.binwrite(trunc, File.binread(lib_out)[0, 0x8010])
    _o, e, s = tool('verify', trunc)
    check('verify rejects a truncated file', !s.success? && e.include?('arm64e_link: error'), e)
  end

  # --- failure paths
  c_arm64 = File.join(dir, 'plain.c')
  File.write(c_arm64, "int f(void) { return 1; }\n")
  raw_e = compile_raw(dir, c_arm64, 'f_e.o')
  raw_arm64 = compile_raw(dir, c_arm64, 'f_arm64.o', 'arm64-apple-macos13')
  raw_x86 = compile_raw(dir, c_arm64, 'f_x86.o', 'x86_64-apple-macos13')
  garbage = File.join(dir, 'garbage.o')
  File.binwrite(garbage, 'x' * 64)
  not_obj = File.join(dir, 'f_dylib.o')
  File.binwrite(not_obj, File.binread(lib_out)) if File.exist?(lib_out)

  refusals = {
    'plain arm64 object' => [raw_arm64, 'caps byte'],
    'x86_64 object' => [raw_x86, 'not ARM64'],
    'non-Mach-O file' => [garbage, 'not a 64-bit little-endian Mach-O'],
    'linked dylib instead of an object' => [not_obj, 'not a relocatable object']
  }
  refusals.each do |name, (path, msg)|
    next unless File.exist?(path)
    dst = File.join(dir, 'out_refused.o')
    File.delete(dst) if File.exist?(dst)
    _o, e, s = tool('patch', path, dst)
    check("patch refuses #{name}", !s.success? && e.include?(msg) && !File.exist?(dst), e)
  end
  [0x00000002, 0x80000000, 0x81000002, 0xC0000002, 0x80000001].each do |sub|
    src = File.join(dir, format('sub_%08x.o', sub))
    set_subtype(raw_e, src, sub)
    dst = File.join(dir, 'out_sub.o')
    File.delete(dst) if File.exist?(dst)
    _o, e, s = tool('patch', src, dst)
    check(format('patch refuses cpusubtype 0x%08x', sub), !s.success? && e.include?('caps byte') && !File.exist?(dst), e)
  end
  before = File.binread(raw_e)
  _o, e, s = tool('patch', raw_e, raw_e)
  check('patch refuses in-place', !s.success? && e.include?('in place') && File.binread(raw_e) == before, e)
  dst = File.join(dir, 'f_patched.o')
  _o, e, s = tool('patch', raw_e, dst)
  check('patch of a good object succeeds and leaves the input untouched',
        s.success? && File.binread(dst, 4, 8).unpack1('V') == 2 && File.binread(raw_e) == before, e)
  check('patch changes only the subtype word', File.binread(dst).bytes.each_with_index.reject { |b, i| b == before.getbyte(i) }.map(&:last).sort == [11])

  _o, e, s = tool(*build_args([c_arm64], File.join(dir, 'x.dylib'), 'dylib'), unset: ['LD64'])
  check('build without LD64 fails loudly', !s.success? && e.include?('no linker'), e)
  _o, e, s = tool(*build_args([c_arm64], File.join(dir, 'x.dylib'), 'dylib'), env: { 'LD64' => File.join(dir, 'nope') })
  check('build with a bad LD64 fails loudly', !s.success? && e.include?('not an executable'), e)
  _o, e, s = tool(*build_args([c_arm64], File.join(dir, 'x.dylib'), 'dylib', ['--ld-arg=-undefined', '--ld-arg=dynamic_lookup']),
                  env: { 'LD64' => LD64 })
  check('build refuses -undefined dynamic_lookup', !s.success? && e.include?('not allowed'), e)

  undef_src = File.join(dir, 'undef.c')
  File.write(undef_src, "extern int missing_symbol(void);\nint f(void) { return missing_symbol(); }\n")
  _o, e, s = tool(*build_args([undef_src], File.join(dir, 'undef.dylib'), 'dylib'), env: { 'LD64' => LD64 })
  check('link failure is surfaced with the linker output', !s.success? && e.include?('failed (exit') && e.include?('missing_symbol'), e)
  _o, e, s = tool(*build_args([File.join(dir, 'absent.c')], File.join(dir, 'absent.dylib'), 'dylib'), env: { 'LD64' => LD64 })
  check('compile failure is surfaced', !s.success? && e.include?('failed (exit'), e)
  _o, e, s = tool('verify', raw_e)
  check('verify refuses a clang object', !s.success? && e.include?('cpusubtype'), e)
end

puts $failures.zero? ? 'PASS arm64e-link-toy' : "FAIL arm64e-link-toy: #{$failures} check(s) failed"
exit($failures.zero? ? 0 : 1)
