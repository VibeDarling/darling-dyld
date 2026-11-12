# The opposite-direction adapters (a PLAIN importer binding an export of an arm64e image) of dyld3/DarlingArm64eAdapters.cpp on
# this host (arm64 Linux with pointer authentication, SKIP otherwise): the table against an independent reading of the mangled
# names, the thunk bytes against llvm-mc, a native run with real PAC instructions (signing, authentication, NULL, data, round
# trips, thunk page), and mutation probes: each mutant of the source must make this test fail.
# Usage: ruby tests/darling-arm64e-reverse-adapters.rb [checkout]
# Optional: CACHE_EXPORTS=file with the mangled export names of the cache's libc++ and libc++abi (one per line).
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
require_relative 'darling-arm64e-adapters-support'
unless AdapterSupport.pac_host?
  puts 'SKIP darling-arm64e-reverse-adapters: needs an arm64 Linux host with pointer authentication and clang++'
  exit 0
end
HAVE_MC = system('llvm-mc', '--version', out: File::NULL, err: File::NULL)
$failures = 0
def check(desc, ok, detail = nil)
  if ok then puts "PASS #{desc}" else $failures += 1; puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}" end
end

def mc_words(listing)
  o, _e, st = Open3.capture3('llvm-mc', '-triple=aarch64', '-mattr=+pauth', '-show-encoding', stdin_data: listing)
  return nil unless st.success?
  o.lines.grep(/encoding:/).map { |l| l[/encoding: \[(.*)\]/, 1].scan(/0x(\h\h)/).flatten.map { |b| b.to_i(16) }.pack('C*').unpack1('V') }
rescue StandardError
  nil
end

# the call-thunk template of both directions, as an assembler reads it, and what its literals must be
TEMPLATE = ['stp x29, x30, [sp, #-80]!', 'mov x29, sp', 'stp x0, x1, [sp, #16]', 'stp x2, x3, [sp, #32]', 'stp x4, x5, [sp, #48]', 'stp x6, x7, [sp, #64]',
            'add x0, sp, #16', 'ldr x1, #28', 'ldr x2, #32', 'ldr x3, #36', 'ldr x16, #40', 'blr x16', 'ldp x29, x30, [sp], #80', 'ret'].freeze

# returns [row address, forward helper, predicate, words] of the reverse thunk of `sym`
def reverse_thunk(exe, sym)
  lines = AdapterSupport.run(exe, 'reverse-thunk', sym)[0].lines
  head = lines.shift.split
  [head[1].to_i(16), head[3].to_i(16), head[5].to_i(16), lines.map { |w| w.to_i(16) }]
end

driver = File.join(root, 'tests/darling-arm64e-reverse-adapters-host.cpp')
Dir.mktmpdir('rev-adapters') do |dir|
  exe, err = AdapterSupport.build(root, dir, 'base', driver)
  check('the driver builds', !exe.nil?, err)
  abort "build failed:\n#{err}" unless exe
  out, st = AdapterSupport.run(exe)
  check('the native checks pass', st.success?, out)
  puts out.lines.last

  # The table against the mangled names (independent of the table): a name with PF has one masked argument per function
  # pointer parameter, the handler getters authenticate a result, set_* sign argument 0 and authenticate the old handler.
  rows, = AdapterSupport.run(exe, 'rows')
  table = rows.lines.map { |l| s, m, ret, c, status = l.split; [s, [m.to_i(16), ret == '1', c.to_i, status.to_i]] }.to_h
  outs = rows.lines.to_h { |l| f = l.split; [f[0], f[8].to_i] }
  structs = rows.lines.map { |l| f = l.split; [f[0], [f[5].to_i, f[6].to_i, f[7].to_i(16)]] }.to_h
  check('the table has 65 rows, 3 of them unsupported', table.size == 65 && table.values.count { |v| v[3] == 3 } == 3, table.size.to_s)
  # the C exports found by the sweep of every plain image against the arm64e set (tests/darling-arm64e-reverse-callback-imports.tsv, the
  # argument numbers from the DWARF of the exporter): R and RS have a row signing exactly those arguments, U an unsupported row, and
  # B (blocks, which need a caller built for arm64e), N (arm64e code never calls the pointer) and T (a returned table) have no row
  sweep = File.readlines(File.join(root, 'tests/darling-arm64e-reverse-callback-imports.tsv'), chomp: true).drop(1).map { |l| l.split("\t") }
  sweep_by_symbol = sweep.to_h { |f| [f[0], f] }
  check('the sweep file has no repeated symbol', sweep_by_symbol.size == sweep.size, sweep.size.to_s)
  sweep.each do |sym, _exporter, kind, args|
    row = table[sym]
    case kind
    when 'R', 'RS'
      want = args.split(',').sum { |i| 1 << i.to_i }
      check("#{sym}: the swept code-pointer arguments #{args} are the sign mask, no result is a handler",
            row && row[3] != 3 && row[0] == want && !row[1] && row[2] == args.split(',').map(&:to_i).max + 1, row.inspect)
    when 'U'
      check("#{sym}: an unsupported row, not a silent skip", row && row[3] == 3, row.inspect)
    else
      check("#{sym}: class #{kind} has no row (a block-taking export needs a caller built for arm64e and gets no tolerance)", row.nil?, row.inspect)
    end
  end
  check('every row of a C export is in the sweep file',
        table.keys.reject { |n| n.start_with?('__Z', '___cxa_throw') || %w[__libc_initializer __dyld_func_lookup].include?(n) }.all? { |n| sweep_by_symbol.key?(n) },
        table.keys.reject { |n| n.start_with?('__Z', '___cxa_throw') || %w[__libc_initializer __dyld_func_lookup].include?(n) || sweep_by_symbol.key?(n) }.inspect)
  check('the tls_private_key_create struct is argument 0 (desc, structArg 1): words 2 and 3 of 4 (rsa sign and decrypt, or ecdsa curve and sign)', structs['_tls_private_key_create'] == [1, 4, 0xC], structs['_tls_private_key_create'].inspect)
  cache = (ENV['CACHE_EXPORTS'] ? File.readlines(ENV['CACHE_EXPORTS'], chomp: true) : [])
  expected_pf = cache.select { |n| n.include?('PF') && !n.include?('money_get') }
  check('every cache export with a function-pointer parameter has a supported row (skipped without the export list)',
        cache.empty? || expected_pf.all? { |n| table.key?(n) && table[n][3] != 3 }, expected_pf.reject { |n| table[n] }.inspect)
  table.each do |sym, (mask, auth_return, argc, status)|
    next if status == 3
    pf = sym.scan(/PF/).size
    if sym =~ /get_(terminate|unexpected|new_handler)v\z/
      check("#{sym}: a getter authenticates the result and signs nothing", auth_return && mask == 0 && argc == 0)
    elsif sym =~ /set_(terminate|unexpected|new_handler)P/
      check("#{sym}: sets sign argument 0 and authenticate the old handler", mask == 1 && auth_return && argc == 1)
    elsif sym == '__libc_initializer'
      check('__libc_initializer signs no argument and returns no handler, but the words of its argument 0 struct: version, then 5 code pointers (struct _libc_functions)', mask == 0 && !auth_return && argc == 1 && structs[sym] == [1, 6, 0x3E])
    elsif sym == '__dyld_func_lookup'
      check('__dyld_func_lookup signs nothing and returns no handler, but authenticates its argument 1 out parameter (void** address)', mask == 0 && !auth_return && argc == 2 && outs[sym] == 2)
    elsif sweep_by_symbol.key?(sym)
      next # checked against the sweep above
    elsif sym == '___cxa_throw'
      check('___cxa_throw signs the destructor (argument 2)', mask == 4 && !auth_return && argc == 3)
    else
      check("#{sym}: #{pf} function pointer parameter(s) are signed, no result is a handler", mask.to_s(2).count('1') == pf && !auth_return && argc >= 1)
    end
  end

  # the thunk bytes: the call template, then the literals row, real target, predicate, helper
  if HAVE_MC
    want = mc_words(TEMPLATE.join("\n"))
    lit = ->(v) { [v & 0xffffffff, v >> 32] }
    %w[__ZSt13set_terminatePFvvE __ZSt13get_terminatev ___cxa_throw].each do |sym|
      row, forward_helper, predicate, got = reverse_thunk(exe, sym)
      helper = got[20] | (got[21] << 32)
      check("reverse thunk of #{sym} is the template and its literals (its own predicate; the helper is not the forward one)",
            want && got.size == 22 && got[0, 14] == want && got[14, 2] == lit[row] && got[16, 2] == lit[0x1122334455667788] && got[18, 2] == lit[predicate] && helper != 0 && helper != forward_helper,
            got.map { |w| format('%08x', w) }.join(' ')[0, 200])
    end
  else
    puts 'SKIP thunk bytes: llvm-mc not found'
  end

  # the rows file: a mutant of the __libc_initializer row must change what the driver reports
  rows_file = File.read(File.join(root, 'dyld3/DarlingArm64eReverseRows.inc'))
  {
    'the __libc_initializer row signs the version word and no dirhelper' => ['0x3E },', '0x1F },'],
    'the __libc_initializer row misses atfork_failed' => ['1, 6, 0x3E },', '1, 5, 0x1E },'],
    'the __libc_initializer row has no struct' => ['1, 6, 0x3E },', '0, 0, 0 },'],
    'the __libc_initializer row is dropped' => [/^\t\{ "__libc_initializer",.*\n/, ''],
  }.each do |name, (from, to)|
    check("rows mutant applies: #{name}", rows_file.scan(from).size == 1)
    rexe, = AdapterSupport.build(root, dir, 'rowsmutant', driver, reverse_rows_text: rows_file.sub(from, to))
    rout, = rexe ? AdapterSupport.run(rexe, 'rows') : ['', nil]
    row = rout.lines.map(&:split).find { |f| f[0] == '__libc_initializer' }
    check("rows probe killed: #{name}", rexe.nil? || row.nil? || row[5..7] != ['1', '6', '3e'])
  end

  {
    'the __dyld_func_lookup row fixes up the wrong argument' => ['0, 0, 0, 2 },', '0, 0, 0, 1 },'],
    'the __dyld_func_lookup row has no out argument' => ['0, 0, 0, 2 },', '0, 0, 0, 0 },'],
    'the __dyld_func_lookup row is dropped' => [/^\t\{ "__dyld_func_lookup",.*\n/, ''],
  }.each do |name, (from, to)|
    check("rows mutant applies: #{name}", rows_file.scan(from).size == 1)
    rexe, = AdapterSupport.build(root, dir, 'rowsmutant', driver, reverse_rows_text: rows_file.sub(from, to))
    rout, = rexe ? AdapterSupport.run(rexe, 'rows') : ['', nil]
    row = rout.lines.map(&:split).find { |f| f[0] == '__dyld_func_lookup' }
    check("rows probe killed: #{name}", rexe.nil? || row.nil? || row[8] != '2')
  end

  # the sweep rows: a mutant of the rows file must break one of the sweep expectations, which are read from the DWARF-derived file
  # and not from the table (a violation count of 0 on the real table, above 0 on each mutant)
  # (the driver's `rows` columns: symbol mask authReturn argCount status structArg structWords structSignMask outCodeArg)
  violations = lambda do |text|
    t = text.lines.to_h { |l| f = l.split; [f[0], { mask: f[1].to_i(16), argc: f[3].to_i, status: f[4].to_i, struct: [f[5].to_i, f[6].to_i, f[7].to_i(16)] }] }
    bad = sweep.count do |sym, _e, kind, args|
      row = t[sym]
      case kind
      when 'R', 'RS' then !(row && row[:status] != 3 && row[:mask] == args.split(',').sum { |i| 1 << i.to_i } && row[:argc] == args.split(',').map(&:to_i).max + 1)
      when 'U' then !(row && row[:status] == 3)
      else !row.nil?
      end
    end
    bad + (t['_tls_private_key_create'] && t['_tls_private_key_create'][:struct] == [1, 4, 0xC] ? 0 : 1)
  end
  check('the sweep expectations hold on the real rows', violations.call(rows) == 0, violations.call(rows).to_s)
  {
    'the _atexit row signs the wrong argument' => ['{ "_atexit", 0x1, false, 1,', '{ "_atexit", 0x2, false, 2,'],
    'the ___cxa_atexit row is dropped' => [/^\t\{ "___cxa_atexit",.*\n/, ''],
    'the _qsort row signs the base, not the comparison' => ['{ "_qsort", 0x8, false, 4,', '{ "_qsort", 0x1, false, 1,'],
    'the _funopen row misses its close function' => ['{ "_funopen", 0x1E, false, 5,', '{ "_funopen", 0xE, false, 5,'],
    'the _tls_private_key_create struct misses the decrypt word' => ['1, 4, 0xC },', '1, 4, 0x4 },'],
    'the _tls_private_key_create struct is argument 1 (ctx), not argument 0 (desc)' => ['1, 4, 0xC },', '2, 4, 0xC },'],
    'a block-taking export gets a tolerance row' => ["\t{ \"__dyld_func_lookup\",", "\t{ \"_dispatch_async\", 0x2, false, 2, AdapterStatus::ShapeOnly, \"x\" },\n\t{ \"__dyld_func_lookup\","],
    'the unsupported _tls_handshake_set_callbacks row is dropped' => [/^\t\{ "_tls_handshake_set_callbacks",.*\n/, ''],
  }.each do |name, (from, to)|
    check("sweep mutant applies: #{name}", rows_file.scan(from).size == 1)
    rexe, = AdapterSupport.build(root, dir, 'rowsmutant', driver, reverse_rows_text: rows_file.sub(from) { to })
    rout, = rexe ? AdapterSupport.run(rexe, 'rows') : ['', nil]
    check("sweep probe killed: #{name}", rexe.nil? || violations.call(rout) > 0)
  end

  # mutation probes
  adapters = File.read(File.join(root, 'dyld3/DarlingArm64eAdapters.cpp'))
  sign_line = 'return AdapterSign::signPointer(value, nullptr, false, 0, 0);'
  entry_test = '((isEntry != nullptr) && isEntry(value)) || wasHandedBack(value)'
  mutants = {
    'signing is skipped' => [sign_line, 'return value;'],
    'signing uses the IB key' => [sign_line, 'return AdapterSign::signPointer(value, nullptr, false, 0, 1);'],
    'signing uses a non-zero discriminator' => [sign_line, 'return AdapterSign::signPointer(value, nullptr, false, 1, 0);'],
    'signing is address diversified' => [sign_line, 'return AdapterSign::signPointer(value, &value, true, 0, 0);'],
    'the entry check is removed' => ["if ( (value != 0) && (#{entry_test}) )", 'if ( value != 0 )'],
    'the entry check is replaced by the handed-back ring only' => [entry_test, 'wasHandedBack(value)'],
    'the handed-back ring is removed' => [entry_test, '((isEntry != nullptr) && isEntry(value))'],
    'the handed-back ring accepts any value' => ['return ringHolds(sHandedBack, pointer);', 'return pointer != 0;'],
    'a missing predicate signs' => ['((isEntry != nullptr) && isEntry(value))', '((isEntry == nullptr) || isEntry(value))'],
    'the authenticated handler is not remembered' => ['recordHandedBack(result);', ';'],
    # (removing the NULL skip is an equivalent mutant: signPointer returns 0 for 0)
    'the returned handler is stripped instead of authenticated' => ['const uint64_t authenticatedValue = authenticateIA(value, 0);', 'const uint64_t authenticatedValue = stripCode(value);'],
    'the returned handler is authenticated with a modifier' => ['const uint64_t authenticatedValue = authenticateIA(value, 0);', 'const uint64_t authenticatedValue = authenticateIA(value, 1);'],
    'a failed authentication is ignored' => ["\tif ( !authenticated(authenticatedValue) ) {", "\tif ( false ) {"],
    'a failed authentication is stripped and returned' => ["__builtin_trap();\n\t}\n\treturn authenticatedValue;", "return stripCode(value);\n\t}\n\treturn stripCode(value);"],
    'a failed authentication stops without naming the symbol' => ['it is not handed to plain code\\n", row->symbol);', 'it is not handed to plain code\\n", "?");'],
    'special values are authenticated' => ['if ( row->authReturn && !isSpecialHandler(result) )', 'if ( row->authReturn )'],
    'every result is authenticated' => ['if ( row->authReturn && !isSpecialHandler(result) )', 'if ( !isSpecialHandler(result) )'],
    'the mask bit is read from the wrong argument' => ["if ( (row->signMask >> i) & 1 )\n\t\t\ta[i] = signPlainCode", "if ( (row->signMask >> (i + 1)) & 1 )\n\t\t\ta[i] = signPlainCode"],
    'the thunk calls the forward helper' => ['return emitCallThunkWith(words, row, real, (uint64_t)isEntry, (uint64_t)&callReverseRow);', 'return emitCallThunkWith(words, row, real, (uint64_t)isEntry, callThunkHelperAddress());'],
    'the thunk does not carry its predicate' => ['putLiteral(&words[18], aux);', 'putLiteral(&words[18], 0);'],
    'the thunk cache ignores the predicate' => ['(sThunks[i].row == row) && (sThunks[i].real == real) && (sThunks[i].aux == aux)', '(sThunks[i].row == row) && (sThunks[i].real == real)'],
    'the reverse path accepts what the forward ring handed out' => ['return ringHolds(sHandedBack, pointer);', 'return ringHolds(sHandedBack, pointer) || ringHolds(sHandedOut, pointer);'],
    'a plain exporter is adapted' => ["if ( (sMode == AdapterMode::Off) || !targetIsArm64e )\n\t\treturn target;\n\tconst ReverseRow* row", "if ( (sMode == AdapterMode::Off) )\n\t\treturn target;\n\tconst ReverseRow* row"],
    'the kill switch does nothing in this direction' => ["if ( (sMode == AdapterMode::Off) || !targetIsArm64e )\n\t\treturn target;\n\tconst ReverseRow* row", "if ( !targetIsArm64e )\n\t\treturn target;\n\tconst ReverseRow* row"],
    'an unsupported row is bound as if supported' => ["if ( row->status == AdapterStatus::Unsupported ) {\n\t\tdyld::warn(\"arm64e adapters: %s is bound by a plain image", "if ( false ) {\n\t\tdyld::warn(\"arm64e adapters: %s is bound by a plain image"],
    'report mode is always on in this direction' => [/if \( sMode == AdapterMode::Report \)\s+reportMissingRow\(symbol, "a plain image"/, 'reportMissingRow(symbol, "a plain image"'],
    'a thunk page of this direction is left writable' => ['PROT_READ | PROT_EXEC) == 0', 'PROT_READ | PROT_WRITE | PROT_EXEC) == 0'],
    'a function start matches any later offset' => ["if ( address == offset )\n\t\t\treturn true;", "if ( address >= offset )\n\t\t\treturn true;"],
    'the terminator is ignored' => ["if ( delta == 0 )\n\t\t\tbreak;", ';'],
    'the ULEB shift is unbounded' => ['(shift > 63)', '(false)'],
    'a delta that overflows the address is accepted' => ['if ( delta > UINT64_MAX - address )', 'if ( false )'],
    'the struct is not copied: the callee gets the caller\'s' => ['a[row->structArg - 1] = (uint64_t)calleeStruct;', ';'],
    'the struct words are not signed' => ['calleeStruct[i] = signPlainCode(calleeStruct[i], isEntry);', ';'],
    'the struct words are signed without the entry check' => ['calleeStruct[i] = signPlainCode(calleeStruct[i], isEntry);', 'calleeStruct[i] = AdapterSign::signPointer(calleeStruct[i], nullptr, false, 0, 0);'],
    'every struct word is signed whatever the mask says' => ['if ( (row->structSignMask >> i) & 1 )', 'if ( true )'],
    'the struct mask is read off by one word' => ['if ( (row->structSignMask >> i) & 1 )', 'if ( (row->structSignMask >> (i + 1)) & 1 )'],
    'only the first word of the struct is copied' => ['row->structWords * sizeof(uint64_t))', 'sizeof(uint64_t))'],
    'the struct is read with a plain memcpy' => ['copyThroughPipe(calleeStruct, (const void*)a[row->structArg - 1], row->structWords * sizeof(uint64_t))', '(memcpy(calleeStruct, (const void*)a[row->structArg - 1], row->structWords * sizeof(uint64_t)), Access::Ok)'],
    'a struct argument is ignored' => ["if ( (row->structArg != 0) && (a[row->structArg - 1] != 0) ) {\n\t\tconst Access access = copyThroughPipe(calleeStruct", "if ( false ) {\n\t\tconst Access access = copyThroughPipe(calleeStruct"],
    'an unreadable struct passes without a warning' => ["\t\telse\n\t\t\tdyld::warn(\"arm64e adapters: %s could not %s its struct argument", "\t\telse if ( access == Access::NoResource )\n\t\t\tdyld::warn(\"arm64e adapters: %s could not %s its struct argument"],
    'the struct argument is read from the wrong register' => ['a[row->structArg - 1], row->structWords', 'a[row->structArg], row->structWords'],
    'the validator accepts a struct mask outside the words' => ['((r.structSignMask >> r.structWords) != 0)', 'false'],
    'the validator accepts a struct argument that is also masked' => ['if ( (r.signMask >> (r.structArg - 1)) & 1 )', 'if ( false )'],
    'the validator accepts a struct argument past the row\'s arguments' => ['if ( r.structArg > r.argCount )', 'if ( false )'],
    'the out parameter is not fixed up' => ['if ( (row->outCodeArg != 0) && ((int)result != 0) && (a[row->outCodeArg - 1] != 0) ) {', 'if ( false ) {'],
    'the out parameter is fixed up for a failed lookup' => ['((int)result != 0) && (a[row->outCodeArg - 1] != 0) ) {', '(a[row->outCodeArg - 1] != 0) ) {'],
    'the out parameter is stripped instead of authenticated' => ['*out = authenticateForPlain(row, *out);', '*out = stripCode(*out);'],
    'the out parameter is read from the wrong argument' => ['uint64_t* out = (uint64_t*)a[row->outCodeArg - 1];', 'uint64_t* out = (uint64_t*)a[row->outCodeArg];'],
    'special values in the out parameter are authenticated' => ['if ( !isSpecialHandler(*out) )', 'if ( true )'],
    'the validator accepts an out argument past the row\'s arguments' => ['(r.outCodeArg > r.argCount) ||', 'false ||'],
    'the validator accepts a row that does nothing' => ["\t\tif ( !acts )\n\t\t\treturn \"a row does nothing\";\n\t\tif ( r.argCount > 8 )", "\t\tif ( r.argCount > 8 )"],
    'the validator accepts an unsupported row with an action' => ["\t\t\tif ( acts )\n\t\t\t\treturn \"a row without an adapter has an action\";\n\t\t\tcontinue;\n\t\t}\n\t\tif ( r.status == AdapterStatus::HandledElsewhere )", "\t\t\tcontinue;\n\t\t}\n\t\tif ( r.status == AdapterStatus::HandledElsewhere )"],
  }
  killed = 0
  mutants.each do |name, (from, to)|
    found = from.is_a?(Regexp) ? adapters.scan(from).size : adapters.scan(from).size
    unless found == 1
      check("mutant #{name}: the source text is there to mutate exactly once (#{found})", false)
      next
    end
    mutated = from.is_a?(Regexp) ? adapters.sub(from, to) : adapters.sub(from) { to }
    mexe, merr = AdapterSupport.build(root, dir, 'mutant', driver, adapters_text: mutated)
    dead = mexe.nil?
    detail = mexe.nil? ? merr[0, 120] : nil
    unless dead
      mout, mst = AdapterSupport.run(mexe)
      dead = !mst.success? || mout =~ /^FAIL/
      # a thunk-shape mutant that the native run does not see is still caught by the assembler comparison
      if !dead && HAVE_MC
        row, forward_helper, predicate, got = reverse_thunk(mexe, '__ZSt13set_terminatePFvvE')
        helper = got[20] | (got[21] << 32)
        dead = !(got.size == 22 && got[0, 14] == mc_words(TEMPLATE.join("\n")) && got[14, 2] == [row & 0xffffffff, row >> 32] && got[18, 2] == [predicate & 0xffffffff, predicate >> 32] && helper != 0 && helper != forward_helper)
      end
    end
    killed += 1 if dead
    check("mutation probe killed: #{name}", dead, detail)
  end
  puts "probes killed #{killed}/#{mutants.size}"
end
puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
