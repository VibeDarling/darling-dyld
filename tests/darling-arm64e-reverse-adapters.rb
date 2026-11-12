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
  structs = rows.lines.map { |l| f = l.split; [f[0], [f[5].to_i, f[6].to_i, f[7].to_i(16)]] }.to_h
  check('the table has 26 rows, 2 of them unsupported', table.size == 26 && table.values.count { |v| v[3] == 3 } == 2, table.size.to_s)
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
    'the authenticated handler is not remembered' => ['recordHandedBack(authenticatedResult);', ';'],
    # (removing the NULL skip is an equivalent mutant: signPointer returns 0 for 0)
    'the returned handler is stripped instead of authenticated' => ['const uint64_t authenticatedResult = authenticateIA(result, 0);', 'const uint64_t authenticatedResult = stripCode(result);'],
    'the returned handler is authenticated with a modifier' => ['const uint64_t authenticatedResult = authenticateIA(result, 0);', 'const uint64_t authenticatedResult = authenticateIA(result, 1);'],
    'a failed authentication is ignored' => ["\t\tif ( !authenticated(authenticatedResult) ) {", "\t\tif ( false ) {"],
    'a failed authentication is stripped and returned' => ["__builtin_trap();\n\t\t}\n\t\trecordHandedBack(authenticatedResult);\n\t\tresult = authenticatedResult;", "result = stripCode(result);\n\t\t}\n\t\trecordHandedBack(authenticatedResult);\n\t\tresult = stripCode(result);"],
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
