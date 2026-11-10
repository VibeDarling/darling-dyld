# The arm64e adapter table and thunks of dyld3/DarlingArm64eAdapters.cpp, on this host (arm64 Linux with pointer
# authentication, SKIP otherwise): table validation, the table against the Darwin prototypes (independent spec below),
# every thunk's bytes against llvm-mc, a native run with real PAC instructions (authentication of signed, unsigned, corrupted, NULL, -1, 1
# and garbage pointers; signing of signal() and Block_copy results; blocks and sigaction), and mutation probes: each mutant
# of the source must make this test fail. The hooks in src/ are tested by tests/darling-arm64e-adapters-hooks.rb.
# Env: REQUIRED_SYMBOLS=<file with one Mach-O symbol per line, e.g. the callback-taking imports of the T0 facts scan>:
# each must have a row, supported or explicitly unsupported (a missing row is a failure).
# Usage: ruby tests/darling-arm64e-adapters.rb [checkout]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'rbconfig'

root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
HWCAP_PACA = 1 << 30
host_hwcap = File.binread('/proc/self/auxv').unpack('Q*').each_slice(2).find { |type, _| type == 16 }&.last.to_i
unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/ && (host_hwcap & HWCAP_PACA) != 0 && system('clang++', '--version', out: File::NULL, err: File::NULL)
  puts 'SKIP darling-arm64e-adapters: needs an arm64 Linux host with pointer authentication and clang++'
  exit 0
end
HAVE_MC = system('llvm-mc', '--version', out: File::NULL, err: File::NULL)

$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

# What the table must say, written from the Darwin prototypes and the L2 probe (tests/arm64e-link/abi), not from the table:
# symbol => [auth mask, block arg + 1, struct arg + 1, return fix (0 none, 1 signal handler, 2 re-sign copied block), argc,
#            status (0 probed, 1 shape only, 2 handled elsewhere, 3 unsupported)]
HAND = {
  '___cxa_atexit' => [0x1, 0, 0, 0, 3, 0],                 # __cxa_atexit(void (*f)(void*), void* arg, void* dso)
  '_atexit' => [0x1, 0, 0, 0, 1, 0],                       # atexit(void (*f)(void))
  '_pthread_key_create' => [0x2, 0, 0, 0, 2, 0],           # (pthread_key_t*, void (*destructor)(void*))
  '_pthread_create' => [0x4, 0, 0, 0, 4, 0],               # (pthread_t*, const pthread_attr_t*, void* (*start)(void*), void* arg)
  '_pthread_once' => [0x2, 0, 0, 0, 2, 0],                 # (pthread_once_t*, void (*init)(void))
  '_qsort' => [0x8, 0, 0, 0, 4, 0],                        # (base, nel, width, int (*compar)(const void*, const void*))
  '__dyld_register_func_for_add_image' => [0x1, 0, 0, 0, 1, 0],
  '_dispatch_async' => [0x0, 2, 0, 0, 2, 0],               # (queue, block)
  '_dispatch_once' => [0x0, 2, 0, 0, 2, 0],                # (predicate*, block)
  '_sigaction' => [0x0, 0, 2, 0, 3, 0],                    # (sig, const struct sigaction* act, struct sigaction* oact)
  '_signal' => [0x2, 0, 0, 1, 2, 0],                       # sig_t signal(int, sig_t)
  '__Block_copy' => [0x0, 0, 0, 2, 1, 0],                  # void* _Block_copy(const void*)
  '__tlv_atexit' => [0x1, 0, 0, 0, 2, 1],                  # (void (*termFunc)(void*), void* objAddr); not in the T0 lists
}.freeze
# The callback-taking imports of the C++ runtime, ObjC and Foundation closures from the T0 facts scan: class, public prototype note.
FIXTURE = File.readlines(File.join(root, 'tests/darling-arm64e-callback-imports.tsv'), chomp: true).drop(1).map { |l| l.split("\t") }
              .to_h { |sym, cls, note, present, source| [sym, [cls, note, present, source]] }
UNWIND = %w[__Unwind_RaiseException __Unwind_Resume __Unwind_DeleteException].freeze

# What the facts say a symbol needs, derived here from the prototype note and not from the table
def derived(sym, cls, note)
  args = note.scan(/arg(\d+):[^:;]*:(fnptr|block)/)
  return [0, 0, 0, 0, 0, 2] if UNWIND.include?(sym)
  return [0, 0, 0, 0, 0, 3] unless cls == 'A'
  return [0, 0, 0, 0, 0, 3] if args.any? { |_, k| k == 'block' } || args.any? { |i, _| i.to_i > 7 }
  [args.sum { |i, _| 1 << i.to_i }, 0, 0, 0, args.map { |i, _| i.to_i }.max + 1, 1]
end

SPEC = HAND.dup
FIXTURE.each { |sym, (cls, note, present, _source)| SPEC[sym] ||= derived(sym, cls, note) if present == 'OK' }
SPEC.freeze
# the symbols the L4 set and the L2 probe import (plan shared-cache-m3-l4.md Q1)
L4_AND_L2 = %w[___cxa_atexit _atexit _pthread_key_create _pthread_create _pthread_once __tlv_atexit _qsort _dispatch_async
               _dispatch_once __dyld_register_func_for_add_image _signal _sigaction __Block_copy].freeze

require_relative 'darling-arm64e-adapters-support'

def build(root, dir, name, adapters_text: nil, rows_text: nil)
  AdapterSupport.build(root, dir, name, File.join(root, 'tests/darling-arm64e-adapters-host.cpp'), adapters_text: adapters_text, rows_text: rows_text)
end

def run(exe, *args)
  AdapterSupport.run(exe, *args)
end

Dir.mktmpdir('darling-arm64e-adapters-') do |dir|
  exe, err = build(root, dir, 'real')
  check 'the module and the native driver compile', !exe.nil?, err[0, 600]
  abort "#{$failures} failures" unless exe

  # ---------------------------------------------------------------- the table
  out, = run(exe, 'rows')
  rows = out.lines.map { |l| l.split }.select { |f| f[0] == 'ROW' }.to_h { |f| [f[1], f[2..].map(&:to_i)] }
  check 'the table has exactly the rows of the spec', rows.keys.sort == SPEC.keys.sort, "extra #{(rows.keys - SPEC.keys).inspect} missing #{(SPEC.keys - rows.keys).inspect}"
  wrong = SPEC.reject { |sym, want| rows[sym] == want }
  check "all #{SPEC.size} rows match the Darwin prototypes and the facts", wrong.empty?, wrong.first(3).map { |sym, want| "#{sym}: #{rows[sym].inspect} want #{want.inspect}" }.inspect
  # the hand rows against the prototype notes, where the facts list them
  HAND.each do |sym, want|
    next unless FIXTURE[sym] && FIXTURE[sym][0] == 'A' && want[5] == 0 && want[1] == 0 && want[2] == 0
    cls, note, = FIXTURE[sym]
    check "#{sym}: the hand row names the argument that the prototype note names", cls == 'A' && note.scan(/arg(\d+):[^:;]*:fnptr/).sum { |i,| 1 << i.to_i } == want[0], note
  end
  # a callback-taking import with no row is a failure: every class A, S and D name of the facts that Darling has needs a row
  missing = FIXTURE.select { |_, (_, _, present)| present == 'OK' }.keys - rows.keys
  check "every callback-taking import of the facts (#{FIXTURE.count { |_, (_, _, p)| p == 'OK' }}) has a row", missing.empty?, missing.first(5).inspect
  check 'every symbol of the L4 set and the L2 probe has a row', (L4_AND_L2 - rows.keys).empty?, (L4_AND_L2 - rows.keys).inspect
  if (file = ENV['REQUIRED_SYMBOLS'])
    required = File.readlines(file).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
    check "every symbol of #{File.basename(file)} has a row (#{required.size} symbols)", (required - rows.keys).empty?, (required - rows.keys).inspect
  end

  # ---------------------------------------------------------------- the thunk bytes against an assembler
  def mc_words(listing)
    o, e, st = Open3.capture3('llvm-mc', '-triple=aarch64', '-mattr=+pauth', '-show-encoding', stdin_data: listing)
    return nil unless st.success?
    o.lines.grep(/encoding:/).map { |l| l[/encoding: \[(.*)\]/, 1].scan(/0x(\h\h)/).flatten.map { |b| b.to_i(16) }.pack('C*').unpack1('V') }
  rescue StandardError
    nil
  end
  if HAVE_MC
    bad = []
    (1..255).each do |mask|
      regs = (0..7).select { |i| mask[i] == 1 }
      listing = regs.flat_map { |i| ["add x16, x#{i}, #1", 'cmp x16, #2', 'b.ls #8', "autiza x#{i}"] } + ['ldr x16, #8', 'br x16']
      want = mc_words(listing.join("\n"))
      got = run(exe, 'auth-thunk', mask.to_s)[0].split.map { |w| w.to_i(16) }
      bad << mask unless want && got == want + [0x55667788, 0x11223344]
    end
    check 'strip thunks of all 255 masks are what llvm-mc assembles (skip 0, 1 and -1, autiza per register, ldr x16, br x16, literal)', bad.empty?, bad.first(5).inspect
    %w[_dispatch_async _dispatch_once _sigaction _signal __Block_copy].each do |sym|
      o = run(exe, 'call-thunk', sym)[0].lines
      head = o.shift.split
      row, helper = head[1].to_i(16), head[3].to_i(16)
      got = o.map { |w| w.to_i(16) }
      listing = ['stp x29, x30, [sp, #-80]!', 'mov x29, sp', 'stp x0, x1, [sp, #16]', 'stp x2, x3, [sp, #32]', 'stp x4, x5, [sp, #48]', 'stp x6, x7, [sp, #64]',
                 'add x0, sp, #16', 'ldr x1, #28', 'ldr x2, #32', 'ldr x16, #36', 'blr x16', 'ldp x29, x30, [sp], #80', 'ret', 'nop']
      want = mc_words(listing.join("\n"))
      lit = ->(v) { [v & 0xffffffff, v >> 32] }
      check "call thunk of #{sym} is what llvm-mc assembles", want && got == want + lit[row] + lit[0x1122334455667788] + lit[helper], got.map { |w| format('%08x', w) }.join(' ')[0, 200]
    end
  else
    puts 'SKIP thunk bytes: llvm-mc not found'
  end

  # ---------------------------------------------------------------- the native run
  out, st = run(exe)
  out.lines.grep(/^FAIL/).first(12).each { |l| puts l }
  summary = out.lines.grep(/^(PASS|FAIL) \d+ checks/).last.to_s.strip
  check "native run on real PAC instructions: #{summary}", st.success? && summary.start_with?('PASS')
  checks_run = summary[/\d+/].to_i
  check 'the native run did a meaningful number of checks', checks_run >= 300, checks_run

  # the module also compiles where there are no arm64e importers
  _o, e, st = Open3.capture3('clang++', '--target=x86_64-linux-gnu', '-std=c++17', '-fsyntax-only', '-I', File.join(dir, 'real'), File.join(dir, 'real/DarlingArm64eAdapters.cpp'))
  check 'the module compiles for x86_64 as an identity', st.success?, e[0, 300]

  # ---------------------------------------------------------------- mutation probes: each must make the test fail
  source = File.read(File.join(root, 'dyld3/DarlingArm64eAdapters.cpp'))
  rows_source = File.read(File.join(root, 'dyld3/DarlingArm64eAdapterRows.inc'))
  # [text in the module, replacement] or [text in the rows file, replacement, :rows]
  mutants = {
    'an auth thunk names the wrong register' => ['0xDAC133E0 | i', '0xDAC133E0 | (i + 1)'],
    'an auth thunk strips (xpaci) instead of authenticating' => ['0xDAC133E0 | i', '0xDAC143E0 | i'],
    'an auth thunk authenticates 0, 1 and -1 too' => ['0x54000049;', '0xD503201F;'],
    'an auth thunk loses its branch' => ['words[n++] = 0xD61F0200;', 'words[n++] = 0xD503201F;'],
    'the call thunk strips instead of authenticating a code pointer' => ['const HandlerArg arg = authenticateHandler(a[i]);', 'const HandlerArg arg = { stripCode(a[i]), true };'],
    'a code pointer of 0, 1 or -1 is authenticated' => [/if \( isSpecialHandler\(pointer\) \)\s+return \{ pointer, false \};/, ''],
    'a block invoke is stripped instead of authenticated' => ['const uint64_t plainInvoke = authenticateIA((uint64_t)block->invoke, (uint64_t)&block->invoke);', 'const uint64_t plainInvoke = stripCode((uint64_t)block->invoke);'],
    'a block invoke is authenticated with discriminator 0 instead of its address' => ['const uint64_t plainInvoke = authenticateIA((uint64_t)block->invoke, (uint64_t)&block->invoke);', 'const uint64_t plainInvoke = authenticateIA((uint64_t)block->invoke, 0);'],
    'a heap block is rewritten in place instead of refused' => [/if \( block->flags & kBlockNeedsFree \)\s+refuseBlock\(row, "a heap block"\);/, ''],
    'a block with copy and dispose helpers is passed on' => [/if \( block->flags & kBlockHasCopyDispose \)\s+refuseBlock\(row, "a block with copy and dispose helpers"\);\n\t\t\tif/, 'if'],
    'Block_copy takes a block with helpers' => [/if \( \(block->flags & kBlockHasCopyDispose\) && \(\(block->flags & kBlockIsGlobal\) == 0\) \)\s+refuseBlock\(row, "a block with copy and dispose helpers"\);/, ''],
    'a stack block does not get its signature back' => ['*restoreSlot = restoreValue;', '(void)restoreValue;'],
    'a stack block is never restored (slot not recorded)' => ['restoreSlot = &block->invoke;', 'restoreSlot = nullptr;'],
    'a global block is authenticated in place' => ['a[row->blockArg - 1] = (uint64_t)mirrorOfGlobalBlock(block, plainInvoke);', 'block->invoke = (void*)plainInvoke;'],
    'a global block mirror keeps the signed invoke' => ['copy->invoke = (void*)plainInvoke;', ''],
    'Block_copy signs the copy without authenticating the original' => ['originalInvoke = authenticateIA((uint64_t)block->invoke, (uint64_t)&block->invoke);', 'originalInvoke = stripCode((uint64_t)block->invoke);'],
    'Block_copy signs the copy after a failed authentication' => ['&& authenticated(originalInvoke) ) {', ') {'],
    'Block_copy rewrites a block that was only retained' => ['&& (result != originalBlock)', ''],
    'Block_copy re-signs without address diversity' => ['&copy->invoke, true, 0, 0)', 'nullptr, false, 0, 0)'],
    'signal signs a handler that nobody installed through an adapter' => ['if ( wasInstalledHere(sig, result) )', 'if ( true )'],
    'signal does not remember the handler it installed' => ['recordInstalledHandler(sig, ((genuine >> 1) & 1) ? a[1] : 0);', ''],
    'signal remembers a handler whose installation failed' => ['if ( !failed )', 'if ( true )'],
    'a handler that failed authentication counts as genuine' => ['return { result, false };', 'return { result, true };'],
    'sigaction does not remember the handler it installed' => ['recordInstalledHandler(sig, structGenuine ? structCopy[0] : 0);', ''],
    'sigaction judges its int result by the whole register' => ['if ( (row->structArg != 0) && ((int)result == 0) ) {', 'if ( (row->structArg != 0) && (result == 0) ) {'],
    'sigaction strips the handler instead of authenticating it' => ['const HandlerArg arg = authenticateHandler(structCopy[0]);', 'const HandlerArg arg = { stripCode(structCopy[0]), true };'],
    'a pointer that was never handed out is accepted when it fails authentication' => ['if ( wasHandedOut(pointer) )', 'if ( true )'],
    'a signal() result that plain code installed is not remembered as handed out' => [/else\s+recordHandedOut\(result\);/, ''],
    'a sigaction old action is not remembered as handed out' => ['recordHandedOut(oldCopy[0]);', ''],
    'signal records a handler that the ring accepted as installed by arm64e code' => ['recordInstalledHandler(sig, ((genuine >> 1) & 1) ? a[1] : 0);', 'recordInstalledHandler(sig, a[1]);'],
    'every handler argument counts as genuinely signed' => ['genuine |= (uint8_t)(arg.genuine << i);', 'genuine |= (uint8_t)(1 << i);'],
    'sigaction records a handler that the ring accepted as installed' => ['recordInstalledHandler(sig, structGenuine ? structCopy[0] : 0);', 'recordInstalledHandler(sig, structCopy[0]);'],
    'sigaction gives the callee the caller\'s old-action memory' => ['a[row->structArg] = (uint64_t)oldCopy;', ''],
    'sigaction does not copy the old action out' => ['const Access access = copyThroughPipe(callerOld, oldCopy, sizeof(oldCopy));', 'const Access access = Access::Ok;'],
    'the handed out ring is one slot too long' => ['% kRingCount;', '% (kRingCount + 1);'],
    'the handed out ring is one slot too short' => ['% kRingCount;', '% (kRingCount - 1);'],
    'sigaction forwards the caller\'s act when it cannot be read' => [/if \( a\[row->structArg - 1\] != 0 \)\s+a\[row->structArg - 1\] = ~0ULL;/, ''],
    'sigaction forwards the caller\'s old action when it cannot be written' => [/if \( a\[row->structArg\] != 0 \)\s+a\[row->structArg\] = ~0ULL;/, ''],
    'sigaction copies the caller\'s act with a plain memcpy' => ['copyThroughPipe(structCopy, (const void*)a[row->structArg - 1], sizeof(structCopy))', '(memcpy(structCopy, (const void*)a[row->structArg - 1], sizeof(structCopy)), Access::Ok)'],
    'sigaction does not check that the old action can be written' => ['&& (copyThroughPipe(old, current, sizeof(current)) == Access::Ok) )', ') '],
    'sigaction copies the old action out after a failed call' => ['if ( (row->structArg != 0) && ((int)result == 0) ) {', 'if ( row->structArg != 0 ) {'],
    'the old action is signed whatever it is' => ['if ( wasInstalledHere(sig, oldCopy[0]) )', 'if ( true )'],
    'the old action is never signed' => ['if ( wasInstalledHere(sig, oldCopy[0]) )', 'if ( false )'],
    'a pipe that cannot be made is not reported' => ['return Access::NoResource;', 'return Access::Fault;'],
    'the handed out ring keeps one entry' => ['__atomic_fetch_add(&ring.next, 1, __ATOMIC_RELAXED) % kRingCount', '0'],
    'the signal number is the whole register' => ['return (int32_t)reg;', 'return (reg >> 32) ? 0 : (int32_t)reg;'],
    'the last signal number is out of range' => ['(sig < kSignalCount)', '(sig <= kSignalCount)'],
    'signal number 0 is valid' => ['(sig > 0)', '(sig >= 0)'],
    'sigaction hands the caller\'s struct to the callee' => ['a[row->structArg - 1] = (uint64_t)structCopy;', ''],
    'a thunk page is left read-write-execute by the seal' => ['PROT_READ | PROT_EXEC) == 0', 'PROT_READ | PROT_WRITE | PROT_EXEC) == 0'],
    'a thunk page is mapped writable and executable' => ['mmap(nullptr, kThunkPageSize, PROT_READ | PROT_WRITE,', 'mmap(nullptr, kThunkPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,'],
    'a thunk page is never sealed' => ['if ( !sealExecutablePage(page, kThunkPageSize) ) {', 'if ( false ) {'],
    'a thunk is made again for the same row and target' => ['(sThunks[i].real == real) )', '(sThunks[i].real == real) && false )'],
    'an unsupported row is bound as if supported' => [/if \( row->status == AdapterStatus::Unsupported \) \{(\s+dyld::warn)/, 'if ( false ) {\1'],
    'a handled-elsewhere row warns or is thunked' => [/if \( row->status == AdapterStatus::HandledElsewhere \)\s+return target;\n/, ''],
    'an arm64e target is thunked' => ['if ( (sMode == AdapterMode::Off) || targetIsArm64e )', 'if ( sMode == AdapterMode::Off )'],
    'the kill switch does nothing' => ['if ( (sMode == AdapterMode::Off) || targetIsArm64e )', 'if ( targetIsArm64e )'],
    'report mode names a symbol every time' => [/if \( sReported\[i\] == hash \)\s+return;/, ''],
    'report mode is always on' => [/if \( sMode == AdapterMode::Report \)\s+reportMissingRow\(symbol\);/, 'reportMissingRow(symbol);'],
    'the validator accepts a nine-argument row' => ['(r.argCount > 8)', '(r.argCount > 9)'],
    'the validator accepts a duplicate symbol' => ['return "a symbol has two rows";', ''],
    'the row of _atexit authenticates the wrong argument' => ['{ "_atexit", 0x1,', '{ "_atexit", 0x2,', :rows],
    'the row of _pthread_create authenticates the wrong argument' => ['{ "_pthread_create", 0x4,', '{ "_pthread_create", 0x2,', :rows],
    'the row of _signal has no return fix' => ['0x2, 0, 0, ReturnFix::SignInstalledHandler,', '0x2, 0, 0, ReturnFix::None,', :rows],
    'the row of _qsort is dropped' => [/^\t\{ "_qsort",.*\n/, '', :rows],
    'a row of the facts (_glob) is dropped' => [/^\t\{ "_glob",.*\n/, '', :rows],
    'a row of the facts (_dispatch_after_f) has the wrong argument' => ['{ "_dispatch_after_f", 0x8,', '{ "_dispatch_after_f", 0x4,', :rows],
    'a block-taking import of the facts (_dispatch_after) is made a shape-only strip' => [/\{ "_dispatch_after", 0x0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported/, '{ "_dispatch_after", 0x4, 0, 0, ReturnFix::None, 3, AdapterStatus::ShapeOnly', :rows],
    'the _Unwind_Resume row is unsupported (it would warn on every C++ program)' => [/\{ "__Unwind_Resume", 0x0, 0, 0, ReturnFix::None, 0, AdapterStatus::HandledElsewhere/, '{ "__Unwind_Resume", 0x0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported', :rows],
  }
  killed = 0
  mutants.each_with_index do |(desc, (from, to, where)), i|
    text = where == :rows ? rows_source : source
    unless text.scan(from).size == 1
      check "mutant applies: #{desc}", false, "#{text.scan(from).size} matches"
      next
    end
    mutated = from.is_a?(Regexp) ? text.sub(from, to) : text.sub(from) { to }
    mexe, merr = build(root, dir, "mutant#{i}", adapters_text: (where == :rows ? nil : mutated), rows_text: (where == :rows ? mutated : nil))
    dead = mexe.nil? || begin
      mout, mst = run(mexe)
      !mst.success? || mout =~ /^FAIL/
    end
    # a mutated table row is caught by the comparison with the spec, which reads the rows output
    spec_dead = !mexe.nil? && run(mexe, 'rows')[0].lines.grep(/^ROW/).map { |l| l.split }.to_h { |f| [f[1], f[2..].map(&:to_i)] } != SPEC
    bytes_dead = false
    if mexe && HAVE_MC && !dead
      # a thunk-shape mutant that the native run does not see is still caught by the assembler comparison
      bad = (1..255).any? do |mask|
        regs = (0..7).select { |b| mask[b] == 1 }
        want = mc_words((regs.flat_map { |b| ["add x16, x#{b}, #1", 'cmp x16, #2', 'b.ls #8', "autiza x#{b}"] } + ['ldr x16, #8', 'br x16']).join("\n"))
        run(mexe, 'auth-thunk', mask.to_s)[0].split.map { |w| w.to_i(16) } != want + [0x55667788, 0x11223344]
      end
      bytes_dead = bad
    end
    killed += 1 if dead || spec_dead || bytes_dead
    check "mutation probe killed: #{desc}", dead || spec_dead || bytes_dead, merr[0, 200]
  end
  puts "probes killed #{killed}/#{mutants.size}"
end

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILURES")
exit($failures.zero? ? 0 : 1)
