# dyld3/SupportedArchs.h enables SUPPORT_ARCH_arm64e for an arm64e build only (MachOFile::GradedArchs::forCurrentOS names
# the arm64e members there) and leaves plain arm64 and x86_64 builds unchanged. Pure preprocessing, runs on any host with clang.
# usage: ruby tests/supported-archs-arm64e.rb [checkout]
require 'tmpdir'
require 'open3'
require 'fileutils'

root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
header = File.read("#{root}/dyld3/SupportedArchs.h")

def defined_for(dir, header, target)
  FileUtils.mkdir_p(dir)
  File.write("#{dir}/TargetConditionals.h", '')
  File.write("#{dir}/SupportedArchs.h", header)
  File.write("#{dir}/probe.h", "#include \"SupportedArchs.h\"\n#ifdef SUPPORT_ARCH_arm64e\nENABLED SUPPORT_ARCH_arm64e\n#else\nDISABLED\n#endif\n")
  out, err, st = Open3.capture3('clang', '-E', '-P', '-x', 'c', '-target', target, '-I', dir, "#{dir}/probe.h")
  abort "clang failed for #{target}: #{err}" unless st.success?
  out.include?('ENABLED')
end

$failures = 0
def check(desc, ok)
  puts "#{ok ? 'PASS' : 'FAIL'} #{desc}"
  $failures += 1 unless ok
end

Dir.mktmpdir('supported-archs-') do |dir|
  check 'arm64e enables SUPPORT_ARCH_arm64e', defined_for("#{dir}/a", header, 'arm64e-apple-darwin20')
  check 'arm64 leaves it undefined', !defined_for("#{dir}/b", header, 'arm64-apple-darwin20')
  check 'aarch64 leaves it undefined', !defined_for("#{dir}/c", header, 'aarch64-apple-darwin20')
  check 'x86_64 leaves it undefined', !defined_for("#{dir}/d", header, 'x86_64-apple-darwin20')
  # probes: each mutant must make a check fail
  {
    'always defined' => ['#if __arm64e__ && !defined(SUPPORT_ARCH_arm64e)', '#if 1'],
    'never defined' => ['#if __arm64e__ && !defined(SUPPORT_ARCH_arm64e)', '#if 0'],
  }.each_with_index do |(name, (from, to)), i|
    abort "probe text missing: #{name}" unless header.scan(from).size == 1
    m = header.sub(from) { to }
    killed = defined_for("#{dir}/m#{i}a", m, 'arm64e-apple-darwin20') == false || defined_for("#{dir}/m#{i}b", m, 'arm64-apple-darwin20') == true
    check "probe killed: #{name}", killed
  end
end
puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
