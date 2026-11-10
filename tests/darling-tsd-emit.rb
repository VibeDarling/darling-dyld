# Tests for the TSD site table emitter (tests/darling-tsd/emit_tsd_sites.py).
# usage: ruby tests/darling-tsd-emit.rb REPO [--probes]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'yaml'

root = File.realpath(ARGV.fetch(0))
tests = "#{root}/tests/darling-tsd"
abort 'needs an ARM64 host' unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/

def run(*cmd)
  out, status = Open3.capture2e(*cmd)
  [status.success?, out]
end

def emit_checks(root, tests, emitter, dir)
  ok, out = run('python3', '-I', "#{tests}/emit_test.py", emitter, "#{dir}/keep")
  return [false, out] unless ok
  [ok, out]
end

Dir.mktmpdir('darling-tsd-emit-') do |dir|
  ok, out = emit_checks(root, tests, "#{tests}/emit_tsd_sites.py", dir)
  puts out
  abort 'emitter tests failed' unless ok

  next unless ARGV.include?('--probes')
  probes = YAML.load_file("#{tests}/emit_probes.yml")
  killed = 0
  probes.each do |probe|
    copy = "#{dir}/probe_emit.py"
    original = File.read("#{tests}/#{probe.fetch('file')}")
    abort "probe text not found: #{probe['name']}" unless original.include?(probe.fetch('from'))
    File.write(copy, original.sub(probe['from'], probe.fetch('to')))
    ok, out = emit_checks(root, tests, copy, dir)
    if ok
      puts "SURVIVED #{probe['name']}"
    else
      killed += 1
      puts "killed   #{probe['name']}"
    end
  end
  puts "#{killed}/#{probes.size} probes killed"
  abort 'a probe survived' unless killed == probes.size
end
