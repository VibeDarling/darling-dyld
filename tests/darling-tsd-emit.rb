# Tests for the TSD site table emitter (tests/darling-tsd/emit_tsd_sites.py) and the placement over what it emits.
# usage: ruby tests/darling-tsd-emit.rb REPO [--probes]
# With DARLING_TSD_CACHE=<main cache file> set, also emits the table of that real cache (read-only, slow, about 4 GiB
# of reads) and runs the placement over it.
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
  ok2, out2 = run('clang++', '-std=c++17', '-O1', '-Wall', '-Werror', '-I', "#{root}/dyld3", '-o', "#{dir}/plan_check",
                  "#{tests}/plan_check.cpp", "#{root}/dyld3/DarlingTSDIslands.cpp")
  return [false, out2] unless ok2
  ok3, out3 = run("#{dir}/plan_check", "#{dir}/keep/fixture.tsdsites", '180000000', '8')
  [ok3, out + out3]
end

Dir.mktmpdir('darling-tsd-emit-') do |dir|
  ok, out = emit_checks(root, tests, "#{tests}/emit_tsd_sites.py", dir)
  puts out
  abort 'emitter tests failed' unless ok

  if ENV['DARLING_TSD_CACHE']
    ok, out = run('python3', '-I', "#{tests}/emit_tsd_sites.py", ENV['DARLING_TSD_CACHE'], "#{dir}/real.tsdsites", '--summary')
    puts out
    abort 'real cache emission failed' unless ok
    # the base is the main file's region start, as the table says through its offsets
    ok, out = run("#{dir}/plan_check", "#{dir}/real.tsdsites", '180000000', '1000')
    puts out
    abort 'placement over the real cache failed' unless ok
  end

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
