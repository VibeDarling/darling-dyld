# Host tests for the cache TSD translation module (dyld3/DarlingTSDIslands.cpp). Needs an ARM64 Linux host with clang++.
# usage: ruby tests/darling-tsd-islands.rb REPO [--probes]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'yaml'

root = File.realpath(ARGV.fetch(0))
run_probes = ARGV.include?('--probes')

def build_and_run(dir, root, sources)
  exe = "#{dir}/islands_test"
  cmd = ['clang++', '-std=c++17', '-O1', '-Wall', '-Werror', '-I', "#{dir}/dyld3", '-o', exe,
         "#{root}/tests/darling-tsd/islands_test.cpp", "#{root}/tests/darling-tsd/oracle.S", *sources, '-lpthread']
  out, status = Open3.capture2e(*cmd)
  return [false, "build failed:\n#{out}"] unless status.success?
  out, status = Open3.capture2e(exe)
  [status.success?, out]
end

abort 'needs an ARM64 host' unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/

Dir.mktmpdir('darling-tsd-islands-') do |dir|
  FileUtils.mkdir_p("#{dir}/dyld3")
  FileUtils.cp(Dir["#{root}/dyld3/DarlingTSDIslands.*"], "#{dir}/dyld3")
  ok, out = build_and_run(dir, root, ["#{dir}/dyld3/DarlingTSDIslands.cpp"])
  puts out
  abort 'tests failed' unless ok
  next unless run_probes

  probes = YAML.load_file("#{root}/tests/darling-tsd/probes.yml")
  killed = 0
  probes.each do |probe|
    path = "#{dir}/dyld3/#{probe.fetch('file')}"
    original = File.read(path)
    abort "probe text not found: #{probe['name']}" unless original.include?(probe.fetch('from'))
    File.write(path, original.sub(probe['from'], probe.fetch('to')))
    ok, out = build_and_run(dir, root, ["#{dir}/dyld3/DarlingTSDIslands.cpp"])
    File.write(path, original)
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
