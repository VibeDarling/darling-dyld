# Execute the existing C fixture against the extracted production C++ API.
# Host linkage checks C symbol naming, not final Darwin libdyld exports.
require 'open3'
require 'tmpdir'
root = File.expand_path('..', __dir__)
source = File.read("#{root}/src/dyldAPIsInLibSystem.cpp")
method = source[/extern "C" void _dyld_stack_range\(.*?\n\}/m]
abort 'stack-range definition missing' unless method
Dir.mktmpdir('dyld-stack-range') do |dir|
  File.write("#{dir}/api.cpp", method)
  commands = [
    ['clang++', '-std=c++11', '-c', "#{dir}/api.cpp", '-o', "#{dir}/api.o"],
    ['clang', '-UNDEBUG', '-c', "#{root}/tests/auxiliary_stack_range.c", '-o', "#{dir}/test.o"],
    ['clang++', "#{dir}/api.o", "#{dir}/test.o", '-o', "#{dir}/test"],
    ["#{dir}/test"]
  ]
  commands.each do |command|
    output, status = Open3.capture2e(*command)
    abort output unless status.success?
  end
end
puts 'PASS: production C++ API linked to C fixture, sentinel outputs and null-pointer combinations'
