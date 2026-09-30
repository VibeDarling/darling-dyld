# Build real LC_REEXPORT_DYLIB cycles using staged compiler/linker recipes.
require 'open3'
require 'shellwords'
require 'tmpdir'
w=File.realpath(ARGV.fetch(0))
b="#{w}/build-arm64-stage18"
out,ok=Open3.capture2('ninja','-C',b,'-t','commands','src/tools/Controls')
abort 'recipe missing' unless ok.success?
remap=->(s){s.gsub('/work/source',"#{w}/source").gsub('/work/build',b)}
compile=out.lines.find{|l|l.include?(' -c ') && l.include?('controls/Controls.m')}
cc=Shellwords.split(remap.call(compile.split(' -MD ').first))
ld=Shellwords.split(remap.call(out.lines.last.sub(/\A: && /,'').sub(/ && :\s*\z/,'')))
ld.reject!{|s|s.end_with?('controls/Controls.m.o') || s.end_with?('start.S.o') || ['src/external/cocotron/AppKit/AppKit','src/external/foundation/Foundation'].include?(s)}
ld.slice!(ld.index('-o'),2)
dir=Dir.mktmpdir('reexport-cycle-')
File.write("#{dir}/empty.c",'int reexport_anchor(void) { return 1; }')
File.write("#{dir}/leaf.c",'int reexport_leaf(void) { return 71; }')
%w[empty leaf].each{|name|abort 'compile failed' unless system(*cc,'-c',"#{dir}/#{name}.c",'-o',"#{dir}/#{name}.o")}
link=->(name,object,deps){
  args=ld+['-dynamiclib',"#{dir}/#{object}.o",'-o',"#{dir}/#{name}.dylib","-Wl,-install_name,/probe-libraries/#{name}.dylib"]
  deps.each{|dep|args<<"-Wl,-reexport_library,#{dir}/#{dep}.dylib"}
  abort "link #{name} failed" unless system(*args,chdir:b)
}
link.call('A','empty',[])
link.call('B','empty',['A'])
link.call('Leaf','leaf',[])
link.call('A','empty',['B','Leaf'])
puts "libraries=#{dir}"
