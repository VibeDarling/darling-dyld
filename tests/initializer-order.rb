# Initializer order. The recursion (ImageLoader::recursiveInitialization / processInitializers, extracted from
# src/ImageLoader.cpp, with the real recursiveUpdateDepth / updateDepth computing the depths as link() does) is run over
# synthetic dependency graphs and compared with a reference of dyld4's walk (dyld-1378 Loader.cpp runInitializersBottomUp):
# depth first over the non-upward dependents in load-command order, an image marked at entry so a cycle member that is in
# progress is skipped, upward dependents deferred until the walk is done, an image running after its dependents.
#
# The start of the order DIVERGES FROM DYLD4 on purpose. dyld4 (DyldAPIs.cpp:4042-4075) runs libSystem's own initializer
# and each libsystem image's own initializer, following no upward link, then walks the main executable. Darling mixes its
# own libSystem family with the macOS cache's images, so its graph has a cycle dyld4 never sees on macOS (CoreFoundation,
# libobjc, libswiftCore and Foundation, with Metal below Foundation). The cluster graph here has that shape; dyld4's own
# steps leave Metal before CoreFoundation on it (checked below as a model, the reason for the divergence), so
# initializeMainExecutable runs libSystem's whole walk and then libobjc's, by install name, before the main executable.
# The helpers are extracted from src/dyld2.cpp and run against stub images; the roots they run feed the walk. The graph is
# also checked without the upward link from libxpc to libobjc, which the order must not depend on.
# Mutants (always run): each must fail at least one check.
# Usage: ruby tests/initializer-order.rb [checkout]
require 'tmpdir'
require 'open3'

ROOT = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
SRC = File.read("#{ROOT}/src/ImageLoader.cpp")
$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

def cut(re, what)
  SRC[re] or abort "#{what} missing from src/ImageLoader.cpp"
end

FUNCS = {
  rec: cut(/^void ImageLoader::recursiveInitialization\(.*?^\}/m, 'recursiveInitialization'),
  proc: cut(/^void ImageLoader::processInitializers\(.*?^\}/m, 'processInitializers'),
  depth_rec: cut(/^unsigned int ImageLoader::recursiveUpdateDepth\(.*?^\}/m, 'recursiveUpdateDepth'),
  depth: cut(/^unsigned int ImageLoader::updateDepth\(.*?^\}/m, 'updateDepth'),
}

HARNESS = <<~'CPP'
  #include <stdint.h>
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <string>
  #include <vector>
  #include <map>
  #include <utility>
  #include <algorithm>
  #include <iostream>
  #include <sstream>
  typedef uint32_t mach_port_t;
  static uint64_t mach_absolute_time() { return 0; }
  #define DYLD_LOG(...) ((void)0)
  enum dyld_image_states { dyld_image_state_dependents_initialized = 45, dyld_image_state_initialized = 50 };
  namespace dyld3 { template <class T> struct Array : std::vector<T> { bool contains(T v) const { return std::find(this->begin(), this->end(), v) != this->end(); } }; }
  #define STACK_ALLOC_ARRAY(T, name, n) dyld3::Array<T> name
  class ImageLoader;
  struct recursive_lock { recursive_lock(mach_port_t) {} };
  struct Edge { int to; char kind; };
  struct Node { std::string name; std::vector<Edge> deps; };
  static std::vector<Node> gNodes;
  static std::vector<std::string> gOrder;
  class ImageLoader {
  public:
    struct InitializerTimingList { uintptr_t count; void addTime(const char*, uint64_t) {} };
    struct UninitedUpwards { uintptr_t count; std::pair<ImageLoader*, const char*> imagesAndPaths[1]; };
    struct LinkContext {
      void (*terminationRecorder)(ImageLoader*) = nullptr;
      void (*notifySingle)(dyld_image_states, const ImageLoader*, InitializerTimingList*) = nullptr;
      unsigned imageCount() const { return (unsigned)gNodes.size(); }
    };
    int index; uint8_t fState = 0; uint16_t fDepth = 0; bool fAllLibraryChecksumsAndLoadAddressesMatch = true;
    ImageLoader* libImage(unsigned i) const;
    bool libIsUpward(unsigned i) const { return gNodes[index].deps[i].kind == 'u'; }
    unsigned libraryCount() const { return (unsigned)gNodes[index].deps.size(); }
    const char* libPath(unsigned) const { return "x"; }
    const char* getPath() const { return gNodes[index].name.c_str(); }
    bool needsTermination() { return false; }
    bool doInitialization(const LinkContext&) { gOrder.push_back(gNodes[index].name); return true; }
    void recursiveSpinLock(recursive_lock&) {}
    void recursiveSpinUnLock() {}
    void recursiveInitialization(const LinkContext&, mach_port_t, const char*, InitializerTimingList&, UninitedUpwards&);
    void processInitializers(const LinkContext&, mach_port_t, InitializerTimingList&, UninitedUpwards&);
    unsigned recursiveUpdateDepth(unsigned, dyld3::Array<ImageLoader*>&);
    unsigned updateDepth(unsigned);
    const char* getShortName() const { return gNodes[index].name.c_str(); }
  };
  static std::vector<ImageLoader> gImages;
  ImageLoader* ImageLoader::libImage(unsigned i) const { return &gImages[gNodes[index].deps[i].to]; }
  static void noteSingle(dyld_image_states, const ImageLoader*, ImageLoader::InitializerTimingList*) {}
  @@FUNCS@@
  @@EXTRA@@
  int main() {
    std::string line; std::map<std::string, int> id; int mainIdx = -1; std::vector<std::string> roots;
    auto get = [&](const std::string& n) { if ( !id.count(n) ) { id[n] = (int)gNodes.size(); gNodes.push_back({n, {}}); } return id[n]; };
    while ( std::getline(std::cin, line) ) {
      std::istringstream is(line); std::string cmd; is >> cmd;
      if ( cmd == "edge" ) { std::string a, b, k; is >> a >> b >> k; int ia = get(a), ib = get(b); gNodes[ia].deps.push_back({ib, k[0]}); }
      else if ( cmd == "main" ) { std::string a; is >> a; mainIdx = get(a); }
      else if ( cmd == "root" ) { std::string a; is >> a; roots.push_back(a); }
    }
    gImages.resize(gNodes.size());
    for (size_t i = 0; i < gImages.size(); ++i) gImages[i].index = (int)i;
    ImageLoader::LinkContext ctx; ctx.notifySingle = noteSingle;
    gImages[mainIdx].updateDepth(ctx.imageCount());
    ImageLoader::InitializerTimingList timing; timing.count = 0;
    @@RUN@@
    for (auto& n : gOrder) printf("%s\n", n.c_str());
    return 0;
  }
CPP

# each "root" line is run as its own runInitializers() call, then the main executable, like initializeMainExecutable
RUN_MAIN = 'std::vector<int> order; for (auto& r : roots) order.push_back(id[r]); order.push_back(mainIdx); ' \
           'for (int n : order) { ImageLoader::UninitedUpwards up; up.count = 1; up.imagesAndPaths[0] = { &gImages[n], "x" }; gImages[n].processInitializers(ctx, 0, timing, up); }'

def run_harness(funcs, extra, run_code, graph, dir)
  run_code = RUN_MAIN if run_code.empty?
  src = HARNESS.sub('@@FUNCS@@') { funcs.values_at(:rec, :proc, :depth_rec, :depth).join("\n") }.sub('@@EXTRA@@') { extra }.sub('@@RUN@@') { run_code }
  File.write("#{dir}/t.cpp", src)
  o, s = Open3.capture2e('c++', '-std=c++17', '-w', '-o', "#{dir}/t", "#{dir}/t.cpp")
  abort "harness build failed:\n#{o}" unless s.success?
  out, st = Open3.capture2("#{dir}/t", stdin_data: graph)
  abort 'harness run failed' unless st.success?
  out.split("\n")
end

# reference: dyld4's runInitializersBottomUp, started at each of `starts` in turn and then at the main executable
def parse(graph)
  deps = Hash.new { |h, k| h[k] = [] }
  main = nil
  graph.each_line do |l|
    w = l.split
    deps[w[1]] << [w[2], w[3]] if w[0] == 'edge'
    main = w[1] if w[0] == 'main'
  end
  [deps, main]
end

def walk_from(deps, visited, order, start)
  ups = []
  walker = lambda do |n|
    return if visited[n]
    visited[n] = true
    deps[n].each { |(d, k)| k == 'u' ? ups << d : walker.call(d) }
    order << n
  end
  walker.call(start)
  until ups.empty?
    pending = ups
    ups = []
    pending.each { |u| walker.call(u) }
  end
end

def reference(graph, starts = [])
  deps, main = parse(graph)
  visited = {}; order = []
  (starts + [main]).each { |s| walk_from(deps, visited, order, s) }
  order
end

# dyld4's own steps: libSystem's initializer alone, each libsystem image's initializer alone (no dependents, no upward
# link), then the walk of the main executable
def dyld4_literal(graph, below)
  deps, main = parse(graph)
  visited = {}; order = []
  (['libSystem'] + below).each { |n| visited[n] = true; order << n }
  walk_from(deps, visited, order, main)
  order
end

# CoreFoundation > libobjc (re-export) > libswiftCore > Foundation > ... > Metal, as the stock apps reach it
CLUSTER = <<~G
  main Dictionary
  edge Dictionary CFNetwork r
  edge Dictionary libSystem r
  edge CFNetwork CoreFoundation r
  edge CoreFoundation libobjc R
  edge CoreFoundation Foundation u
  edge CoreFoundation libSystem r
  edge libobjc libswiftCore r
  edge libobjc libSystem r
  edge libswiftCore Foundation r
  edge libswiftCore CoreFoundation r
  edge Foundation libobjc R
  edge Foundation CoreFoundation R
  edge Foundation SystemConfiguration r
  edge SystemConfiguration QuartzCore r
  edge QuartzCore Metal r
  edge Metal CoreFoundation r
  edge Metal libSystem r
  edge libSystem libxpc r
  edge libxpc libobjc u
G
CLUSTER_NO_UPWARD = CLUSTER.sub("edge libxpc libobjc u\n", '')
# a cycle that gives a dependent a lower depth than its dependents: A > B > C > A, A also reaches D which depends on B
CYCLE = <<~G
  main M
  edge M A r
  edge A B r
  edge A D r
  edge B C r
  edge C A r
  edge D B r
  edge D X r
G

DYLD2 = File.read("#{ROOT}/src/dyld2.cpp")
HELPERS = DYLD2[/^static void runInitializersOf\(.*?^\}\n\nstatic void runRuntimeInitializersFirst\(.*?^\}/m] or abort 'runInitializersOf / runRuntimeInitializersFirst missing from src/dyld2.cpp'
INIT_MAIN = DYLD2[/^void initializeMainExecutable\(\)\n\{.*?^\}/m] or abort 'initializeMainExecutable missing'
STUB = <<~'CPP'
  #include <string.h>
  #include <stdio.h>
  #include <vector>
  struct Timing { };
  struct Ctx { } gLinkContext;
  static const char* libSystemPath(const Ctx&) { return "/usr/lib/libSystem.B.dylib"; }
  struct ImageLoader {
    typedef Timing InitializerTimingList;
    const char* install; const char* tag;
    const char* getInstallPath() const { return install; }
    void runInitializers(const Ctx&, Timing&) { printf("%s\n", tag); }
  };
  static std::vector<ImageLoader*> sAllImages;
  @@HELPER@@
  int main() {
    ImageLoader a = { "/usr/lib/libSystem.B.dylib.fake", "decoy" }, b = { nullptr, "noname" }, c = { "/Applications/X.app/Contents/MacOS/X", "main" },
                d = { "/usr/lib/libobjc.A.dylib", "libobjc" }, e = { "/usr/lib/libSystem.B.dylib", "libSystem" }, f = { "/usr/lib/libSystem.B.dylib", "second" },
                g = { "/usr/lib/libobjc.A.dylib.fake", "decoy2" };
    Timing t;
    sAllImages = { &a, &b, &c, &d, &e, &f, &g };   // libobjc is listed before libSystem: the order of the run must not follow the list
    runRuntimeInitializersFirst(t);
    printf("--\n");
    sAllImages = { &a, &b, &c, &g };
    runRuntimeInitializersFirst(t);
    return 0;
  }
CPP
def run_helpers(text, dir)
  File.write("#{dir}/h.cpp", STUB.sub('@@HELPER@@') { text })
  o, s = Open3.capture2e('c++', '-std=c++17', '-w', '-o', "#{dir}/h", "#{dir}/h.cpp")
  abort "helper build failed:\n#{o}" unless s.success?
  Open3.capture2("#{dir}/h").first.split("\n")
end

Dir.mktmpdir('initializer-order-') do |dir|
  plain = run_harness(FUNCS, '', '', CYCLE, dir)
  check 'a cycle: the order is dyld4\'s (every image once)', plain == reference(CYCLE), "#{plain.inspect} vs #{reference(CYCLE).inspect}"

  ran = run_helpers(HELPERS, dir)
  check 'libSystem then libobjc run once each, by exact install name, whatever the list order; neither present is a no-op',
        ran == %w[libSystem libobjc --], ran.inspect
  roots = ran - ['--']
  [['with', CLUSTER], ['without', CLUSTER_NO_UPWARD]].each do |label, graph|
    g = run_harness(FUNCS, '', '', graph + roots.map { |r| "root #{r}\n" }.join, dir)
    expected = reference(graph, roots)
    check "cluster graph #{label} the libxpc upward link: every image runs once", g.sort == g.uniq.sort && g.size == 11, g.inspect
    check "cluster graph #{label} the libxpc upward link: CoreFoundation runs before Metal", g.index('CoreFoundation') && g.index('Metal') && g.index('CoreFoundation') < g.index('Metal'), g.inspect
    check "cluster graph #{label} the libxpc upward link: the order is the walk of libSystem, libobjc, the main executable", g == expected, "#{g.inspect} vs #{expected.inspect}"
  end
  lit = dyld4_literal(CLUSTER, ['libxpc'])
  check 'model of dyld4\'s own steps: Metal runs before CoreFoundation on the cluster graph (why this diverges)', lit.index('Metal') < lit.index('CoreFoundation'), lit.inspect

  # mutants of the recursion
  gate = FUNCS.merge(rec: FUNCS[:rec].sub(/^(\t+)else \{\n/, "\\1else if ( dependentImage->fDepth >= fDepth ) {\n"))
  walk = roots.map { |r| "root #{r}\n" }.join
  check 'mutant: restoring the depth test is detected', gate[:rec] != FUNCS[:rec] &&
    (run_harness(gate, '', '', CLUSTER + walk, dir) != reference(CLUSTER, roots) || run_harness(gate, '', '', CYCLE, dir) != reference(CYCLE))
  noup = FUNCS.merge(rec: FUNCS[:rec].sub('if ( libIsUpward(i) ) {', 'if ( false ) {'))
  check 'mutant: treating upward dependents as regular is detected', noup[:rec] != FUNCS[:rec] &&
    run_harness(noup, '', '', CLUSTER + walk, dir) != reference(CLUSTER, roots)

  # mutants of the helpers
  no_objc = HELPERS.sub(/^\trunInitializersOf\("\/usr\/lib\/libobjc.A.dylib", timingInfo\);\n/, '')
  check 'mutant: no explicit libobjc step is detected without the libxpc upward link', no_objc != HELPERS &&
    (run_helpers(no_objc, dir) - ['--']).then { |r| run_harness(FUNCS, '', '', CLUSTER_NO_UPWARD + r.map { |x| "root #{x}\n" }.join, dir) != reference(CLUSTER_NO_UPWARD, roots) }
  prefix = HELPERS.sub('strcmp(installPath, installName) == 0', 'strncmp(installPath, installName, strlen(installName) - 1) == 0')
  check 'mutant: matching a prefix of the install name is detected', prefix != HELPERS && run_helpers(prefix, dir) != ran
  every = HELPERS.sub("\t\t\treturn;\n", '')
  check 'mutant: running every match is detected', every != HELPERS && run_helpers(every, dir) != ran
  hard = HELPERS.sub('libSystemPath(gLinkContext)', '"/usr/lib/libSystem.B.dylib.fake"')
  check 'mutant: a wrong libSystem path is detected', hard != HELPERS && run_helpers(hard, dir) != ran
end

# the call order in initializeMainExecutable: libSystem and libobjc first, then the inserted dylibs, then the main executable
body = INIT_MAIN
first = body.index('runRuntimeInitializersFirst(')
check 'initializeMainExecutable runs the helpers before the inserted dylibs and the main executable',
      first && first < body.index('sImageRoots[i]->runInitializers') && first < body.index('sMainExecutable->runInitializers')
late = body.sub(/\trunRuntimeInitializersFirst\(.*?\);\n/, '').sub("\tsMainExecutable->runInitializers(gLinkContext, initializerTimes[0]);", "\tsMainExecutable->runInitializers(gLinkContext, initializerTimes[0]);\n\trunRuntimeInitializersFirst(initializerTimes[0]);")
check 'mutant: running them after the main executable is detected', late != body &&
      late.index('runRuntimeInitializersFirst(') > late.index('sMainExecutable->runInitializers')

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
