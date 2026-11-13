# Initializer order: the recursion of ImageLoader::recursiveInitialization / processInitializers (extracted from
# src/ImageLoader.cpp, with the real recursiveUpdateDepth / updateDepth computing the depths as link() does) is run over
# synthetic dependency graphs and compared with a reference of dyld4's rule (dyld-1378 Loader.cpp runInitializersBottomUp):
# depth first over the non-upward dependents in load-command order, an image is marked at entry so a cycle member that is
# in progress is skipped, upward dependents are deferred until the walk is done, and an image runs after its dependents.
# The cluster graph copies the shape that trapped macOS stock apps under Darling: CoreFoundation, libobjc, libswiftCore and
# Foundation form a cycle and Metal sits below Foundation, so Metal must not run before CoreFoundation has.
# Mutants (--probes is implied): each must fail at least one check.
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

# reference: dyld4's runInitializersBottomUp over [roots..., main]
def reference(graph, roots_first = [])
  deps = Hash.new { |h, k| h[k] = [] }
  main = nil
  graph.each_line do |l|
    w = l.split
    deps[w[1]] << [w[2], w[3]] if w[0] == 'edge'
    main = w[1] if w[0] == 'main'
  end
  visited = {}; order = []
  walk = lambda do |n, ups|
    return if visited[n]
    visited[n] = true
    deps[n].each { |(d, k)| k == 'u' ? ups << d : walk.call(d, ups) }
    order << n
  end
  (roots_first + [main]).each do |r|
    ups = []
    walk.call(r, ups)
    until ups.empty?
      more = []
      ups.each { |u| walk.call(u, more) }
      ups = more
    end
  end
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

Dir.mktmpdir('initializer-order-') do |dir|
  plain = run_harness(FUNCS, '', '', CYCLE, dir)
  check 'a cycle: the order is dyld4\'s (every image once)', plain == reference(CYCLE), "#{plain.inspect} vs #{reference(CYCLE).inspect}"
  g = run_harness(FUNCS, '', '', CLUSTER + "root libSystem\n", dir)
  check 'cluster graph: every image runs once', g.sort == g.uniq.sort && g.size == 11, g.inspect
  check 'cluster graph: the order is dyld4\'s', g == reference(CLUSTER, ['libSystem']), "#{g.inspect} vs #{reference(CLUSTER, ['libSystem']).inspect}"
  # the depth test: with it a dependent whose depth the cycle made lower is not entered from the image that needs it
  gate = FUNCS.merge(rec: FUNCS[:rec].sub(/^(\t+)else \{\n/, "\\1else if ( dependentImage->fDepth >= fDepth ) {\n"))
  check 'mutant: restoring the depth test is detected', gate[:rec] != FUNCS[:rec] &&
    (run_harness(gate, '', '', CLUSTER + "root libSystem\n", dir) != reference(CLUSTER, ['libSystem']) || run_harness(gate, '', '', CYCLE, dir) != reference(CYCLE))
  noup = FUNCS.merge(rec: FUNCS[:rec].sub('if ( libIsUpward(i) ) {', 'if ( false ) {'))
  check 'mutant: treating upward dependents as regular is detected', noup[:rec] != FUNCS[:rec] &&
    run_harness(noup, '', '', CLUSTER + "root libSystem\n", dir) != reference(CLUSTER, ['libSystem'])
end

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
