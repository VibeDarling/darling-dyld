# Actual Mach-O lookup traversal with controlled shallow-export collaborators.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source=File.read("#{root}/src/ImageLoaderMachO.cpp")
lookup=source[/const ImageLoader::Symbol\* ImageLoaderMachO::findExportedSymbol\(.*?^\}/m] or abort 'lookup missing'
Dir.mktmpdir('export-context-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <vector>
    #include <string.h>
    #include <assert.h>
    #include <stdio.h>
    #include <pthread.h>
    class ImageLoader {
    public:
      struct Symbol { int value=71; };
      struct ExportLookup { const ImageLoader* image; const char* name; const ExportLookup* parent; bool searchReExports; };
      virtual const Symbol *findExportedSymbol(const char*,bool,const char*,const ImageLoader**,const ExportLookup* =nullptr) const=0;
      virtual ~ImageLoader() {}
    };
    class ImageLoaderMachO:public ImageLoader {
    public:
      std::vector<ImageLoader*> children;
      const char *definition=nullptr, *aliasFrom=nullptr, *aliasTo=nullptr;
      ImageLoader *aliasTarget=nullptr;
      Symbol symbol;
      unsigned libraryCount() const { return children.size(); }
      bool libReExported(unsigned) const { return true; }
      ImageLoader *libImage(unsigned i) const { return children[i]; }
      const char *libPath(unsigned) const { return "fixture"; }
      const Symbol *findShallowExportedSymbol(const char *name,const ImageLoader **foundIn,const ExportLookup *parent=nullptr) const {
        if (definition && strcmp(definition,name)==0) { *foundIn=this; return &symbol; }
        if (aliasFrom && strcmp(aliasFrom,name)==0)
          return aliasTarget->findExportedSymbol(aliasTo,true,"alias",foundIn,parent);
        return nullptr;
      }
      const Symbol *findExportedSymbol(const char*,bool,const char*,const ImageLoader**,const ExportLookup* =nullptr) const;
    };
    #{lookup}
    static ImageLoaderMachO graph[3];
    static void *worker(void*) {
      for (unsigned i=0;i<1000;++i) {
        const ImageLoader *found=nullptr;
        assert(graph[0].findExportedSymbol("present",true,"root",&found)==&graph[2].symbol);
        assert(found==&graph[2]);
        assert(!graph[0].findExportedSymbol("absent",true,"root",&found));
      }
      return nullptr;
    }
    int main() {
      graph[0].children={&graph[1],&graph[2]};
      graph[1].children={&graph[0]}; graph[2].definition="present";
      worker(nullptr);
      const ImageLoader *found=nullptr;
      assert(!graph[0].findExportedSymbol("present",false,"root",&found));
      ImageLoaderMachO self;
      self.children={&self}; assert(!self.findExportedSymbol("absent",true,"self",&found));
      // Same image under a different symbol remains a legitimate search.
      self.children.clear(); self.aliasFrom="alias"; self.aliasTo="target";
      self.aliasTarget=&self; self.definition="target";
      assert(self.findExportedSymbol("alias",true,"self",&found)==&self.symbol);
      // A renamed-symbol cycle must terminate, not reset the ancestry.
      ImageLoaderMachO a,b;
      a.aliasFrom="a"; a.aliasTo="b"; a.aliasTarget=&b;
      b.aliasFrom="b"; b.aliasTo="a"; b.aliasTarget=&a;
      assert(!a.findExportedSymbol("a",true,"a",&found));
      ImageLoaderMachO mode;
      mode.aliasFrom="present"; mode.aliasTo="present"; mode.aliasTarget=&mode;
      mode.children={&graph[2]};
      assert(mode.findExportedSymbol("present",false,"mode",&found)==&graph[2].symbol);
      std::vector<ImageLoaderMachO> chain(512);
      for (unsigned i=0;i+1<chain.size();++i) chain[i].children={&chain[i+1]};
      chain.back().definition="deep";
      assert(chain[0].findExportedSymbol("deep",true,"chain",&found)==&chain.back().symbol);
      pthread_t threads[4];
      for (auto &thread:threads) assert(pthread_create(&thread,nullptr,worker,nullptr)==0);
      for (auto &thread:threads) assert(pthread_join(thread,nullptr)==0);
      puts("PASS actual lookup cycles, renamed aliases, alternate branches, 512-image chain and concurrent searches");
    }
  CPP
  out,ok=Open3.capture2e('clang++','-std=c++11','-pthread','-fsanitize=address,undefined',"#{dir}/test.cpp",'-o',"#{dir}/test")
  abort out unless ok.success?
  out,ok=Open3.capture2e("#{dir}/test"); puts out
  abort 'lookup context regression failed' unless ok.success?
end
