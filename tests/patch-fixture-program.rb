# The C++ that the patch info tests share: it parses the manifest of tests/gen-split-cache-fixture.py --variant patch
# and maps the synthetic cache with the real mapSplitCachePrivate. Prepend SplitCacheHarness.prefix(root).
module PatchFixtureProgram
  PREFIX = <<~CPP
    #include <map>
    #include <sys/wait.h>
    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)
    #define CHECK_ERR(expr, text) do { const char *e_ = (expr); if (!e_ || !strstr(e_, text)) { printf("FAIL line %d: %s gave '%s', wanted '%s'\\n", __LINE__, #expr, e_ ? e_ : "(null)", text); ++failures; } } while (0)

    struct Got { uint64_t slot; unsigned exporter; std::string symbol; uint32_t flags; bool auth, addrDiv, keyData, bit8, explained; unsigned disc, addend, high7; };
    struct Plain { uint64_t slot; unsigned exporter; std::string symbol; unsigned client; uint32_t flags; };
    struct Export { unsigned image; std::string name; uint32_t impl, kind; };
    struct Fixture {
      std::map<std::string, std::pair<uint64_t, uint64_t>> arrays; uint64_t blobAddr = 0, blobSize = 0, gotMapAddr = 0, gotMapSize = 0;
      std::vector<std::pair<uint64_t, std::string>> images; std::vector<Export> exports; std::vector<Got> got; std::vector<Plain> plain;
      std::vector<uint64_t> control;
    };
    static unsigned long long hexv(const std::string &s) { return strtoull(s.c_str(), nullptr, 0); }
    static Fixture loadManifest(const std::string &dir) {
      Fixture f; FILE *m = fopen((dir + "/manifest.txt").c_str(), "r"); assert(m);
      char line[512];
      while (fgets(line, sizeof line, m)) {
        std::vector<std::string> w; char *save = nullptr;
        for (char *t = strtok_r(line, " \\n", &save); t; t = strtok_r(nullptr, " \\n", &save)) w.push_back(t);
        if (w.empty()) continue;
        if (w[0] == "patchinfo") { f.blobAddr = hexv(w[1]); f.blobSize = hexv(w[2]); }
        else if (w[0] == "parray") f.arrays[w[1]] = {hexv(w[2]), hexv(w[3])};
        else if (w[0] == "pgotmap") { f.gotMapAddr = hexv(w[1]); f.gotMapSize = hexv(w[2]); }
        else if (w[0] == "pimage") f.images.push_back({hexv(w[2]), w[3]});
        else if (w[0] == "pexport") f.exports.push_back({(unsigned)hexv(w[1]), w[2], (uint32_t)hexv(w[3]), (uint32_t)hexv(w[4])});
        else if (w[0] == "pgot") f.got.push_back({hexv(w[1]), (unsigned)hexv(w[2]), w[3], (uint32_t)hexv(w[4]), !!hexv(w[5]), !!hexv(w[6]), !!hexv(w[7]),
                                                  !!hexv(w[11]), !!hexv(w[12]), (unsigned)hexv(w[8]), (unsigned)hexv(w[9]), (unsigned)hexv(w[10])});
        else if (w[0] == "pplain") f.plain.push_back({hexv(w[1]), (unsigned)hexv(w[2]), w[3], (unsigned)hexv(w[4]), (uint32_t)hexv(w[5])});
        else if (w[0] == "pcontrol") f.control.push_back(hexv(w[1]));
      }
      fclose(m); return f;
    }
    static const Export *findExport(const Fixture &f, unsigned image, const std::string &name) {
      for (const Export &e : f.exports) if (e.image == image && e.name == name) return &e;
      return nullptr;
    }
    static const DyldSharedCache *mapFixture(const std::string &dir) {
      SharedCacheLoadInfo result = {}; SplitCacheMapStats stats = {};
      if (!mapSplitCachePrivate((dir + "/cache").c_str(), false, &result, &stats)) { printf("FAIL mapping: %s\\n", result.errorMessage ? result.errorMessage : "(none)"); exit(1); }
      return result.loadAddress;
    }
  CPP
end

