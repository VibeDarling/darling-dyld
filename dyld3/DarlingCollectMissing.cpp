#include "DarlingCollectMissing.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

namespace dyld {
	extern void halt(const char* message) __attribute__((noreturn));
}

// Design (DARLING_DYLD_COLLECT_MISSING):
//  - One line per (referring image, symbol), TAB separated, appended to the file as it is found, so an abort or a crash
//    leaves a complete file: referrer, symbol, expected library, ordinal, strong|weak, lazy|nonlazy|chained, zero|trap|guard, slot, pid.
//    The pid attributes lines when children inherit the variable; a relative path resolves against the cwd at each write.
//    Ordinals are signed as in the bind opcodes: 0 self, -1 main executable, -2 flat lookup, -3 weak lookup. The expected-library
//    column is the install name as the image records it (so it may start with @), the referrer falls back to the path.
//    A symbol shared by several referrers has one thunk or guard slot; the trap names the first referrer that met it.
//    Names only. Lines starting with '#' give the pid and the bases of our own two regions, so a fault in a guard maps to its slot.
//  - Functions bind to a 16-byte thunk of ours (movz x0,#slot; ldr x16,<trap>; br x16). The region is read-write while an entry
//    is written and read-execute while it runs, never both. dyld signs the address like any resolved one, so an arm64e
//    importer's authenticated call works and reaches the trap. The trap halts with the symbol's name.
//  - Data binds to a slot in a PROT_NONE region: a read faults at that slot. A bind records no type, so "data" is a name
//    test (GUESS, see collectMissingNameLooksLikeData). A data symbol it misses gets a thunk: a read returns instruction
//    bytes and the app fails soon after, not at the read.
//  - No printf family: dyld's _main runs before libc's locale state is usable (it crashed in localeconv_l).
namespace dyld3 {
namespace darling {

static const size_t kStride = 16;
static const size_t kSlotsPerKind = 8192;
static const size_t kThunkRegionBytes = 0x30000;	// the trap address, then kSlotsPerKind entries, rounded to 64 KiB
static const size_t kGuardRegionBytes = 0x20000;

static const char* sOutputPath = nullptr;
static uint8_t* sThunks = nullptr;
static uint8_t* sGuards = nullptr;

struct SymbolInfo { const char* symbol; const char* referrer; const char* expectedIn; };
// Mapped by makeRegions, so a process that never turns the mode on carries no static storage for them.
static SymbolInfo* sThunkSlots = nullptr;
static SymbolInfo* sGuardSlots = nullptr;
static size_t sThunkCount = 0;
static size_t sGuardCount = 0;

// Open addressing maps of strdup'ed keys: lines already written, and the slot already handed out for a symbol.
struct KeyMap {
	const char** keys = nullptr;
	uint32_t*	 values = nullptr;
	size_t		 capacity = 0;
	size_t		 used = 0;
};

static uint64_t hashKey(const char* key)
{
	uint64_t h = 1469598103934665603ULL;
	for (; *key != '\0'; ++key)
		h = (h ^ (uint8_t)*key) * 1099511628211ULL;
	return h;
}

static void growMap(KeyMap& map)
{
	const size_t newCapacity = map.capacity ? map.capacity * 2 : 1024;
	const char** keys = (const char**)calloc(newCapacity, sizeof(const char*));
	uint32_t* values = (uint32_t*)calloc(newCapacity, sizeof(uint32_t));
	if ( (keys == nullptr) || (values == nullptr) )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: out of memory");
	for (size_t i = 0; i != map.capacity; ++i) {
		if ( map.keys[i] == nullptr )
			continue;
		size_t j = hashKey(map.keys[i]) & (newCapacity - 1);
		while ( keys[j] != nullptr )
			j = (j + 1) & (newCapacity - 1);
		keys[j] = map.keys[i];
		values[j] = map.values[i];
	}
	free(map.keys);
	free(map.values);
	map.keys = keys;
	map.values = values;
	map.capacity = newCapacity;
}

// Returns the slot where `key` is (found=true) or was just inserted with `value` (found=false).
static uint32_t mapInsert(KeyMap& map, const char* key, uint32_t value, bool& found)
{
	if ( (map.used + 1) * 2 > map.capacity )
		growMap(map);
	size_t i = hashKey(key) & (map.capacity - 1);
	while ( map.keys[i] != nullptr ) {
		if ( strcmp(map.keys[i], key) == 0 ) {
			found = true;
			return map.values[i];
		}
		i = (i + 1) & (map.capacity - 1);
	}
	char* copy = strdup(key);
	if ( copy == nullptr )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: out of memory");
	map.keys[i] = copy;
	map.values[i] = value;
	++map.used;
	found = false;
	return value;
}

static KeyMap sLines;		// "referrer TAB symbol"
static KeyMap sThunkMap;	// symbol
static KeyMap sGuardMap;	// symbol

static size_t appendStr(char* out, size_t at, const char* s)
{
	const size_t n = strlen(s);
	memcpy(out + at, s, n);
	return at + n;
}

static size_t appendDec(char* out, size_t at, uint64_t v)
{
	char tmp[24];
	size_t n = 0;
	do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while ( v != 0 );
	while ( n != 0 )
		out[at++] = tmp[--n];
	return at;
}

static size_t appendHex(char* out, size_t at, uint64_t v)
{
	out[at++] = '0';
	out[at++] = 'x';
	bool started = false;
	for (int shift = 60; shift >= 0; shift -= 4) {
		const unsigned d = (unsigned)((v >> shift) & 0xF);
		if ( (d != 0) || started || (shift == 0) ) {
			out[at++] = "0123456789abcdef"[d];
			started = true;
		}
	}
	return at;
}

// One write(2) per line. The file is opened per line, so no descriptor stays open in the process for the app to see.
static void writeLine(const char* line, size_t length)
{
	const int fd = open(sOutputPath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0644);
	if ( fd < 0 )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: cannot open the output file");
	const ssize_t written = write(fd, line, length);
	close(fd);
	if ( (written < 0) || ((size_t)written != length) )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: cannot write the output file");
}

static void writeRegionHeader()
{
	char line[160];
	size_t n = appendStr(line, 0, "# process pid=");
	n = appendDec(line, n, (uint64_t)getpid());
	n = appendStr(line, n, " regions thunk=");
	n = appendHex(line, n, (uint64_t)(uintptr_t)sThunks);
	n = appendStr(line, n, " guard=");
	n = appendHex(line, n, (uint64_t)(uintptr_t)sGuards);
	n = appendStr(line, n, " stride=16\n");
	writeLine(line, n);
}

// What the thunks branch to. x0 is the slot; a thunk is entered in place of the missing function, so the caller's
// frame and link register are intact and the trap is the first thing that runs.
static void collectedMissingTrap(uint64_t slot) __attribute__((noreturn));
static void collectedMissingTrap(uint64_t slot)
{
	const SymbolInfo* info = (slot < sThunkCount) ? &sThunkSlots[slot] : nullptr;
	const char* symbol = info ? info->symbol : "?";
	const char* referrer = info ? info->referrer : "?";
	const char* expectedIn = info ? info->expectedIn : "?";
	const size_t need = strlen(symbol) + strlen(referrer) + strlen(expectedIn) + 128;
	char* msg = (char*)malloc(need);
	if ( msg == nullptr )
		dyld::halt("a collected missing symbol was called");
	size_t n = appendStr(msg, 0, "a collected missing symbol was called: ");
	n = appendStr(msg, n, symbol);
	n = appendStr(msg, n, " (referenced from ");
	n = appendStr(msg, n, referrer);
	n = appendStr(msg, n, ", expected in ");
	n = appendStr(msg, n, expectedIn);
	n = appendStr(msg, n, ")");
	msg[n] = '\0';
	dyld::halt(msg);
}

static void makeRegions()
{
	if ( sThunks != nullptr )
		return;
	void* thunks = mmap(nullptr, kThunkRegionBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	void* guards = mmap(nullptr, kGuardRegionBytes, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	void* slots = mmap(nullptr, 2 * kSlotsPerKind * sizeof(SymbolInfo), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if ( (thunks == MAP_FAILED) || (guards == MAP_FAILED) || (slots == MAP_FAILED) )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: cannot map its regions");
	sThunkSlots = (SymbolInfo*)slots;
	sGuardSlots = sThunkSlots + kSlotsPerKind;
	sThunks = (uint8_t*)thunks;
	sGuards = (uint8_t*)guards;
	const uint64_t trap = (uint64_t)(uintptr_t)&collectedMissingTrap;
	memcpy(sThunks, &trap, sizeof(trap));	// the literal the thunks load; the first entry follows it at kStride
	if ( mprotect(sThunks, kThunkRegionBytes, PROT_READ | PROT_EXEC) != 0 )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: cannot protect its thunk region");
	writeRegionHeader();
}

static uintptr_t newThunk(const MissingImport& import)
{
	bool found;
	const uint32_t slot = mapInsert(sThunkMap, import.symbol, (uint32_t)sThunkCount, found);
	if ( !found ) {
		if ( sThunkCount == kSlotsPerKind )
			dyld::halt("DARLING_DYLD_COLLECT_MISSING: more than 8192 missing functions");
		sThunkSlots[sThunkCount] = { strdup(import.symbol), strdup(import.referrer), strdup(import.expectedIn) };
		uint32_t* entry = (uint32_t*)(sThunks + kStride + kStride * slot);
		const int64_t literalOffset = -(int64_t)(kStride + kStride * slot + 4);	// from the ldr to the literal at the region start
		if ( mprotect(sThunks, kThunkRegionBytes, PROT_READ | PROT_WRITE) != 0 )
			dyld::halt("DARLING_DYLD_COLLECT_MISSING: cannot write its thunk region");
		entry[0] = 0xD2800000u | (slot << 5);							// movz x0, #slot
		entry[1] = 0x58000010u | ((uint32_t)((literalOffset / 4) & 0x7FFFF) << 5);	// ldr x16, <literal>
		entry[2] = 0xD61F0200u;											// br x16
		entry[3] = 0xD503201Fu;											// nop
		// Linux arm64 syncs the instruction cache for a page when it first becomes executable, not for later rewrites of it
		__builtin___clear_cache((char*)entry, (char*)(entry + 4));
		if ( mprotect(sThunks, kThunkRegionBytes, PROT_READ | PROT_EXEC) != 0 )
			dyld::halt("DARLING_DYLD_COLLECT_MISSING: cannot protect its thunk region");
		++sThunkCount;
	}
	return (uintptr_t)(sThunks + kStride + kStride * slot);
}

static uintptr_t newGuard(const MissingImport& import)
{
	bool found;
	const uint32_t slot = mapInsert(sGuardMap, import.symbol, (uint32_t)sGuardCount, found);
	if ( !found ) {
		if ( sGuardCount == kSlotsPerKind )
			dyld::halt("DARLING_DYLD_COLLECT_MISSING: more than 8192 missing data symbols");
		sGuardSlots[sGuardCount] = { strdup(import.symbol), strdup(import.referrer), strdup(import.expectedIn) };
		++sGuardCount;
	}
	return (uintptr_t)(sGuards + kStride * slot);
}

static bool startsWith(const char* s, const char* prefix)
{
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool endsWith(const char* s, const char* suffix)
{
	const size_t n = strlen(s), m = strlen(suffix);
	return (n >= m) && (strcmp(s + n - m, suffix) == 0);
}

// GUESS, no Apple fact behind it: Cocoa-style constants end in Key/Identifier/AttributeName/..., Objective-C class and
// exception-type symbols are data by construction, and `k` constants are a naming convention. A function that happens to end
// the same way (_NSAccessibilityPostNotification) is vetoed by a verb followed by a capital anywhere in the name.
bool collectMissingNameLooksLikeData(const char* symbol)
{
	if ( startsWith(symbol, "_OBJC_CLASS_$_") || startsWith(symbol, "_OBJC_METACLASS_$_") || startsWith(symbol, "_OBJC_EHTYPE_$_") )
		return true;
	if ( (symbol[0] == '_') && (symbol[1] == 'k') && (symbol[2] >= 'A') && (symbol[2] <= 'Z') )
		return true;
	static const char* const verbs[] = { "Copy", "Create", "Get", "Set", "Post", "Add", "Remove", "Register", "Release", "Retain" };
	for (const char* verb : verbs) {
		for (const char* at = strstr(symbol, verb); at != nullptr; at = strstr(at + 1, verb)) {
			const char next = at[strlen(verb)];
			if ( (next >= 'A') && (next <= 'Z') )
				return false;
		}
	}
	static const char* const suffixes[] = { "Key", "Keys", "Identifier", "Identifiers", "AttributeName", "Notification", "Domain", "Zero", "PboardType" };
	for (const char* suffix : suffixes) {
		if ( endsWith(symbol, suffix) )
			return true;
	}
	return false;
}

void collectMissingEnable(const char* outputPath)
{
	if ( (outputPath == nullptr) || (outputPath[0] == '\0') )
		return;
	sOutputPath = strdup(outputPath);
}

bool collectMissingEnabled()
{
	return sOutputPath != nullptr;
}

uintptr_t collectMissingBind(const MissingImport& import)
{
	if ( sOutputPath == nullptr )
		return 0;
	makeRegions();
	const char* binding = "zero";
	uintptr_t address = 0;
	size_t slot = 0;
	if ( !import.weak ) {
		const bool data = (import.kind != BindKind::Lazy) && collectMissingNameLooksLikeData(import.symbol);
		binding = data ? "guard" : "trap";
		address = data ? newGuard(import) : newThunk(import);
		slot = data ? (size_t)(address - (uintptr_t)sGuards) / kStride : (size_t)(address - (uintptr_t)sThunks) / kStride - 1;
	}
	// one line per referrer and symbol
	const size_t keyBytes = strlen(import.referrer) + strlen(import.symbol) + 2;
	char* key = (char*)malloc(keyBytes);
	if ( key == nullptr )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: out of memory");
	size_t k = appendStr(key, 0, import.referrer);
	key[k++] = '\t';
	k = appendStr(key, k, import.symbol);
	key[k] = '\0';
	bool found;
	mapInsert(sLines, key, 0, found);
	free(key);
	if ( found )
		return address;
	const size_t lineBytes = strlen(import.referrer) + strlen(import.symbol) + strlen(import.expectedIn) + 128;
	char* line = (char*)malloc(lineBytes);
	if ( line == nullptr )
		dyld::halt("DARLING_DYLD_COLLECT_MISSING: out of memory");
	size_t n = appendStr(line, 0, import.referrer);
	line[n++] = '\t';
	n = appendStr(line, n, import.symbol);
	line[n++] = '\t';
	n = appendStr(line, n, import.expectedIn);
	line[n++] = '\t';
	if ( import.ordinal < 0 ) {
		line[n++] = '-';
		n = appendDec(line, n, (uint64_t)(-import.ordinal));
	}
	else {
		n = appendDec(line, n, (uint64_t)import.ordinal);
	}
	line[n++] = '\t';
	n = appendStr(line, n, import.weak ? "weak" : "strong");
	line[n++] = '\t';
	n = appendStr(line, n, (import.kind == BindKind::Lazy) ? "lazy" : (import.kind == BindKind::NonLazy) ? "nonlazy" : "chained");
	line[n++] = '\t';
	n = appendStr(line, n, binding);
	line[n++] = '\t';
	if ( import.weak ) {
		line[n++] = '-';
	}
	else {
		line[n++] = (strcmp(binding, "guard") == 0) ? 'G' : 'T';
		n = appendDec(line, n, slot);
	}
	line[n++] = '\t';
	n = appendDec(line, n, (uint64_t)getpid());
	line[n++] = '\n';
	writeLine(line, n);
	free(line);
	return address;
}

} // namespace darling
} // namespace dyld3
