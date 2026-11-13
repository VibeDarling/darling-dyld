/* The cache's libobjc imports these two from /usr/lib/libRosetta.dylib and only calls them when the
 * process is translated, which a native Darling guest never is. Answering "not translated" keeps the
 * cache's libRosetta, whose text holds 4 raw svc sites, out of every process. Rosetta/Rosetta.h is
 * not in any open-source drop, so the prototypes follow objc-cache.mm:1189-1193: the first is used in
 * a boolean test (weakly addressed), the second's result is compared to KERN_SUCCESS. */

#include <stdbool.h>
#include <stdint.h>

enum { KERN_FAILURE = 5 };

__attribute__ ((visibility ("default")))
bool
rosetta_is_current_process_translated(void)
{
	return false;
}

__attribute__ ((visibility ("default")))
int
objc_thread_get_rip(uint32_t thread, uint64_t *pc)
{
	(void)thread;
	(void)pc;
	return KERN_FAILURE;
}
