/* Link against the candidate libdyld; run on Darling's dyld2 loader. */
#include <assert.h>
#include <stddef.h>

extern void _dyld_stack_range(const void**, const void**);

int main(void)
{
    int sentinel;
    const void *bottom = &sentinel, *top = &sentinel;
    _dyld_stack_range(&bottom, &top);
    assert(bottom == NULL && top == NULL);
    bottom = &sentinel;
    _dyld_stack_range(&bottom, NULL);
    assert(bottom == NULL);
    top = &sentinel;
    _dyld_stack_range(NULL, &top);
    assert(top == NULL);
    _dyld_stack_range(NULL, NULL);
    return 0;
}
