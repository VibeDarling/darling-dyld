#undef NDEBUG
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    alarm(10);
    void *library=dlopen("/probe-libraries/A.dylib",RTLD_LAZY|RTLD_LOCAL|RTLD_FIRST);
    if (!library) fprintf(stderr,"dlopen: %s\n",dlerror());
    assert(library);
    int (*leaf)(void)=dlsym(library,"reexport_leaf");
    assert(leaf && leaf()==71);
    assert(dlsym(library,"reexport_missing")==NULL);
    assert(dlerror());
    assert(dlclose(library)==0);
    alarm(0);
    puts("PASS real Mach-O reexport cycle terminates and alternate export resolves");
    return 0;
}
