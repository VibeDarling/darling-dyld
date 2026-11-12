// Local declarations of the libSystem interface the ABI probe uses (Darwin arm64 LP64).
// No SDK headers: the Darling SDK's header symlinks do not resolve outside its build tree, and
// h0/ declares zlib locally for the same reason. Layouts follow xnu bsd/sys/signal.h,
// bsd/sys/_types/_ucontext.h, bsd/arm/_mcontext.h and osfmk/mach/arm/_structs.h.
#ifndef ABI_DECL_H
#define ABI_DECL_H

#ifdef ABI_NATIVE
// Native build (the host validating the checks of l4/, which cannot run Mach-O): the system's own
// declarations; abi_harness.c carries the few platform branches. The blocks, dispatch and unwinder
// declarations below are for abi_checks.c and are not part of it.
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
typedef siginfo_t siginfo_min;
extern char *getenv(const char *);
#else

typedef __SIZE_TYPE__ size_t;
typedef long ssize_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTPTR_TYPE__ intptr_t;
typedef __UINT32_TYPE__ uint32_t;
typedef int pid_t;

extern ssize_t write(int, const void *, size_t);
extern ssize_t read(int, void *, size_t);
extern char *getenv(const char *);
extern void exit(int) __attribute__((noreturn));
extern void _exit(int) __attribute__((noreturn));
extern int close(int);
extern int dup2(int, int);
extern int pipe(int[2]);
extern pid_t fork(void);
extern int execv(const char *, char *const[]);
extern pid_t waitpid(pid_t, int *, int);
extern int kill(pid_t, int);
extern pid_t getpid(void);

struct pollfd { int fd; short events; short revents; };
extern int poll(struct pollfd *, unsigned, int);

extern int atexit(void (*)(void));
extern int __cxa_atexit(void (*)(void *), void *, void *);
extern char __dso_handle;
extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));

typedef struct _opaque_pthread_t *pthread_t;
typedef unsigned long pthread_key_t;
typedef struct { long sig; char opaque[8]; } pthread_once_t;
#define PTHREAD_ONCE_INIT {0x30B1BCBA, {0}}
extern int pthread_create(pthread_t *, const void *, void *(*)(void *), void *);
extern int pthread_join(pthread_t, void **);
extern int pthread_key_create(pthread_key_t *, void (*)(void *));
extern int pthread_setspecific(pthread_key_t, const void *);
extern int pthread_once(pthread_once_t *, void (*)(void));

typedef void *dispatch_queue_t;
typedef void *dispatch_semaphore_t;
typedef void (^dispatch_block_t)(void);
typedef long dispatch_once_t;
typedef unsigned long long dispatch_time_t;
extern dispatch_queue_t dispatch_get_global_queue(long, unsigned long);
extern void dispatch_async(dispatch_queue_t, dispatch_block_t);
extern void dispatch_once(dispatch_once_t *, dispatch_block_t);
extern dispatch_semaphore_t dispatch_semaphore_create(long);
extern long dispatch_semaphore_wait(dispatch_semaphore_t, dispatch_time_t);
extern long dispatch_semaphore_signal(dispatch_semaphore_t);
extern dispatch_time_t dispatch_time(dispatch_time_t, long long);

extern void _dyld_register_func_for_add_image(void (*)(const void *, intptr_t));
extern void *dlsym(void *, const char *);
extern void *_Block_copy(const void *);
typedef void (*sig_t)(int);
extern sig_t signal(int, sig_t);
#define SIGUSR1 30
#define RTLD_DEFAULT ((void *)-2)
extern int unw_getcontext(void *);
extern int unw_init_local(void *, void *);
extern int unw_step(void *);
extern int unw_get_reg(void *, int, uintptr_t *);
extern int unw_get_proc_info(void *, void *);
#define UNW_REG_IP (-1)
extern uint32_t _dyld_image_count(void);
extern const void *_dyld_get_image_header(uint32_t);
extern const char *_dyld_get_image_name(uint32_t);

// struct sigaction as the libc entry point takes it (the handler member is a raw pointer
// on purpose: the harness must store it unsigned, see harness_install_handler)
struct sigaction { void *handler; uint32_t mask; int flags; };
extern int sigaction(int, const struct sigaction *, struct sigaction *);
#define SA_SIGINFO 0x40
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 10
#define SIGSEGV 11
#define SIGKILL 9

typedef struct { int si_signo, si_errno, si_code; pid_t si_pid; unsigned si_uid; int si_status; void *si_addr; } siginfo_min;
#define SI_ADDR_OFFSET 24
// ucontext: uc_mcontext at 48; mcontext64 = exception state (far, esr, exception) then thread
// state (x0-x28, fp, lr, sp, pc, cpsr)
#define UC_MCONTEXT_OFFSET 48
#define MC_FAR_OFFSET 0
#define MC_ESR_OFFSET 8
#define MC_LR_OFFSET (16 + 29 * 8 + 8)
#define MC_PC_OFFSET (16 + 29 * 8 + 24)

#endif   // ABI_NATIVE

#endif
