#include <stdio.h>
#include <seccomp.h>

#include "enableseccomp.h"

#define TRY_RULE(A) do { \
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, (A), 0) != 0) { \
        fprintf( \
            stderr, \
            "failed to add seccomp rule for syscall number: %d\n", \
            (A) \
        ); \
        goto fail; \
    } \
} while (0)

int enable_seccomp() {
    scmp_filter_ctx ctx = NULL;
    int err = 0;

    ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize seccomp");
        goto fail;
    }

    TRY_RULE(SCMP_SYS(rt_sigreturn));
    TRY_RULE(SCMP_SYS(exit));
    TRY_RULE(SCMP_SYS(exit_group));
    TRY_RULE(SCMP_SYS(read));
    TRY_RULE(SCMP_SYS(write));
    TRY_RULE(SCMP_SYS(getrandom));
    TRY_RULE(SCMP_SYS(close));
    TRY_RULE(SCMP_SYS(rt_sigaction));
    TRY_RULE(SCMP_SYS(munmap));
    TRY_RULE(SCMP_SYS(mmap));
    TRY_RULE(SCMP_SYS(brk));

    err = seccomp_load(ctx);
    seccomp_release(ctx);
    return err;

fail:
    if (ctx) {
        seccomp_release(ctx);
    }
    return -1;
}
