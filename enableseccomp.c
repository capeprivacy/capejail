#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>

#include "enableseccomp.h"

#define TRY_RULE(A) do { \
    if ((A)) { \
        fprintf(stderr, "failed to add seccomp rule"); \
        goto fail; \
    } \
} while (0)

int enable_seccomp() {
    scmp_filter_ctx ctx = NULL;

    ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize seccomp");
        goto fail;
    }

    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0));
    TRY_RULE(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0));

    return seccomp_load(ctx);

fail:
    /* TODO: cleanup ctx? */
    return -1;
}
