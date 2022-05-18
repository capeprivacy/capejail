#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>

#include "enableseccomp.h"

int enable_seccomp() {
    scmp_filter_ctx ctx = NULL;
    int err = 0;

    ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize seccomp");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    if (err) {
        fprintf(stderr, "failed to add seccomp rule");
        goto fail;
    }

    seccomp_load(ctx);

    return 0;

fail:

    /* TODO: cleanup ctx? */
    return -1;
}
