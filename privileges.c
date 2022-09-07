#define _GNU_SOURCE
#include <grp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "logger.h"
#include "privileges.h"

static int do_unshare(bool disable_networking) {
    int err = 0;
    int unshare_flags = CLONE_NEWPID;

    if (disable_networking) {
        /* disable networking for the jailed process */
        unshare_flags |= CLONE_NEWNET;
    }

    err = unshare(unshare_flags);
    if (err) {
        perror("unshare");
        goto done;
    }

done:
    return err;
}

/*
 * Set the UID of the current process to `uid`.
 * Drop group memberships to only the current user group.
 * Create a new process namespace for child processes.
 * Optionally unshare the networking namespace.
 */
int cape_drop_privileges(uid_t uid, bool disable_networking) {
    /*
     * Drop root privileges:
     * https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges
     */
    int err = 0;
    const gid_t list[] = {uid};
    const size_t len = sizeof(list) / sizeof(*list);

    err = do_unshare(disable_networking);
    if (err) {
        cape_log_error("could not unshare");
        goto done;
    }

    err = setgroups(len, list);
    if (err) {
        perror("setgroups");
        cape_log_error("could not setgroups to: '%d'", uid);
        goto done;
    }

    err = setgid(uid);
    if (err) {
        perror("setgid");
        cape_log_error("could not setgid to: '%d'", uid);
        goto done;
    }

    err = setuid(uid);
    if (err) {
        perror("setuid");
        cape_log_error("could not setuid to: '%d'", uid);
        goto done;
    }

done:
    return err;
}
