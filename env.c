#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "banned.h"
#include "env.h"
#include "logger.h"
#include "vec.h"

int cape_envp_finalize(uid_t uid, struct cape_string_vec *env) {
    int err = 0;
    const char *ps1 = (uid == 0) ? "PS1=[jail]# " : "PS1=[jail]$ ";

    err = cape_string_vec_push(env, ps1);
    if (err) {
        goto done;
    }

    err = cape_string_vec_push(env, NULL);
    if (err) {
        goto done;
    }

done:
    return err;
}
