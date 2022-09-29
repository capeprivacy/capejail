#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "banned.h"
#include "env.h"
#include "logger.h"

char **cape_envp_new(uid_t uid) {
    char *ps1 = NULL;

    /*
     * NOTICE:
     * If adding additional environment variables to envp, be sure to increment
     * `num_environment_variables`
     */
    const size_t num_environment_variables = 1;

    char **envp = calloc(
        num_environment_variables + 1 /* +1 for NULL terminated envp */,
        sizeof(*envp)
    );
    if (!envp) {
        perror("calloc");
        cape_log_error("out of memory");
        goto fail;
    }

    /*
     * It is possible on some platforms that NULL != 0, so make sure to NULL
     * the entire array. Because of this, memset will also not work here, and
     * to be completely standards compliant, we must NULL out this array in a
     * for loop.
     *
     * See: https://c-faq.com/null/runtime0.html
     */
    for (size_t i = 0; i < num_environment_variables + 1; i++) {
        envp[i] = NULL;
    }

    ps1 = strdup((uid == 0) ? "PS1=[jail]# " : "PS1=[jail]$ ");
    if (!ps1) {
        perror("strdup");
        cape_log_error("out of memory");
        goto fail;
    }

    envp[0] = ps1;

    /* recall, just like argv, envp must also be NULL terminated */
    envp[1] = NULL;
    return envp;

fail:
    cape_envp_destroy(envp);
    return NULL;
}

void cape_envp_destroy(char **envp) {
    if (envp) {
        for (size_t i = 0; envp[i] != NULL; i++) {
            free(envp[i]);
        }
        free(envp);
    }
}
