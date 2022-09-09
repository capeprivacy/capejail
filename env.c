#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "env.h"
#include "logger.h"

char **cape_envp_new(uid_t uid) {
    char **envp = calloc(2, sizeof(*envp));
    char *ps1 = NULL;

    if (!envp) {
        perror("calloc");
        cape_log_error("out of memory");
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
