#ifndef ENV_H
#define ENV_H

#include <unistd.h>

/*
 * Create a new environment variable pointer to be used by the child process.
 * Returns NULL on failure.
 */
char **cape_envp_new(uid_t uid);

/*
 * Cleanup the environment variable pointer and all of its allocated memory.
 */
void cape_envp_destroy(char **envp);

#endif /* ENV_H */
