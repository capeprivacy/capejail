#ifndef ENV_H
#define ENV_H

#include <unistd.h>

#include "vec.h"

/*
 * Create a new environment variable pointer to be used by the child process.
 * Returns NULL on failure.
 */
int cape_envp_finalize(uid_t uid, struct cape_string_vec *env /* out */);

#endif /* ENV_H */
