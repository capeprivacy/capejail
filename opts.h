#ifndef OPTS_H
#define OPTS_H

#include <stdbool.h>

#include "vec.h"

struct cape_opts {
    const char *root;
    const char *user;
    const char *directory;
    bool insecure_mode;
    bool disable_networking;
};

/*
 * On failure: returns a negative value
 * On success: returns the index in argv of the program and arguments to exec
 *             in the jail
 */
int cape_parse_opts(
    int argc,
    char *const *const argv,
    struct cape_opts *opts,     /* out */
    struct cape_string_vec *env /* out */
);

#endif /* OPTS_H */
