#ifndef LAUNCH_H
#define LAUNCH_H

#include "vec.h"

int cape_launch_jail(
    const char *program_path,
    char *const *program_args,
    const struct cape_string_vec *env,
    int *child_status
);

#endif /* LAUNCH_H */
