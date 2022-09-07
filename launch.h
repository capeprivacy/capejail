#ifndef LAUNCH_H
#define LAUNCH_H

int cape_launch_jail(
    const char *program_path,
    char *const *program_args,
    char *const *envp,
    int *child_status
);

#endif /* LAUNCH_H */
