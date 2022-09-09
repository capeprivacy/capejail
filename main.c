#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "banned.h"
#include "env.h"
#include "launch.h"
#include "logger.h"
#include "privileges.h"
#include "seccomp.h"

/*
 * On failure: returns a negative value
 * On success: returns the index in argv of the program and arguments to exec
 *             in the jail
 */
static int parse_opts(
    int argc,
    char **argv,
    char **root,
    char **user,
    const char **directory,
    bool *insecure_mode,
    bool *disable_networking
) {
    int c;
    if (!root || !user || !directory || !insecure_mode ||
        !disable_networking) {
        cape_log_error(
            "parse_opts got a null pointer for root and/or user and/or "
            "directory and/or insecure_mode and/or networking"
        );
        return -1;
    }
    while ((c = getopt(argc, argv, "Ihr:u:d:n")) != -1) {
        switch (c) {
        case 'd':
            *directory = optarg;
            break;
        case 'r':
            *root = optarg;
            break;
        case 'u':
            *user = optarg;
            break;
        case 'h':
            cape_print_usage();
            exit(EXIT_SUCCESS);
        case 'I':
            *insecure_mode = true;
            break;
        case 'n':
            *disable_networking = true;
            break;
        default:
            return -1;
        }
    }
    if (optind >= argc) {
        cape_log_error("no program specified");
        return -1;
    } else {
        return optind;
    }
}

int main(int argc, char **argv) {
    int err = 0;
    int index;
    char *program_path = NULL;
    char **program_args = NULL;
    char *root = NULL;
    char *user = NULL;
    const char *directory = "/";
    char **envp = NULL;
    struct passwd *user_data = NULL;
    bool insecure_mode = false;
    bool disable_networking = false;
    uid_t uid = getuid();
    int child_status = 0;

    err = cape_logger_init(argv[0]);
    if (err) {
        fprintf(stderr, "failed to initialize logger\n");
        exit(EXIT_FAILURE);
    }

    index = parse_opts(
        argc,
        argv,
        &root,
        &user,
        &directory,
        &insecure_mode,
        &disable_networking
    );
    if (index < 0) {
        cape_print_usage();
        err = -1;
        goto done;
    }

    if (user) {
        user_data = getpwnam(user);
        if (!user_data) {
            perror("getpwnam");
            cape_log_error("failed to lookup user: '%s'", user);
            err = -1;
            goto done;
        }
        uid = user_data->pw_uid;
    }

    if (root) {
        err = chroot(root);
        if (err) {
            perror("chroot");
            cape_log_error(
                "could not chroot to: '%s' (are you root? does the directory "
                "exist?)",
                root
            );
            goto done;
        }
    }

    if (directory) {
        err = chdir(directory);
        if (err) {
            perror("chdir");
            cape_log_error("could not change directory to '%s'", directory);
            goto done;
        }
    }

    err = cape_drop_privileges(uid, disable_networking);
    if (err) {
        cape_log_error("could not drop privileges");
        goto done;
    }

    envp = cape_envp_new(uid);
    if (!envp) {
        cape_log_error(
            "failed to setup environment variables for child process"
        );
        goto done;
    }

    if (!insecure_mode) {
        err = cape_enable_seccomp();
        if (err) {
            cape_log_error("could not enable seccomp");
            goto done;
        }
    }

    program_path = argv[index];
    program_args = argv + index;

    err = cape_launch_jail(program_path, program_args, envp, &child_status);
    if (err) {
        cape_log_error("error encountered while launching jail: %d", err);
        goto done;
    }

    if (child_status) {
        err = child_status;
        cape_log_error(
            "NOTICE: the child process exited with a non-zero exit code.\n"
            "* This is NOT an error with capejail, but an error from the "
            "child process."
        );
    }

done:
    cape_log_error("shutting down");
    cape_logger_shutdown();
    cape_envp_destroy(envp);
    return err;
}
