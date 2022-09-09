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

struct opts {
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
static int parse_opts(int argc, char **argv, struct opts *opts) {
    int c;
    while ((c = getopt(argc, argv, "Ihr:u:d:n")) != -1) {
        switch (c) {
        case 'd':
            opts->directory = optarg;
            break;
        case 'r':
            opts->root = optarg;
            break;
        case 'u':
            opts->user = optarg;
            break;
        case 'h':
            cape_print_usage();
            exit(EXIT_SUCCESS);
        case 'I':
            opts->insecure_mode = true;
            break;
        case 'n':
            opts->disable_networking = true;
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
    char **envp = NULL;
    struct passwd *user_data = NULL;
    uid_t uid = getuid();
    int child_status = 0;

    struct opts opts = {
        .root = NULL,
        .user = NULL,
        .directory = "/",
        .insecure_mode = false,
        .disable_networking = false,
    };

    err = cape_logger_init(argv[0]);
    if (err) {
        fprintf(stderr, "failed to initialize logger\n");
        exit(EXIT_FAILURE);
    }

    index = parse_opts(argc, argv, &opts);
    if (index < 0) {
        cape_print_usage();
        err = -1;
        goto done;
    }

    if (opts.user) {
        user_data = getpwnam(opts.user);
        if (!user_data) {
            perror("getpwnam");
            cape_log_error("failed to lookup user: '%s'", opts.user);
            err = -1;
            goto done;
        }
        uid = user_data->pw_uid;
    }

    if (opts.root) {
        err = chroot(opts.root);
        if (err) {
            perror("chroot");
            cape_log_error(
                "could not chroot to: '%s' (are you root? does the directory "
                "exist?)",
                opts.root
            );
            goto done;
        }
    }

    if (opts.directory) {
        err = chdir(opts.directory);
        if (err) {
            perror("chdir");
            cape_log_error(
                "could not change directory to '%s'", opts.directory
            );
            goto done;
        }
    }

    err = cape_drop_privileges(uid, opts.disable_networking);
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

    if (!opts.insecure_mode) {
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
