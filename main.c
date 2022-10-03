#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "banned.h"
#include "env.h"
#include "launch.h"
#include "logger.h"
#include "opts.h"
#include "privileges.h"
#include "seccomp.h"
#include "vec.h"

int main(int argc, char **argv) {
    int err = 0;
    int index;
    char *program_path = NULL;
    char **program_args = NULL;
    struct passwd *user_data = NULL;
    uid_t uid = getuid();
    int child_status = 0;

    struct cape_opts opts = {
        .root = NULL,
        .user = NULL,
        .directory = "/",
        .insecure_mode = false,
        .disable_networking = false,
    };

    struct cape_string_vec env = {
        .data = NULL,
        .len = 0,
        .cap = 0,
    };

    err = cape_logger_init(argv[0]);
    if (err) {
        fprintf(stderr, "failed to initialize logger\n");
        exit(EXIT_FAILURE);
    }

    index = cape_parse_opts(argc, argv, &opts, &env);
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

    err = cape_envp_finalize(uid, &env);
    if (err) {
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

    err = cape_launch_jail(program_path, program_args, &env, &child_status);
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
    cape_string_vec_free(&env);
    return err;
}
