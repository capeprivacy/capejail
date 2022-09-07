#define _GNU_SOURCE
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "banned.h"
#include "enableseccomp.h"
#include "logger.h"

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
    bool *with_networking
) {
    int c;
    if (!root || !user || !directory || !insecure_mode || !with_networking) {
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
            *with_networking = false;
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

static int launch_jail(
    const char *program_path,
    char *const *program_args,
    char *const *envp,
    int *child_status
) {
    pid_t child_pid;
    int err = 0;
    int wait_status;

    child_pid = fork();
    if (child_pid == 0) {
        /* child */
        err = execvpe(program_path, program_args, envp);
        if (err) {
            perror(program_path);
            cape_log_error("could not exec: %s", program_path);
            goto done;
        }
    } else if (child_pid > 0) {
        /* parent */
        pid_t w;
        do {
            w = waitpid(child_pid, &wait_status, WUNTRACED | WCONTINUED);
            if (w == -1) {
                perror("waitpid");
                cape_log_error("failed to wait for child process");
                err = w;
                goto done;
            }

            if (WIFEXITED(wait_status)) {
                cape_log_error(
                    "'%s' exited with status %d",
                    program_path,
                    WEXITSTATUS(wait_status)
                );
                *child_status = WEXITSTATUS(wait_status);

            } else if (WIFSIGNALED(wait_status)) {
                cape_log_error(
                    "'%s' killed by signal %d",
                    program_path,
                    WTERMSIG(wait_status)
                );

            } else if (WIFSTOPPED(wait_status)) {
                cape_log_error(
                    "'%s' stopped by signal %d",
                    program_path,
                    WSTOPSIG(wait_status)
                );

            } else if (WIFCONTINUED(wait_status)) {
                cape_log_error("'%s' continued", program_path);
            }
        } while (!WIFEXITED(wait_status) && !WIFSIGNALED(wait_status));

    } else {
        /* failure */
        cape_log_error("failed to fork, shutting down jail");
        err = child_pid;
        goto done;
    }

done:
    return err;
}

int main(int argc, char **argv) {
    int err = 0;
    int index;
    char *program_path = NULL;
    char **program_args = NULL;
    char *root = NULL;
    char *user = NULL;
    const char *directory = "/";
    char *envp[2];
    struct passwd *user_data = NULL;
    bool insecure_mode = false;
    bool with_networking = true;
    uid_t uid = getuid();
    char *ps1 = NULL;
    int unshare_flags = CLONE_NEWPID;
    int child_status = 0;

    err = cape_logger_init(argv[0]);
    if (err) {
        fprintf(stderr, "failed to initialize logger\n");
        exit(EXIT_FAILURE);
    }

    index = parse_opts(
        argc, argv, &root, &user, &directory, &insecure_mode, &with_networking
    );
    if (index < 0) {
        cape_print_usage();
        exit(EXIT_FAILURE);
    }

    if (user) {
        user_data = getpwnam(user);
        if (!user_data) {
            perror("getpwnam");
            cape_log_error("failed to lookup user: '%s'", user);
            exit(EXIT_FAILURE);
        }
        uid = user_data->pw_uid;
    }

    if (!with_networking) {
        /* disable networking for the jailed process */
        unshare_flags |= CLONE_NEWNET;
    }

    if (unshare_flags) {
        err = unshare(unshare_flags);
        if (err) {
            perror("unshare");
            cape_log_error("could not unshare the flags: %d", unshare_flags);
            exit(EXIT_FAILURE);
        }
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
            exit(EXIT_FAILURE);
        }
    }

    if (directory) {
        err = chdir(directory);
        if (err) {
            perror("chdir");
            cape_log_error("could not change directory to '%s'", directory);
            exit(EXIT_FAILURE);
        }
    }

    if (user) {
        /*
         * Drop root privileges:
         * https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges
         */
        const gid_t list[] = {uid};
        const size_t len = sizeof(list) / sizeof(*list);

        err = setgroups(len, list);
        if (err) {
            perror("setgroups");
            cape_log_error("could not setgroups to: '%d'", uid);
            exit(EXIT_FAILURE);
        }

        err = setgid(uid);
        if (err) {
            perror("setgid");
            cape_log_error("could not setgid to: '%d'", uid);
            exit(EXIT_FAILURE);
        }

        err = setuid(uid);
        if (err) {
            perror("setuid");
            cape_log_error("could not setuid to: '%d'", uid);
            exit(EXIT_FAILURE);
        }
    }

    ps1 = strdup((uid == 0) ? "PS1=[jail]# " : "PS1=[jail]$ ");
    if (!ps1) {
        perror("strdup");
        cape_log_error("out of memory");
        exit(EXIT_FAILURE);
    }

    if (!insecure_mode) {
        err = cape_enable_seccomp();
        if (err) {
            cape_log_error("could not enable seccomp");
            exit(EXIT_FAILURE);
        }
    }

    envp[0] = ps1;
    envp[1] = NULL;
    program_path = argv[index];
    program_args = argv + index;

    err = launch_jail(program_path, program_args, envp, &child_status);
    if (err) {
        cape_log_error("capejail encountered an error: %d", err);
        goto done;
    }

    if (child_status) {
        err = child_status;
        cape_log_error(
            "NOTICE: the child process exited with a non-zero exit code.\n"
            "* This is NOT an error with capejail, but an error from the "
            "child "
            "process"
        );
    }

done:
    cape_logger_shutdown();
    return err;
}
