#define _GNU_SOURCE
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    bool *insecure_mode
) {
    int c;
    if (!root || !user || !directory || !insecure_mode) {
        cape_log_error("parse_opts got null pointer for root and/or user and/or "
                 "directory and/or insecure_mode");
        return -1;
    }
    while ((c = getopt(argc, argv, "Ihr:u:d:")) != -1) {
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
    char *envp[2];
    struct passwd *user_data = NULL;
    bool insecure_mode = false;
    uid_t uid = getuid();
    char *ps1 = NULL;

    err = cape_logger_init(argv[0]);
    if (err) {
        fprintf(stderr, "failed to initialize logger\n");
        return err;
    }

    index = parse_opts(argc, argv, &root, &user, &directory, &insecure_mode);
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
         * Drop root privledges:
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
    err = execvpe(program_path, program_args, envp);
    if (err) {
        perror(program_path);
        cape_log_error("could not exec: %s", program_path);
        exit(EXIT_FAILURE);
    }
    return err;
}
