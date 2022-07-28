#define _GNU_SOURCE
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "banned.h"
#include "enableseccomp.h"

static char *program_name = NULL;

static void print_usage(void) {
    fprintf(
        stderr,
        "%s: enable a secure compute environment in a jail that blocks "
        "certain syscalls\n"
        "usage:\n"
        "\t%s [OPTION] -- PROGRAM [ARGS]\n\n"
        "\t-d\tdirectory to start in within jail\n\n"
        "\t-r\tpath to chroot directory to use in jail\n\n"
        "\t-u\tuser to run as within the jail\n\n"
        "\t-I\tinsecure mode, launch with seccomp disabled\n\n"
        "NOTE: should be run as root or with sudo to allow chroot\n\n",
        program_name,
        program_name
    );
}

static void logerror(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s: ", program_name);

    /*
     * clang-tidy has a bug where a false positive warning is thrown for this
     * exact situation. We will suppress this for now by using "NOLINT" since
     * this is currently an open bug and not an actual problem with this source
     * code.
     *
     * bug report:
     * https://bugs.llvm.org/show_bug.cgi?id=41311
     */
    vfprintf(stderr, fmt, args); /* NOLINT */

    fprintf(stderr, "\n");
    va_end(args);
}

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
        logerror("parse_opts got null pointer for root and/or user and/or "
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
            print_usage();
            exit(EXIT_SUCCESS);
        case 'I':
            *insecure_mode = true;
            break;
        default:
            return -1;
        }
    }
    if (optind >= argc) {
        logerror("no program specified");
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

    program_name = argv[0];

    index = parse_opts(argc, argv, &root, &user, &directory, &insecure_mode);
    if (index < 0) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    if (user) {
        user_data = getpwnam(user);
        if (!user_data) {
            perror("getpwnam");
            logerror("failed to lookup user: '%s'", user);
            exit(EXIT_FAILURE);
        }
        uid = user_data->pw_uid;
    }

    if (root) {
        err = chroot(root);
        if (err) {
            perror("chroot");
            logerror(
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
            logerror("could not change directory to '%s'", directory);
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
            logerror("could not setgroups to: '%d'", uid);
            exit(EXIT_FAILURE);
        }

        err = setgid(uid);
        if (err) {
            perror("setgid");
            logerror("could not setgid to: '%d'", uid);
            exit(EXIT_FAILURE);
        }

        err = setuid(uid);
        if (err) {
            perror("setuid");
            logerror("could not setuid to: '%d'", uid);
            exit(EXIT_FAILURE);
        }
    }

    ps1 = strdup((uid == 0) ? "PS1=[jail]# " : "PS1=[jail]$ ");
    if (!ps1) {
        perror("strdup");
        logerror("out of memory");
        exit(EXIT_FAILURE);
    }

    if (!insecure_mode) {
        err = enable_seccomp();
        if (err) {
            logerror("could not enable seccomp");
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
        logerror("could not exec: %s", program_path);
        exit(EXIT_FAILURE);
    }
    return err;
}
