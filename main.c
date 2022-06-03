#define _GNU_SOURCE
#include <ctype.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "enableseccomp.h"

static char *program_name = NULL;

static void print_usage(void) {
    fprintf(stderr,
            "%s: enable a secure compute environment in a jail that blocks "
            "certain syscalls\n"
            "usage:\n"
            "\t%s -u USER -r CHROOT [-d DIRECTORY] -- PROGRAM [ARGS]\n\n"
            "\t-d\tdirectory to start in within jail\n\n"
            "\t-r\tpath to chroot directory to use in jail\n\n"
            "\t-u\tuser to run as within the jail\n\n"
            "NOTE: should be run as root or with sudo to allow chroot\n\n",
            program_name, program_name);
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
static int parse_opts(int argc, char **argv, char **root, char **user,
                      const char **directory) {
    int c;
    if (!root || !user) {
        logerror("parse_opts got null pointer for root and/or user");
        return -1;
    }
    while ((c = getopt(argc, argv, "hr:u:d:")) != -1) {
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
        default:
            return -1;
        }
    }
    if (!*root || !*user) {
        logerror("-r and -u are required arguments");
        return -1;
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
    char **env = {NULL};
    uid_t uid;
    struct passwd *user_data = NULL;

    program_name = argv[0];

    index = parse_opts(argc, argv, &root, &user, &directory);
    if (index < 0) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    user_data = getpwnam(user);
    if (!user_data) {
        perror(user);
        logerror("failed to lookup user: '%s'", user);
        exit(EXIT_FAILURE);
    }

    uid = user_data->pw_uid;

    err = chroot(root);
    if (err) {
        perror(root);
        logerror("could not chroot to: '%s' (are you root?)", root);
        exit(EXIT_FAILURE);
    }

    err = chdir(directory);
    if (err) {
        perror(directory);
        logerror("could not change directory to '%s'", directory);
        exit(EXIT_FAILURE);
    }

    err = setuid(uid);
    if (err) {
        perror(user);
        logerror("could not setuid to: '%d'", uid);
        exit(EXIT_FAILURE);
    }

    err = enable_seccomp();
    if (err) {
        logerror("could not enable seccomp");
        exit(EXIT_FAILURE);
    }

    program_path = argv[index];
    program_args = argv + index;
    return execvpe(program_path, program_args, env);
}
