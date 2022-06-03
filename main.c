#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>

#include "enableseccomp.h"

static char *program_name = NULL;

static void print_usage() {
    fprintf(
        stderr,
        "%s: enable a secure compute environment that blocks certain syscalls\n"
        "usage:\n"
        "\t%s -u USER -r CHROOT PROGRAM [ARGS]\n"
        "\tu:\tuser to run as in jail\n\n"
        "\tr:\tpath to chroot directory to use in jail\n",
        program_name,
        program_name
    );
}

static void logerror(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s: ", program_name);
    fprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/*
 * On failure: returns a negative value
 * On success: returns the index in argv of the program and arguments to exec
 *             in the jail
 */
static int parse_opts(int argc, char** argv, char **root, char **user) {
    int c;
    if (!root || !user) {
        logerror("parse_opts got null pointer for root and/or user");
    }
    while ((c = getopt (argc, argv, "r:u:")) != -1) {
        switch (c) {
            case 'r':
                *root = optarg;
                break;
            case 'u':
                *user = optarg;
                break;
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            case '?':
                puts("here");
                fflush(stdout);
                if ((optopt == 'r') || (optopt == 'u')) {
                    logerror("option -%c requires an argument", optopt);
                } else if (isprint(optopt)) {
                    logerror("unknown option `-%c'", optopt);
                } else {
                    logerror("unknown option character `\\x%x'", optopt);
                }
                return -1;
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

    program_name = argv[0];

    index = parse_opts(argc, argv, &root, &user);
    if (index < 0) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    /*
     * TODO:
     *     - chroot
     *     - setuid
     */

    err = enable_seccomp();
    if (err) {
        logerror("could not enable seccomp");
        exit(EXIT_FAILURE);
    }

    program_path = argv[index];
    program_args = argv + index;
    return execvp(program_path, program_args);
}
