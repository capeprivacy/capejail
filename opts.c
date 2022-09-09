#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "logger.h"
#include "opts.h"

int cape_parse_opts(
    int argc, char *const *const argv, struct cape_opts *opts /* out */
) {
    int c;
    while ((c = getopt(argc, argv, "Ihr:u:d:n")) != -1) {
        switch (c) {
        case 'h':
            cape_print_usage();
            exit(EXIT_SUCCESS);
        case 'n':
            opts->disable_networking = true;
            break;
        case 'd':
            opts->directory = optarg;
            break;
        case 'r':
            opts->root = optarg;
            break;
        case 'u':
            opts->user = optarg;
            break;
        case 'I':
            opts->insecure_mode = true;
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
