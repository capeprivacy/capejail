#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "banned.h"
#include "logger.h"

static char *PROGRAM_NAME = NULL;

void cape_print_usage(void) {
    fprintf(
        stderr,
        "%s: enable a secure compute environment in a jail that blocks "
        "certain syscalls\n\n"
        "usage:\n"
        "\t%s [OPTION] -- PROGRAM [ARGS]\n\n"
        "\t-e\tadd an environment variable in the form of KEY=VALUE\n"
        "\t\texample: capejail -e HOME=/home/jailuser -e FOO=bar -- ...\n\n"
        "\t-h\tdisplay this help message\n\n"
        "\t-n\tdisable networking for the jailed process\n\n"
        "\t-d\tdirectory to start in within jail\n\n"
        "\t-r\tpath to chroot directory to use in jail\n\n"
        "\t-u\tuser to run as within the jail\n\n"
        "\t-I\tinsecure mode, launch with seccomp disabled\n\n"
        "NOTE: should be run as root or with sudo to allow chroot\n\n",
        PROGRAM_NAME,
        PROGRAM_NAME
    );
}

void cape_log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s: ", PROGRAM_NAME);

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

int cape_logger_init(const char *program_name) {
    int err = 0;

    PROGRAM_NAME = strdup(program_name);
    if (!PROGRAM_NAME) {
        perror("strdup");
        fprintf(stderr, "failed to allocate memory in logger\n");
        err = -1;
        goto fail;
    }

    return 0;

fail:
    free(PROGRAM_NAME);
    return err;
}

void cape_logger_shutdown(void) {
    free(PROGRAM_NAME);
}
