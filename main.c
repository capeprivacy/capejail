/*
 * This serves as a cannary test to ensure that seccomp is functioning as
 * expected. If seccomp is working as expected, then the last thing you should
 * see printed to stderr is "opening test.txt", which should be immediately
 * followed by the process getting killed for opening a file.
 *
 * If you see the message "done", then this means that seccomp is indeed NOT
 * FUNCTIONING and should not be trusted.
 */

#include <stdio.h>
#include <stdlib.h>

#include "enableseccomp.h"

int main(void) {
    FILE *fp = NULL;
    int err = 0;

    /*
     * stderr is not buffered, so if this process gets a sigkill, it will be
     * able to write a message to stderr before hand
     */
    fprintf(stderr, "hello world!\n");

    err = enable_seccomp();
    if (err != 0) {
        fprintf(stderr, "could not enable seccomp");
        exit(1);
    }
    fprintf(stderr, "seccomp enabled\n");

    fprintf(stderr, "opening test.txt\n");
    fp = fopen("test.txt", "w");
    if (fp == NULL) {
        perror("fopen test.txt");
        exit(2);
    }

    fprintf(stderr, "writing to test.txt\n");
    fprintf(fp, "some text\n");
    fclose(fp);

    fprintf(stderr, "done\n");
    return 0;
}
