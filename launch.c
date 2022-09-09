#define _GNU_SOURCE
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "banned.h"
#include "launch.h"
#include "logger.h"

static int wait_for_child(
    pid_t child_pid, const char *program_path, int *child_status
) {
    pid_t wait_id;
    int wait_status;
    int err = 0;

    do {
        wait_id = waitpid(child_pid, &wait_status, WUNTRACED | WCONTINUED);
        if (wait_id == -1) {
            perror("waitpid");
            cape_log_error("failed to wait for child process");
            err = -1;
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
                "'%s' killed by signal %d", program_path, WTERMSIG(wait_status)
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

done:
    return err;
}

int cape_launch_jail(
    const char *program_path,
    char *const *program_args,
    char *const *envp,
    int *child_status
) {
    pid_t child_pid;
    int err = 0;

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
        err = wait_for_child(child_pid, program_path, child_status);
        if (err) {
            goto done;
        }

    } else {
        /* failure */
        cape_log_error("failed to fork, shutting down jail");
        err = child_pid;
        goto done;
    }

done:
    return err;
}
