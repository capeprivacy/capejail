#include <seccomp.h>
#include <stdio.h>

#include "banned.h"
#include "enableseccomp.h"
#include "logger.h"

static const int ALLOWED_SYSCALLS[] = {
    SCMP_SYS(access),
    SCMP_SYS(alarm),
    SCMP_SYS(arch_prctl),
    SCMP_SYS(bind),
    SCMP_SYS(brk),
    SCMP_SYS(chdir),
    SCMP_SYS(clock_getres),
    SCMP_SYS(clock_gettime),
    SCMP_SYS(clock_nanosleep),
    SCMP_SYS(clone),
    SCMP_SYS(clone3),
    SCMP_SYS(close),
    SCMP_SYS(close_range),
    SCMP_SYS(connect),
    SCMP_SYS(copy_file_range),
    SCMP_SYS(creat),
    SCMP_SYS(dup),
    SCMP_SYS(dup2),
    SCMP_SYS(dup3),
    SCMP_SYS(epoll_create),
    SCMP_SYS(epoll_create1),
    SCMP_SYS(epoll_ctl),
    SCMP_SYS(epoll_ctl_old),
    SCMP_SYS(epoll_pwait),
    SCMP_SYS(epoll_wait),
    SCMP_SYS(epoll_wait_old),
    SCMP_SYS(eventfd),
    SCMP_SYS(eventfd2),
    SCMP_SYS(execve),
    SCMP_SYS(execveat),
    SCMP_SYS(exit),
    SCMP_SYS(exit_group),
    SCMP_SYS(faccessat),
    SCMP_SYS(faccessat2),
    SCMP_SYS(fadvise64),
    SCMP_SYS(fallocate),
    SCMP_SYS(fanotify_init),
    SCMP_SYS(fanotify_mark),
    SCMP_SYS(fchdir),
    SCMP_SYS(fcntl),
    SCMP_SYS(fdatasync),
    SCMP_SYS(fgetxattr),
    SCMP_SYS(flistxattr),
    SCMP_SYS(flock),
    SCMP_SYS(fork),
    SCMP_SYS(fremovexattr),
    SCMP_SYS(fsetxattr),
    SCMP_SYS(fstat),
    SCMP_SYS(fsync),
    SCMP_SYS(ftruncate),
    SCMP_SYS(futex),
    SCMP_SYS(getcpu),
    SCMP_SYS(getcwd),
    SCMP_SYS(getdents64),
    SCMP_SYS(getegid),
    SCMP_SYS(geteuid),
    SCMP_SYS(getgid),
    SCMP_SYS(getgroups),
    SCMP_SYS(getitimer),
    SCMP_SYS(get_mempolicy),
    SCMP_SYS(getpeername),
    SCMP_SYS(getpgid),
    SCMP_SYS(getpgrp),
    SCMP_SYS(getpid),
    SCMP_SYS(getppid),
    SCMP_SYS(getpriority),
    SCMP_SYS(getrandom),
    SCMP_SYS(getresuid),
    SCMP_SYS(getrlimit),
    SCMP_SYS(getrusage),
    SCMP_SYS(getsid),
    SCMP_SYS(getsockname),
    SCMP_SYS(getsockopt),
    SCMP_SYS(get_thread_area),
    SCMP_SYS(gettid),
    SCMP_SYS(gettimeofday),
    SCMP_SYS(getuid),
    SCMP_SYS(getxattr),
    SCMP_SYS(inotify_add_watch),
    SCMP_SYS(inotify_init),
    SCMP_SYS(inotify_init1),
    SCMP_SYS(inotify_rm_watch),
    SCMP_SYS(io_cancel),
    SCMP_SYS(ioctl),
    SCMP_SYS(io_destroy),
    SCMP_SYS(io_getevents),
    SCMP_SYS(ioprio_get),
    SCMP_SYS(ioprio_set),
    SCMP_SYS(io_setup),
    SCMP_SYS(io_submit),
    SCMP_SYS(io_uring_enter),
    SCMP_SYS(io_uring_register),
    SCMP_SYS(io_uring_setup),
    SCMP_SYS(kill),
    SCMP_SYS(lgetxattr),
    SCMP_SYS(listxattr),
    SCMP_SYS(lookup_dcookie),
    SCMP_SYS(lremovexattr),
    SCMP_SYS(lseek),
    SCMP_SYS(lsetxattr),
    SCMP_SYS(lstat),
    SCMP_SYS(madvise),
    SCMP_SYS(mkdir),
    SCMP_SYS(mmap),
    SCMP_SYS(mprotect),
    SCMP_SYS(mremap),
    SCMP_SYS(munmap),
    SCMP_SYS(newfstatat),
    SCMP_SYS(openat),
    SCMP_SYS(pipe),
    SCMP_SYS(pipe2),
    SCMP_SYS(prctl),
    SCMP_SYS(pread64),
    SCMP_SYS(prlimit64),
    SCMP_SYS(pselect6),
    SCMP_SYS(read),
    SCMP_SYS(readahead),
    SCMP_SYS(readlink),
    SCMP_SYS(rename),
    SCMP_SYS(rt_sigaction),
    SCMP_SYS(rt_sigprocmask),
    SCMP_SYS(rt_sigreturn),
    SCMP_SYS(sched_getaffinity),
    SCMP_SYS(select),
    SCMP_SYS(setpgid),
    SCMP_SYS(set_robust_list),
    SCMP_SYS(set_tid_address),
    SCMP_SYS(sigaltstack),
    SCMP_SYS(signal),
    SCMP_SYS(socket),
    SCMP_SYS(stat),
    SCMP_SYS(statfs),
    SCMP_SYS(statx),
    SCMP_SYS(sysinfo),
    SCMP_SYS(umask),
    SCMP_SYS(uname),
    SCMP_SYS(unlink),
    SCMP_SYS(vfork),
    SCMP_SYS(wait4),
    SCMP_SYS(write),
    SCMP_SYS(writev),
};

enum {
    NUM_SYSCALLS = sizeof(ALLOWED_SYSCALLS) / sizeof(*ALLOWED_SYSCALLS)
};

int cape_enable_seccomp(void) {
    scmp_filter_ctx ctx = NULL;
    int err = 0;

    ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */
    if (ctx == NULL) {
        err = -1;
        cape_log_error("failed to initialize seccomp");
        goto cleanup;
    }

    for (size_t i = 0; i < NUM_SYSCALLS; i++) {
        const int the_syscall = ALLOWED_SYSCALLS[i];
        err = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, the_syscall, 0);
        if (err) {
            cape_log_error(
                "failed to add seccomp rule for syscall number: %d",
                the_syscall
            );
            goto cleanup;
        }
    }

    err = seccomp_load(ctx);
    if (err) {
        cape_log_error("failed to load seccomp");
        goto cleanup;
    }

cleanup:
    if (ctx) {
        seccomp_release(ctx);
    }
    return err;
}
