#include <seccomp.h>
#include <stdio.h>

#include "banned.h"
#include "logger.h"
#include "seccomp.h"

static const int ALLOWED_SYSCALLS[] = {
    /*
     * Check user's permissions for a file.
     */
    SCMP_SYS(access),

    /*
     * Sends a SIGALRM signal to the calling process after a number of seconds.
     * Sleep could possibly be implemented using alarm in some libraries.
     */
    SCMP_SYS(alarm),

    /*
     * Set architecture-specific thread state. Used by numpy.
     */
    SCMP_SYS(arch_prctl),

    /*
     * Bind an address to a socket.
     */
    SCMP_SYS(bind),

    /*
     * Used to adjust the heap. Mostly obsoleted by mmap, but could be used by
     * a malloc implementation.
     */
    SCMP_SYS(brk),

    /*
     * Get capabilities of calling thread. Unlikely to be useful
     */
    SCMP_SYS(capget),

    /*
     * Set permissions of file.
     */
    SCMP_SYS(chmod),

    /*
     * Change ownership of a file.
     */
    SCMP_SYS(chown),

    /*
     * Change directories. Pretty useful, and with the chroot jail along with
     * seccomp filtering, it should be unlikely to be exploitable.
     */
    SCMP_SYS(chdir),

    /*
     * Get the resolution (precision) of the system clock.
     */
    SCMP_SYS(clock_getres),

    /*
     * Get the current time.
     */
    SCMP_SYS(clock_gettime),

    /*
     * Put the thread to sleep with nanosecond precision.
     */
    SCMP_SYS(clock_nanosleep),

    /*
     * The Linux way of doing [fork](#fork), but with more options and better
     * performance.
     */
    SCMP_SYS(clone),

    /*
     * See [clone](#clone).
     */
    SCMP_SYS(clone3),

    /*
     * Close a file descriptor.
     */
    SCMP_SYS(close),

    /*
     * Close all file descriptors from first to last.
     */
    SCMP_SYS(close_range),

    /*
     * Initiate a socket connection. Used by a lot of programs, including `ls
     * -l`.
     */
    SCMP_SYS(connect),

    /*
     * Copy a range of data from one file to another
     */
    SCMP_SYS(copy_file_range),

    /*
     * Create a file with given permissions.
     */
    SCMP_SYS(creat),

    /*
     * Duplicate a file descriptor.
     */
    SCMP_SYS(dup),

    /*
     * See [dup](#dup).
     */
    SCMP_SYS(dup2),

    /*
     * See [dup](#dup).
     */
    SCMP_SYS(dup3),

    /*
     * Create an epoll instance, used for monitoring files for IO.
     */
    SCMP_SYS(epoll_create),

    /*
     * See [epoll_create](#epoll_create).
     */
    SCMP_SYS(epoll_create1),

    /*
     * See [epoll_create](#epoll_create).
     */
    SCMP_SYS(epoll_ctl),

    /*
     * See [epoll_create](#epoll_create).
     */
    SCMP_SYS(epoll_ctl_old),

    /*
     * See [epoll_create](#epoll_create).
     */
    SCMP_SYS(epoll_pwait),

    /*
     * See [epoll_create](#epoll_create).
     */
    SCMP_SYS(epoll_wait),

    /*
     * See [epoll_create](#epoll_create).
     */
    SCMP_SYS(epoll_wait_old),

    /*
     * Create a file descriptor for event notification.
     */
    SCMP_SYS(eventfd),

    /*
     * See [eventfd](#eventfd).
     */
    SCMP_SYS(eventfd2),

    /*
     * Execute a program.
     */
    SCMP_SYS(execve),

    /*
     * See [execve](#execve).
     */
    SCMP_SYS(execveat),

    /*
     * Terminate the calling process
     */
    SCMP_SYS(exit),

    /*
     * See [exit](#exit).
     */
    SCMP_SYS(exit_group),

    /*
     * Check the user's permissions for a file. See [access](#access).
     */
    SCMP_SYS(faccessat),

    /*
     * See [faccessat](#faccessat).
     */
    SCMP_SYS(faccessat2),

    /*
     * Declare an access pattern for data.
     */
    SCMP_SYS(fadvise64),

    /*
     * Allocate space for a file.
     */
    SCMP_SYS(fallocate),

    /*
     * Initialize an fanotify group.
     */
    SCMP_SYS(fanotify_init),

    /*
     * See [fanotify_init](#fanotify_init)
     */
    SCMP_SYS(fanotify_mark),

    /*
     * Change working directory. See [chdir](#chdir)
     */
    SCMP_SYS(fchdir),

    /*
     * Toolbox for manipulating a file descriptor.
     */
    SCMP_SYS(fcntl),

    /*
     * See [fsync](#fsync)
     */
    SCMP_SYS(fdatasync),

    /*
     * Get extended attributes for file descriptor.
     */
    SCMP_SYS(fgetxattr),

    /*
     * List extended attributes for file descriptor.
     */
    SCMP_SYS(flistxattr),

    /*
     * Place or remove a lock on a file.
     */
    SCMP_SYS(flock),

    /*
     * Create a child process. Mostly replaced by [clone](#clone).
     */
    SCMP_SYS(fork),

    /*
     * Remove extended file attributes.
     */
    SCMP_SYS(fremovexattr),

    /*
     * Set the value of extended file attributes.
     */
    SCMP_SYS(fsetxattr),

    /*
     * Get file status.
     */
    SCMP_SYS(fstat),

    /*
     * Get filesystem status.
     */
    SCMP_SYS(fstatfs),

    /*
     * Sync data to disk (with caveats that disk vendors often lie about
     * fsync).
     */
    SCMP_SYS(fsync),

    /*
     * Shrink a file to the given size in bytes.
     */
    SCMP_SYS(ftruncate),

    /*
     * User space lock.
     */
    SCMP_SYS(futex),

    /*
     * Identify which CPU the thread is running on.
     */
    SCMP_SYS(getcpu),

    /*
     * Get current working directory.
     */
    SCMP_SYS(getcwd),

    /*
     * Get directory entries.
     */
    SCMP_SYS(getdents),

    /*
     * See [getdents](#getdents)
     */
    SCMP_SYS(getdents64),

    /*
     * Get effective user id
     */
    SCMP_SYS(geteuid),

    /*
     * Get effective group id
     */
    SCMP_SYS(getegid),

    /*
     * Get real group id
     */
    SCMP_SYS(getgid),

    /*
     * Get groups
     */
    SCMP_SYS(getgroups),

    /*
     * Get timer
     */
    SCMP_SYS(getitimer),

    /*
     * Retrieve NUMA memory policy for a thread.
     */
    SCMP_SYS(get_mempolicy),

    /*
     * Get name of connected peer socket.
     */
    SCMP_SYS(getpeername),

    /*
     * Get process group.
     */
    SCMP_SYS(getpgid),

    /*
     * See [getpgid](#getpgid)
     */
    SCMP_SYS(getpgrp),

    /*
     * Get process ID.
     */
    SCMP_SYS(getpid),

    /*
     * Get process ID of parent process.
     */
    SCMP_SYS(getppid),

    /*
     * Get scheduling priority.
     */
    SCMP_SYS(getpriority),

    /*
     * Fill a buffer with random bytes.
     */
    SCMP_SYS(getrandom),

    /*
     * Get real, effective, and saved group IDs
     */
    SCMP_SYS(getresuid),

    /*
     * Get real, effective, and saved user IDs
     */
    SCMP_SYS(getresuid),

    /*
     * Get resource limits
     */
    SCMP_SYS(getrlimit),

    /*
     * Get list of robust futexes.
     */
    SCMP_SYS(get_robust_list),

    /*
     * Get resource usage.
     */
    SCMP_SYS(getrusage),

    /*
     * Get session ID.
     */
    SCMP_SYS(getsid),

    /*
     * Get the address that the socket file descriptor is bound to.
     */
    SCMP_SYS(getsockname),

    /*
     * Get options on socket.
     */
    SCMP_SYS(getsockopt),

    /*
     * Get thread local storage information.
     */
    SCMP_SYS(get_thread_area),

    /*
     * Get thread ID.
     */
    SCMP_SYS(gettid),

    /*
     * Get time of day.
     */
    SCMP_SYS(gettimeofday),

    /*
     * Get User ID of process.
     */
    SCMP_SYS(getuid),

    /*
     * Get extended attribute value.
     */
    SCMP_SYS(getxattr),

    /*
     * Part of the inotify API to monitor files and directories.
     */
    SCMP_SYS(inotify_add_watch),

    /*
     * See [inotify_add_watch](#inotify_add_watch)
     */
    SCMP_SYS(inotify_init),

    /*
     * See [inotify_add_watch](#inotify_add_watch)
     */
    SCMP_SYS(inotify_init1),

    /*
     * See [inotify_add_watch](#inotify_add_watch)
     */
    SCMP_SYS(inotify_rm_watch),

    /*
     * Cancel an IO operation.
     */
    SCMP_SYS(io_cancel),

    /*
     * Control an IO device.
     */
    SCMP_SYS(ioctl),

    /*
     * Destroy an IO context.
     */
    SCMP_SYS(io_destroy),

    /*
     * Read asynchronous I/O events from the completion queue
     */
    SCMP_SYS(io_getevents),

    /*
     * Get IO scheduling priority.
     */
    SCMP_SYS(ioprio_get),

    /*
     * Set the scheduling priority of the calling process.
     */
    SCMP_SYS(ioprio_set),

    /*
     * Create an async IO context.
     */
    SCMP_SYS(io_setup),

    /*
     * See [io_setup](#io_setup)
     */
    SCMP_SYS(io_setup),

    /*
     * See [io_setup](#io_setup)
     */
    SCMP_SYS(io_submit),

    /*
     * See [io_setup](#io_setup)
     */
    SCMP_SYS(io_uring_enter),

    /*
     * See [io_setup](#io_setup)
     */
    SCMP_SYS(io_uring_register),

    /*
     * See [io_setup](#io_setup)
     */
    SCMP_SYS(io_uring_setup),

    /*
     * Send a signal to a process. We can't really get away from signaling
     * processes, and even if the user program manages to get root, it couldn't
     * leak private information by killing other processes, so there is little
     * risk to allow the kill system call.
     */
    SCMP_SYS(kill),

    /*
     * See [chown](#chown)
     */
    SCMP_SYS(lchown),

    /*
     * See [getxattr](#getxattr)
     */
    SCMP_SYS(lgetxattr),

    /*
     * List extended attributes
     */
    SCMP_SYS(listxattr),

    /*
     * See [listxattr](#listxattr)
     */
    SCMP_SYS(llistxattr),

    /*
     * Lookup path of directory entry.
     */
    SCMP_SYS(lookup_dcookie),

    /*
     * Remove an extended attribute.
     */
    SCMP_SYS(lremovexattr),

    /*
     * Seek to a location in a file.
     */
    SCMP_SYS(lseek),

    /*
     * Set extended attributes.
     */
    SCMP_SYS(lsetxattr),

    /*
     * Get file status.
     */
    SCMP_SYS(lstat),

    /*
     * Inform the kernel of which address ranges the process will be used for
     * performance improvements.
     */
    SCMP_SYS(madvise),

    /*
     * Set NUMA policy, used by numpy
     */
    SCMP_SYS(mbind),

    /*
     * Issue memory barriers on a set of threads
     */
    SCMP_SYS(membarrier),

    /*
     * Create a memory backed file.
     */
    SCMP_SYS(memfd_create),

    /*
     * Create a memory region only visible to the calling process.
     * See the [Phoronix
     * article](https://www.phoronix.com/news/Linux-5.14-memfd_secret) for
     * details.
     */
    SCMP_SYS(memfd_secret),

    /*
     * Determine whether pages are resident in memory.
     */
    SCMP_SYS(mincore),

    /*
     * Create a directory.
     */
    SCMP_SYS(mkdir),

    /*
     * See [mkdir](#mkdir)
     */
    SCMP_SYS(mkdirat),

    /*
     * Lock pages in memory, and keep them from getting swapped out.
     */
    SCMP_SYS(mlock),

    /*
     * See [mlock](#mlock)
     */
    SCMP_SYS(mlock2),

    /*
     * See [mlock](#mlock)
     */
    SCMP_SYS(mlockall),

    /*
     * Create a new mapping in virtual memory. Can map files into memory
     * segments, or can be used to allocate physical memory to a virtual memory
     * address space. Often malloc implementations use mmap.
     */
    SCMP_SYS(mmap),

    /*
     * Modify the local descriptor table for the calling process.
     */
    SCMP_SYS(modify_ldt),

    /*
     * Change the access protections for the calling process's memory at a
     * given address range. Needed by many common programs.
     */
    SCMP_SYS(mprotect),

    /*
     * See [mq_open](#mq-open)
     */
    SCMP_SYS(mq_getsetattr),

    /*
     * See [mq_open](#mq-open)
     */
    SCMP_SYS(mq_notify),

    /*
     * Open a message queue.
     */
    SCMP_SYS(mq_open),

    /*
     * See [mq_open](#mq-open)
     */
    SCMP_SYS(mq_timedreceive),

    /*
     * See [mq_open](#mq-open)
     */
    SCMP_SYS(mq_timedsend),

    /*
     * Remove a message queue.
     */
    SCMP_SYS(mq_unlink),

    /*
     * Expand or shrink an existing memory map. Possibly used by malloc.
     */
    SCMP_SYS(mremap),

    /*
     * Perform control operation on message queue.
     */
    SCMP_SYS(msgctl),

    /*
     * Get a message queue identifier.
     */
    SCMP_SYS(msgget),

    /*
     * Receive message from a message queue.
     */
    SCMP_SYS(msgrcv),

    /*
     * Send a message on a message queue.
     */
    SCMP_SYS(msgsnd),

    /*
     * Synchronize a memory mapped file to disk.
     */
    SCMP_SYS(msync),

    /*
     * See [mlock](#mlock)
     */
    SCMP_SYS(munlock),

    /*
     * See [mlock](#mlock)
     */
    SCMP_SYS(munlockall),

    /*
     * Unmap a region of memory.
     */
    SCMP_SYS(munmap),

    /*
     * Get a handle for a pathname.
     */
    SCMP_SYS(name_to_handle_at),

    /*
     * High resolution sleep.
     */
    SCMP_SYS(nanosleep),

    /*
     * See [fstat](#fstat)
     */
    SCMP_SYS(newfstatat),

    /*
     * Open and/or create a file.
     */
    SCMP_SYS(open),

    /*
     * See [open](#open)
     */
    SCMP_SYS(openat),

    /*
     * See [open](#open)
     */
    SCMP_SYS(openat2),

    /*
     * Open a file via a handle.
     */
    SCMP_SYS(open_by_handle_at),

    /*
     * Calling process waits for a signal.
     */
    SCMP_SYS(pause),

    /*
     * Set which "personality" the process will use.
     */
    SCMP_SYS(personality),

    /*
     * Get a file descriptor to refer to a process.
     */
    SCMP_SYS(pidfd_open),

    /*
     * Send a signal to a process as a file descriptor.
     */
    SCMP_SYS(pidfd_send_signal),

    /*
     * Create a unidirectional data channel.
     */
    SCMP_SYS(pipe),

    /*
     * See [pipe](#pipe)
     */
    SCMP_SYS(pipe2),

    /*
     * Allocate a protection key.
     */
    SCMP_SYS(pkey_alloc),

    /*
     * Free a protection key.
     */
    SCMP_SYS(pkey_free),

    /*
     * Set memory protection using pkeys(7).
     */
    SCMP_SYS(pkey_mprotect),

    /*
     * Wait for an event on a file descriptor.
     */
    SCMP_SYS(poll),

    /*
     * See [poll](poll)
     */
    SCMP_SYS(ppoll),

    /*
     * Manipulate the calling thread/process.
     */
    SCMP_SYS(prctl),

    /*
     * Read from an fd at a given offset.
     */
    SCMP_SYS(pread64),

    /*
     * Read data into multiple buffers.
     */
    SCMP_SYS(preadv),

    /*
     * Set resource limits.
     */
    SCMP_SYS(prlimit64),

    /*
     * Give advice about use of memory to a process
     */
    SCMP_SYS(process_madvise),

    /*
     * IO multiplexing.
     */
    SCMP_SYS(pselect6),

    /*
     * Write to an fd at a given offset.
     */
    SCMP_SYS(pwrite64),

    /*
     * Write data into multiple buffers.
     */
    SCMP_SYS(pwritev),

    /*
     * See [pwritev](#pwritev)
     */
    SCMP_SYS(pwritev2),

    /*
     * Read from a file descriptor.
     */
    SCMP_SYS(read),

    /*
     * Initiate file readahead into page cache.
     */
    SCMP_SYS(readahead),

    /*
     * Read the value of a symbolic link.
     */
    SCMP_SYS(readlink),

    /*
     * See [readlink](#readlink)
     */
    SCMP_SYS(readlinkat),

    /*
     * Read data into multiple buffers.
     */
    SCMP_SYS(readv),

    /*
     * Receive a message from a socket.
     */
    SCMP_SYS(recvfrom),

    /*
     * Receive multiple messages from a socket.
     */
    SCMP_SYS(recvmmsg),

    /*
     * Receive a message from a socket.
     */
    SCMP_SYS(recvmsg),

    /*
     * Deprecated, but not harmful. Create a nonlinear file mapping.
     */
    SCMP_SYS(remap_file_pages),

    /*
     * Remove an extended attribute
     */
    SCMP_SYS(removexattr),

    /*
     * Change the name or location of a file.
     */
    SCMP_SYS(rename),

    /*
     * See [rename](#rename)
     */
    SCMP_SYS(renameat),

    /*
     * See [rename](#rename)
     */
    SCMP_SYS(renameat2),

    /*
     * Restart a system call after interruption by a stop signal.
     */
    SCMP_SYS(restart_syscall),

    /*
     * Remove directory.
     */
    SCMP_SYS(rmdir),

    /*
     * Restartable sequence, see:
     * https://www.phoronix.com/news/Restartable-Sequences-Speed
     */
    SCMP_SYS(rseq),

    /*
     * Change the behavior of a signal action.
     */
    SCMP_SYS(rt_sigaction),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_sigpending),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_sigprocmask),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_sigqueueinfo),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_sigreturn),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_sigsuspend),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_sigtimedwait),

    /*
     * See [rt_sigaction](#rt-sigaction)
     */
    SCMP_SYS(rt_tgsigqueueinfo),

    /*
     * Numpy looks up scheduling configuration for process.
     */
    SCMP_SYS(sched_getaffinity),
    SCMP_SYS(sched_getattr),
    SCMP_SYS(sched_getparam),
    SCMP_SYS(sched_get_priority_max),
    SCMP_SYS(sched_get_priority_min),
    SCMP_SYS(sched_getscheduler),
    SCMP_SYS(sched_rr_get_interval),
    SCMP_SYS(sched_yield),

    SCMP_SYS(sched_setaffinity),

    /*
     * Monitor multiple file descriptors.
     */
    SCMP_SYS(select),

    /*
     * Control a semaphore.
     */
    SCMP_SYS(semctl),

    /*
     * Get a semaphore.
     */
    SCMP_SYS(semget),

    /*
     * Perform a semaphore operation by ID.
     */
    SCMP_SYS(semop),

    /*
     * See [semop](#semop)
     */
    SCMP_SYS(semtimedop),

    /*
     * Write one file descriptor to another directly through kernel buffers,
     * without buffering in user space.
     */
    SCMP_SYS(sendfile),

    /*
     * Send multiple messages on a socket.
     */
    SCMP_SYS(sendmmsg),

    /*
     * Send a message on a socket.
     */
    SCMP_SYS(sendmsg),

    /*
     * Send a message on a socket.
     */
    SCMP_SYS(sendto),

    /*
     * Create a timer that sends a signal on an interval.
     */
    SCMP_SYS(setitimer),

    /*
     * Set numa policy for a thread and it's children.
     */
    SCMP_SYS(set_mempolicy),

    /*
     * Needed by bash.
     */
    SCMP_SYS(setpgid),

    /*
     * Set a list of futexes (i.e., user space fast mutexes).
     */
    SCMP_SYS(set_robust_list),

    /*
     * Create a new session.
     */
    SCMP_SYS(setsid),

    /*
     * Manipulate thread local storage.
     */
    SCMP_SYS(set_thread_area),

    /*
     * Set pointer to thread ID.
     */
    SCMP_SYS(set_tid_address),

    /*
     * Set an extended attribute value.
     */
    SCMP_SYS(setxattr),

    /*
     * Shared memory operation.
     */
    SCMP_SYS(shmat),

    /*
     * Shared memory operation.
     */
    SCMP_SYS(shmctl),

    /*
     * Shared memory operation.
     */
    SCMP_SYS(shmdt),

    /*
     * Allocate shared memory.
     */
    SCMP_SYS(shmget),

    /*
     * Sigaltstack() allows a thread to define a new alternate signal stack
     * and/or retrieve the state of an existing alternate signal stack.
     */
    SCMP_SYS(sigaltstack),

    /*
     * Handle a signal.
     */
    SCMP_SYS(signal),

    /*
     * Create a file descriptor for accepting signals
     */
    SCMP_SYS(signalfd),

    /*
     * See [signalf](#signalf)
     */
    SCMP_SYS(signalfd4),

    /*
     * This system call is needed to start bash and Python, so while we would
     * like to restrict programs from being able to do external networking,
     * this system call is quite important for many programs to simply run.
     */
    SCMP_SYS(socket),

    /*
     * Create a pair of sockets.
     */
    SCMP_SYS(socketpair),

    /*
     * Move data between two file descriptors.
     */
    SCMP_SYS(splice),

    /*
     * Get file status.
     */
    SCMP_SYS(stat),

    /*
     * Get filesystem statistics.
     */
    SCMP_SYS(statfs),

    /*
     * Get extended file status.
     */
    SCMP_SYS(statx),

    /*
     * Get filesystem type information.
     */
    SCMP_SYS(sysfs),

    /*
     * Get system information.
     */
    SCMP_SYS(sysinfo),

    /*
     * Duplicate pipe contents.
     */
    SCMP_SYS(tee),

    /*
     * Send a signal to a thread.
     * See [kill](#kill)
     */
    SCMP_SYS(tgkill),

    /*
     * Get UNIX time in seconds.
     */
    SCMP_SYS(time),

    /*
     * Create a per-process timer.
     */
    SCMP_SYS(timer_create),

    /*
     * Delete a per-process timer.
     */
    SCMP_SYS(timer_delete),

    /*
     * Create a timer bound to a file descriptor.
     */
    SCMP_SYS(timerfd_create),

    /*
     * Get time on a timer fd.
     */
    SCMP_SYS(timerfd_gettime),

    /*
     * Set time on a timer fd.
     */
    SCMP_SYS(timerfd_settime),

    /*
     * Get overrun count for a POSIX per-process timer
     */
    SCMP_SYS(timer_getoverrun),

    /*
     * Per process get time on a timer.
     */
    SCMP_SYS(timer_gettime),

    /*
     * Per process set time on a timer.
     */
    SCMP_SYS(timer_settime),

    /*
     * Get current process times.
     */
    SCMP_SYS(times),

    /*
     * Send a signal to a thread.
     * See [kill](#kill)
     */
    SCMP_SYS(tkill),

    /*
     * Shrink a file to a given length.
     */
    SCMP_SYS(truncate),

    /*
     * Used by `open`.
     */
    SCMP_SYS(umask),

    /*
     * Get kernel and system information.
     */
    SCMP_SYS(uname),

    /*
     * Needed to delete files.
     */
    SCMP_SYS(unlink),

    /*
     * See [unlink](#unlink)
     */
    SCMP_SYS(unlinkat),

    /*
     * Disassociate parts of the process execution context
     */
    SCMP_SYS(unshare),

    /*
     * Load a shared library.
     */
    SCMP_SYS(uselib),

    /*
     * Handle page faults in user space.
     */
    SCMP_SYS(userfaultfd),

    /*
     * Get filesystem statistics.
     */
    SCMP_SYS(ustat),

    /*
     * Change file last access and modification times.
     */
    SCMP_SYS(utime),

    /*
     * See [utime](#utime)
     */
    SCMP_SYS(utimensat),

    /*
     * See [utime](#utime)
     */
    SCMP_SYS(utimes),

    /*
     * Create a child process and block the parent until the child process
     * exits.
     */
    SCMP_SYS(vfork),

    /*
     * Hangup the current terminal.
     */
    SCMP_SYS(vhangup),

    /*
     * Splice user pages to/from a pipe.
     */
    SCMP_SYS(vmsplice),

    /*
     * Wait for process to change state.
     */
    SCMP_SYS(wait4),

    /*
     * See [wait4](#wait4)
     */
    SCMP_SYS(waitid),

    /*
     * Write to a file descriptor.
     */
    SCMP_SYS(write),

    /*
     * Write to multiple buffers.
     */
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
