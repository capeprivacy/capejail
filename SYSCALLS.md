# SYSCALLS

This is a list of both the allowed and blocked syscalls.

We are more prone to blocking syscalls rather than allowing them. If a syscall
does not seem to be useful to our users, then we block it out of an abundance of
caution. Many of the blocked syscalls may indeed be safe, but we think that
defaulting to blocking them will be the safer option. If a blocked syscall is
both safe and useful, then we will be open to discussion of adding it to the
allow list.

We will only allow syscalls that are unlikely to lead to exploits.

Particularly dangerous syscalls will be marked with ⚠️.

## Contents

- [Blocked](#blocked)
- [Allowed](#allowed)


## Blocked

### accept

Not needed by demo programs, and is helpful for restricting networking.

### accept4

See [accept](#accept).

### acct

Requires CAP_SYS_PACCT privileges, and does not seem to be useful for user
processes.

### add_key

It is unlikely that a user program would have a need to add a key to the
kernel's keyring, so best to block it out of caution.

### adjtime

Needs CAP_SYS_TIME privileges. Tunes the kernels clock, could be used
nefariously.

### afs_syscall

Unimplemented system call. This system call is not implemented in the Linux
kernel, and always returns -1.

### bpf

Berkeley Packet Filter. Used for network packet filtering and for seccomp.
Neither of which operations should be necessary for user programs to do.

### capget

Get capabilities of calling thread. Unlikely to be useful

### capset

Set capabilities of calling thread. This syscall can grant the thread privileges
to make additional syscalls, for example CAP_SYS_CHROOT. Could be used
maliciously.

### chmod

Set permissions of file. Probably not useful to user code, and could possibly
(but improbably) be used with chown to exploit setuid.

### chown

Change ownership of a file. Probably not useful to user code, and could possibly
(but improbably) be used with chmod to exploit setuid.

### chroot ⚠️

Change root directory. This is the big one to block, since it can be used to
escape the jail.

### clock_adjtime

See [adjtime](#adjtime).

### clock_settime

See [adjtime](#adjtime).

### create_module

Create a loadable kernel module. This was removed in Linux 2.6, so no reason to
use it.

### delete_module

Probably no good reason for user code to unload kernel modules.

### epoll_pwait2

Not intentionally blocked, but this is a new syscall that currently doesn't
compile with the version of libseccomp used in the container. The plan is to
allow this once libseccomp supports it.

See [epoll_create](#epoll_create).

### finit_module ⚠️

User code probably shouldn't be loading kernel modules.

### fsconfig

Literally no man pages for this syscall. Syscall number 431 in asm/unistd_64.h
on AMD64 Linux.

### fsmount

Literally no man pages for this syscall.

### fsopen

Literally no man pages for this syscall.

### fspick

Literally no man pages for this syscall.

### fstatfs

Users probably don't need filesystem information.

### futimesat

Obsolete system call.

### futex_waitv

Not intentionally blocked, but this is a new syscall that currently doesn't
compile with the version of libseccomp used in the container. The plan is to
allow this once libseccomp supports it.

See [futex](#futex)

### get_kernel_syms

Retrieve exported kernel and module symbols. Users probably don't need to do
anything with kernel modules.

### getpmsg

Unimplemented system call. This system call is not implemented in the Linux
kernel, and always returns -1.

### init_module

Initialize a kernel module. A user function shouldn't need to do this.

### ioperm

Set port IO permissions. Turning on requires CAP_SYS_RAWIO permissions.

### io_pgetevents

No man pages for this syscall.

### iopl

Similar to [ioperm](#ioperm), but this one is deprecated due to it being a lot
slower than ioprem.

### kcmp

Compare if two processes share kernel resources such as virtual memory,
file descriptors, etc. Requires the same privileges as ptrace.

### kexec_file_load ️⚠️

Load a new kernel that will run on reboot.

### kexec_load ⚠️

See [kexec_file_load](#kexec_file_load)

### keyctl

Manage kernel keyring.

### landlock_add_rule

No man page entries, so defaulting to blocking.

### landlock_create_ruleset

No man page entries, so defaulting to blocking.

### landlock_restrict_self

No man page entries, so defaulting to blocking.

### lchown

See [chown](#chown)

### link

Hard links that lead outside of the chroot are a way of escaping a chroot jail.
Since the process is already jailed, I'm not aware of a way for this to be
exploited, I also don't think that it will have any value to user functions, so
I will block it out of an abundance of caution.

### linkat

See [link](#link)

### listen

Listen for a connection on a socket. Could be used to run a webserver from
within the enclave, possibly spoofing sentinel.

### mbind

Set the NUMA policy, requires CAP_SYS_NICE for certain flags.

### migrate_pages

Move all pages in another process to another set of nodes. I'm suspicious of
something that can affect memory of other processes, so for now we're blocking
this one.

### mknod ⚠️

Create special files, e.g., the files that can be found within `/dev`. One of
the goals of `capejail` is to block access to certain special files such as
`/dev/nsm`. We want to be sure that a malicious process will not be able to
create these files itself.

### mknodat ⚠️

See [mknod](#mknod)

### mount

Attach a filesystem to a target path. User's probably won't need to mount any
filesystems.

### mount_setattr

See [mount](#mount)

### move_mount

No manpage entries.

### move_pages

See [migrate_pages](#migrate_pages)

## Allowed

### access

Check user's permissions for a file.

### alarm

Sends a SIGALRM signal to the calling process after a number of seconds. Sleep
could possibly be implemented using alarm in some libraries.

### arch_prctl

Set architecture-specific thread state. Used by numpy.

### bind

Bind an address to a socket.

### brk

Used to adjust the heap. Mostly obsoleted by mmap, but could be used by a malloc
implementation.

### chdir

Change directories. Pretty useful, and with the chroot jail along with seccomp
filtering, it should be unlikely to be exploitable.

### clock_getres

Get the resolution (precision) of the system clock.

### clock_gettime

Get the current time.

### clock_nanosleep

Put the thread to sleep with nanosecond precision.

### clone

The Linux way of doing [fork](#fork), but with more options and better performance.

### __clone2

See [clone](#clone).

### clone3

See [clone](#clone).

### close

Close a file descriptor.

### close_range

Close all file descriptors from first to last.

### connect

Initiate a socket connection. Used by a lot of programs, including `ls -l`.

### copy_file_range

Copy a range of data from one file to another

### creat

Create a file with given permissions.

### dup

Duplicate a file descriptor.

### dup2

See [dup](#dup).

### dup3

See [dup](#dup).

### epoll_create

Create an epoll instance, used for monitoring files for IO.

### epoll_create1

See [epoll_create](#epoll_create).

### epoll_ctl

See [epoll_create](#epoll_create).

### epoll_ctl_old

See [epoll_create](#epoll_create).

### epoll_pwait

See [epoll_create](#epoll_create).

### epoll_wait

See [epoll_create](#epoll_create).

### epoll_wait_old

See [epoll_create](#epoll_create).

### eventfd

Create a file descriptor for event notification.

### eventfd2

See [eventfd](#eventfd).

### execve

Execute a program.

### execveat

See [execve](#execve).

### exit

Terminate the calling process

### exit_group

See [exit](#exit).

### faccessat

Check the user's permissions for a file. See [access](#access).

### faccessat2

See [faccessat](#faccessat).

### fadvise64

Declare an access pattern for data.

### fallocate

Allocate space for a file.

### fanotify_init

Initialize an fanotify group.

### fanotify_mark

See [fanotify_init](#fanotify_init)

### fchdir

Change working directory. See [chdir](#chdir)

### fcntl

Toolbox for manipulating a file descriptor.

### fdatasync

See [fsync](#fsync)

### fgetxattr

Get extended attributes for file descriptor.

### flistxattr

List extended attributes for file descriptor.

### flock

Place or remove a lock on a file.

### fork

Create a child process. Mostly replaced by [clone](#clone).

### fremovexattr

Remove extended file attributes.

### fsetxattr

Set the value of extended file attributes.

### fstat

Get file status.

### fsync

Sync data to disk (with caveats that disk vendors often lie about fsync).

### ftruncate

Shrink a file to the given size in bytes.

### futex

User space lock.

### getcpu

Identify which CPU the thread is running on.

### getdents

Get directory entries.

### getdents64

See [getdents](#getdents)

### geteuid

Get effective user id

### getegid

Get effective group id

### getgid

Get real group id

### getgroups

Get groups

### getitimer

Get timer

### get_mempolicy

Retrieve NUMA memory policy for a thread.

### getpeername

Get name of connected peer socket.

### getpgid

Get process group.

### getpgrp

See [getpgid](#getpgid)

### getpid

Get process ID.

### getppid

Get process ID of parent process.

### getpriority

Get scheduling priority.

### getrandom

Fill a buffer with random bytes.

### getresuid

Get real, effective, and saved group IDs

### getresuid

Get real, effective, and saved user IDs

### getrlimit

Get resource limits

### get_robust_list

Get list of robust futexes.

### getrusage

Get resource usage.

### getsid

Get session ID.

### getsockname

Get the address that the socket file descriptor is bound to.

### getsockopt

Get options on socket.

### get_thread_area

Get thread local storage information.

### gettid

Get thread ID.

### gettimeofday

Get time of day.

### getuid

Get User ID of process.

### getxattr

Get extended attribute value.

### inotify_add_watch

Part of the inotify API to monitor files and directories.

### inotify_init

See [inotify_add_watch](#inotify_add_watch)

### inotify_init1

See [inotify_add_watch](#inotify_add_watch)

### inotify_rm_watch

See [inotify_add_watch](#inotify_add_watch)

### io_cancel

Cancel an IO operation.

### ioctl

Control an IO device.

### io_destroy

Destroy an IO context.

### io_getevents

Read asynchronous I/O events from the completion queue

### ioprio_get

Get IO scheduling priority.

### ioprio_set

Set the scheduling priority of the calling process.

### io_setup

Create an async IO context.

### io_setup

See [io_setup](#io_setup)

### io_submit

See [io_setup](#io_setup)

### io_uring_enter

See [io_setup](#io_setup)

### io_uring_register

See [io_setup](#io_setup)

### io_uring_setup

See [io_setup](#io_setup)

### kill

Send a signal to a process. We can't really get away from signaling processes,
and even if the user program manages to get root, it couldn't leak private
information by killing other processes, so there is little risk to allow the
kill system call.

### lgetxattr

See [getxattr](#getxattr)

### listxattr

List extended attributes

### llistxattr

See [listxattr](#listxattr)

### lookup_dcookie

Lookup path of directory entry.

### lremovexattr

Remove an extended attribute.

### lseek

Seek to a location in a file.

### lsetxattr

Set extended attributes.

### lstat

Get file status.

### madvise

Inform the kernel of which address ranges the process will be used for
performance improvements.

### membarrier

Issue memory barriers on a set of threads

### memfd_create

Create a memory backed file.

### memfd_secret

Create a memory region only visible to the calling process.
See the [Phoronix article](https://www.phoronix.com/news/Linux-5.14-memfd_secret)
for details.

### mincore

Determine whether pages are resident in memory.

### mkdir

Create a directory.

### mkdirat

See [mkdir](#mkdir)

### mlock

Lock pages in memory, and keep them from getting swapped out.

### mlock2

See [mlock](#mlock)

### mlockall

See [mlock](#mlock)

### mmap

Create a new mapping in virtual memory. Can map files into memory segments, or
can be used to allocate physical memory to a virtual memory address space. Often
malloc implementations use mmap.

### modify_ldt

Modify the local describtor table for the calling process.

### mprotect

Change the access protections for the calling process's memory at a given
address range. Needed by many common programs.
