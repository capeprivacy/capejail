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

### finit_module

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

## Allowed

### access

Check user's permissions for a file.

### alarm

Sends a SIGALRM signal to the calling process after a number of seconds. Sleep
may be implemented using alarm in some libraries.

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
